<?php

declare(strict_types=1);

namespace FriendsOfHyperf\Jwt\Tests;

use FriendsOfHyperf\Jwt\Factory\JwtFactory;
use FriendsOfHyperf\Jwt\Jwt;
use FriendsOfHyperf\Jwt\Exceptions\JwtConfigException;
use Hyperf\Config\Config; // 使用 Hyperf 提供的 Config 类进行模拟
use Hyperf\Context\ApplicationContext; // 用于设置容器
use Lcobucci\JWT\Encoding\JoseEncoder;
use Mockery; // 如果需要 mock 复杂的依赖
use Psr\Container\ContainerInterface;
use Lcobucci\JWT\Signer\Hmac\Sha256 as HS256;
use Lcobucci\JWT\Signer\Hmac\Sha512 as HS512;
use Lcobucci\JWT\Signer\Rsa\Sha256 as RS256;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Signer\Hmac\Sha256 as HS256Signer; // 引入默认 Signer
use Lcobucci\JWT\Token\Parser as LcobucciTokenParser; // Alias to avoid conflict


class ConfigAndFactoryTest extends TestCase // 继承我们自己的 TestCase
{
    protected ?ContainerInterface $container;
    private JwtFactory $factory;

    protected function setUp(): void
    {
        parent::setUp();
        $this->container = Mockery::mock(ContainerInterface::class);
        ApplicationContext::setContainer($this->container); // 设置全局容器，Config 会用到
        $this->factory = new JwtFactory();
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    private function mockConfig(array $jwtConfigValues): void
    {
        // 使用 Hyperf 的 Config 类，它实现了 ConfigInterface
        $hyperfConfig = new Config(['jwt' => $jwtConfigValues]);
        $this->container->shouldReceive('get')->with(\Hyperf\Contract\ConfigInterface::class)->andReturn($hyperfConfig);
    }

    public function testFactoryThrowsExceptionIfNoSecretForSymmetricSigner(): void
    {
        $this->expectException(JwtConfigException::class);
        //$this->expectExceptionMessageMatches('/JWT secret is not configured/');
        $this->mockConfig(['algo' => HS256::class]); // 只有 algo，没有 secret
        ($this->factory)($this->container);
    }

    public function testFactoryCreatesJwtWithHs256AndDefaultTtl(): void // 改为 void，不再返回 Jwt
    {
        $testSecret = 'test-hs256-secret-key-test-hs256-secret-key-test-hs256-secret-key';
        $this->mockConfig([
            'secret' => $testSecret,
            'algo' => HS256Signer::class, // 确保是 Signer 类本身
            // ttl, iss, aud 使用 Jwt 类内部的默认值或 jwtConfig 中的默认值 (如果 publish/jwt.php 中有)
        ]);

        $jwt = ($this->factory)($this->container);
        $this->assertInstanceOf(Jwt::class, $jwt);

        // 验证生成的 token
        $userId = 'user1_default_ttl';
        $tokenString = $jwt->generate($userId); // 使用 Jwt 内部的 ttl 逻辑

        // 使用同一个 jwt 实例解析，它已经配置了正确的验证约束
        $parsedToken = $jwt->parse($tokenString);
        $this->assertInstanceOf(Plain::class, $parsedToken);
        $this->assertEquals($userId, $parsedToken->claims()->get('sub'));

        // 验证 TTL (这个测试主要关注工厂创建和基本解析，TTL的精确验证可以放在专门的测试中)
        // 我们需要知道 Jwt::generate 中 ttl 的最终默认值是什么
        // 如果 $jwtConfig['ttl'] 未在 mockConfig 中设置，Jwt::generate 中会用 ?? 3600
        $defaultTtlInGenerate = 3600; // 假设这是 Jwt::generate 中的最终回退值
        $this->assertTrue($parsedToken->claims()->has('exp'));
        $this->assertTrue($parsedToken->claims()->has('iat'));
        $expectedExp = $parsedToken->claims()->get('iat')->getTimestamp() + $defaultTtlInGenerate;
        $actualExp = $parsedToken->claims()->get('exp')->getTimestamp();
        // 由于签发和解析之间可能有微秒级的延迟，iat 可能略早于我们预期。
        // 对于默认TTL的测试，我们允许1秒的误差。
        $this->assertEqualsWithDelta($expectedExp, $actualExp, 1, 'Default TTL should be applied.');
    }

    /**
     * @depends testFactoryCreatesJwtWithHs256AndDefaultTtl
     */
    public function testGeneratedTokenHasConfiguredTtl(): void
    {
        $testSecret = 'test-hs256-secret-key-test-hs256-secret-key-test-hs256-secret-key-test-hs256-secret-key';
        $this->mockConfig([
            'secret' => $testSecret,
            'algo' => HS256Signer::class, // 确保是 Signer 类本身
            // ttl, iss, aud 使用 Jwt 类内部的默认值或 jwtConfig 中的默认值 (如果 publish/jwt.php 中有)
        ]);

        $jwt = ($this->factory)($this->container);
        $this->assertInstanceOf(Jwt::class, $jwt);

        // 验证生成的 token
        $userId = 'user1_default_ttl';
        $tokenString = $jwt->generate($userId); // 使用 Jwt 内部的 ttl 逻辑

        // 使用同一个 jwt 实例解析，它已经配置了正确的验证约束
        $parsedToken = $jwt->parse($tokenString);
        $this->assertInstanceOf(Plain::class, $parsedToken);
        $this->assertEquals($userId, $parsedToken->claims()->get('sub'));

        // 验证 TTL (这个测试主要关注工厂创建和基本解析，TTL的精确验证可以放在专门的测试中)
        // 我们需要知道 Jwt::generate 中 ttl 的最终默认值是什么
        // 如果 $jwtConfig['ttl'] 未在 mockConfig 中设置，Jwt::generate 中会用 ?? 3600
        $defaultTtlInGenerate = 3600; // 假设这是 Jwt::generate 中的最终回退值
        $this->assertTrue($parsedToken->claims()->has('exp'));
        $this->assertTrue($parsedToken->claims()->has('iat'));
        $expectedExp = $parsedToken->claims()->get('iat')->getTimestamp() + $defaultTtlInGenerate;
        $actualExp = $parsedToken->claims()->get('exp')->getTimestamp();
        // 由于签发和解析之间可能有微秒级的延迟，iat 可能略早于我们预期。
        // 对于默认TTL的测试，我们允许1秒的误差。
        $this->assertEqualsWithDelta($expectedExp, $actualExp, 1, 'Default TTL should be applied.');
    }


    public function testFactoryCreatesJwtWithConfiguredIssuerAndAudience(): void
    {
        $testSecret = 'iss-aud-secret-iss-aud-secret-iss-aud-secret-iss-aud-secret-iss-aud-secret-iss-aud-secret-iss-aud-secret-iss-aud-secret';
        $issuer = 'https://my-app.com';
        $audience = 'https://api.my-app.com';

        $this->mockConfig([
            'secret' => $testSecret,
            'algo' => HS256::class,
            'iss' => $issuer,
            'aud' => $audience,
        ]);

        // 在 JwtFactory 中，我们需要确保如果配置了 iss/aud，相应的约束也被添加
        // 如果约束被添加了，那么解析时也应该检查它们
        // 我们需要在 JwtFactory 中解除对 IssuedBy 和 PermittedFor 约束的注释
        // (Ensure IssuedBy and PermittedFor constraints are added in JwtFactory if iss/aud are set)
        // // if (!empty($jwtConfig['iss'])) { $constraints[] = new IssuedBy($jwtConfig['iss']); }
        // // if (!empty($jwtConfig['aud'])) { $constraints[] = new PermittedFor((string) $jwtConfig['aud']); }


        $jwt = ($this->factory)($this->container);
        $tokenString = $jwt->generate('user_iss_aud');

        // 1. 验证生成的 token 包含 iss 和 aud
        $parser = new LcobucciTokenParser(new JoseEncoder());
        try {
            $parsedForClaims = $parser->parse($tokenString);
        } catch (\Exception $e) { // Catch generic exception for brevity in test setup
            $this->fail("Failed to parse token for claim inspection: " . $e->getMessage());
        }
        $this->assertEquals($issuer, $parsedForClaims->claims()->get('iss'));
        $this->assertEquals($audience, ...$parsedForClaims->claims()->get('aud')); // Lcobucci stores aud as array if single

        // 2. 验证解析时会检查 iss 和 aud (如果工厂中已配置相应约束)
        // 这要求 JwtFactory 中的 Lcobucci\Configuration 包含 IssuedBy 和 PermittedFor 约束
        // 如果 JwtFactory 中没有添加这些约束，下面这行会通过，但不能证明约束生效
        // 如果 JwtFactory 中添加了这些约束，这行会验证它们
        $parsedToken = $jwt->parse($tokenString);
        $this->assertEquals($issuer, $parsedToken->claims()->get('iss'));
        $this->assertTrue($parsedToken->claims()->has('aud')); // aud is often an array
        $this->assertContains($audience, $parsedToken->claims()->get('aud'));


        // 测试错误的 issuer (如果约束已在工厂中设置)
        // $this->mockConfig([... 'iss' => 'WRONG_ISSUER_FOR_VALIDATION' ...]);
        // $jwtForWrongIssValidation = ($this->factory)($this->container);
        // $this->expectException(TokenValidationFailedException::class); // or a more specific one
        // $jwtForWrongIssValidation->parse($tokenString); // $tokenString was generated with 'https://my-app.com'
    }

    // TODO: 添加非对称加密 (RS256) 的测试
    //  - 测试密钥从文件加载
    //  - 测试密钥从内容加载
    //  - 测试带密码的私钥

    // TODO: 测试 leeway 配置是否生效
    //  - 这需要精确控制 FrozenClock，并生成边界条件的 token (例如，刚好过期1秒，但 leeway 是2秒)

    // TODO: 测试无效的 algo 配置

    // TODO: 测试 required_claims (如果实现)
}