<?php

declare(strict_types=1);

namespace FriendsOfHyperf\Jwt\Tests;

use DateTimeImmutable;
use DateInterval;
use FriendsOfHyperf\Jwt\Blacklist;

// Mock BlacklistInterface
use FriendsOfHyperf\Jwt\Contract\BlacklistInterface;
use FriendsOfHyperf\Jwt\Contract\PayloadFactoryInterface;
use FriendsOfHyperf\Jwt\Contract\RequestParser\RequestParserFactoryInterface;
use FriendsOfHyperf\Jwt\Contract\RequestParser\RequestParserInterface;
use FriendsOfHyperf\Jwt\Contract\TokenInterface;
use FriendsOfHyperf\Jwt\Contract\ValidatorInterface;
use FriendsOfHyperf\Jwt\Exception\JwtException;
use FriendsOfHyperf\Jwt\Exception\TokenExpiredException;
use FriendsOfHyperf\Jwt\Exception\TokenInvalidException;
use FriendsOfHyperf\Jwt\Manager;
use FriendsOfHyperf\Jwt\PayloadFactory;

// Mock PayloadFactoryInterface
use FriendsOfHyperf\Jwt\RequestParser\RequestParserFactory;

// Mock RequestParserFactoryInterface
use FriendsOfHyperf\Jwt\Token;

// 用于 make(Token::class)
use FriendsOfHyperf\Jwt\Validator;

// Mock ValidatorInterface
use Hyperf\Contract\ConfigInterface;
use Hyperf\HttpServer\Contract\RequestInterface as HyperfRequestInterface;

// 用于测试 parseTokenFromRequest
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\Builder as LcobucciBuilder;
use Lcobucci\JWT\Token\Parser as LcobucciParser;
use Lcobucci\JWT\Token\Plain as LcobucciPlainToken;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\Validator as LcobucciValidator;
use Mockery;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * @internal
 * @coversNothing
 */
class ManagerTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    protected Mockery\MockInterface|ContainerInterface $mockContainer;
    protected Mockery\MockInterface|ConfigInterface $mockHyperfConfig;
    protected Mockery\MockInterface|ValidatorInterface $mockOurValidator; // 我们自己定义的 Validator
    protected Mockery\MockInterface|BlacklistInterface $mockBlacklist;
    protected Mockery\MockInterface|RequestParserFactoryInterface $mockRequestParserFactory;
    protected Mockery\MockInterface|PayloadFactoryInterface $mockPayloadFactory;


//    protected Mockery\MockInterface|Configuration $mockLcobucciConfig;
//    protected Mockery\MockInterface|LcobucciBuilder $mockLcobucciBuilder;
//    protected Mockery\MockInterface|LcobucciParser $mockLcobucciParser;
//    protected Mockery\MockInterface|LcobucciValidator $mockLcobucciValidator;
//    protected Mockery\MockInterface|Signer $mockSigner;
//    protected Mockery\MockInterface|InMemory $mockKey; // Key for signing/verification

    protected Manager $manager;

    protected function setUp(): void
    {
        parent::setUp();

        $this->mockContainer = Mockery::mock(ContainerInterface::class);
        $this->mockHyperfConfig = Mockery::mock(ConfigInterface::class);
        $this->mockOurValidator = Mockery::mock(ValidatorInterface::class); // 使用新名
        $this->mockBlacklist = Mockery::mock(BlacklistInterface::class);
        $this->mockRequestParserFactory = Mockery::mock(RequestParserFactoryInterface::class);
        $this->mockPayloadFactory = Mockery::mock(PayloadFactoryInterface::class);

        // --- 配置 Hyperf ConfigInterface 的默认返回 ---
        // (这部分保持不变，确保所有被 Manager 读取的配置都有 mock)
        $this->mockHyperfConfig->shouldReceive('get')->with('jwt.ttl', Mockery::any())->andReturn(60)->byDefault();
        $this->mockHyperfConfig->shouldReceive('get')->with('jwt.nbf_offset_seconds', Mockery::any())->andReturn(0)->byDefault();
        $this->mockHyperfConfig->shouldReceive('get')->with('jwt.issuer', Mockery::any())->andReturn('test-issuer')->byDefault();
        $this->mockHyperfConfig->shouldReceive('get')->with('jwt.audience', Mockery::any())->andReturn('test-audience')->byDefault();
        $this->mockHyperfConfig->shouldReceive('get')->with('jwt.refresh_ttl', Mockery::any())->andReturn(20160)->byDefault();
        $this->mockHyperfConfig->shouldReceive('get')->with('jwt.subject_claim', Mockery::any())->andReturn('sub')->byDefault();
        $this->mockHyperfConfig->shouldReceive('get')->with('jwt.lcobucci_config_factory')->andReturn(null)->byDefault();
        $this->mockHyperfConfig->shouldReceive('get')->with('jwt.algo', Mockery::any())->andReturn(Sha256::class)->byDefault();
        $this->mockHyperfConfig->shouldReceive('get')->with('jwt.secret')->andReturn('test_secret_key_for_hs256_at_least_32_bytes_long')->byDefault();
        // 如果测试非对称加密，还需要 mock jwt.keys.public, jwt.keys.private, jwt.keys.passphrase
        // 例如:
        // $this->mockHyperfConfig->shouldReceive('get')->with('jwt.keys.private')->andReturn('valid_private_key_string_or_file_path')->byDefault();
        // $this->mockHyperfConfig->shouldReceive('get')->with('jwt.keys.public')->andReturn('valid_public_key_string_or_file_path')->byDefault();
        // $this->mockHyperfConfig->shouldReceive('get')->with('jwt.keys.passphrase')->andReturn(null)->byDefault();

        $this->mockHyperfConfig->shouldReceive('get')->with('jwt.required_claims', Mockery::any())->andReturn([])->byDefault();
        $this->mockHyperfConfig->shouldReceive('get')->with('jwt.leeway', Mockery::any())->andReturn(0)->byDefault();
        $this->mockHyperfConfig->shouldReceive('get')->with('jwt.blacklist_enabled', true)->andReturn(true)->byDefault();

        // 新增：为 Manager::parse() 中 Lcobucci 验证器约束部分添加的配置读取
        $this->mockHyperfConfig->shouldReceive('get')
            ->with('jwt.required_claims.iss', false) // 精确匹配键和默认值
            ->andReturn(false) // 默认情况下，我们假设不强制要求 Lcobucci 层面验证 iss
            ->byDefault();
        $this->mockHyperfConfig->shouldReceive('get')
            ->with('jwt.required_claims.aud', false) // 精确匹配键和默认值
            ->andReturn(false) // 默认情况下，我们假设不强制要求 Lcobucci 层面验证 aud
            ->byDefault();


        // --- 配置 PayloadFactory ---
        // (这部分保持不变)
        $this->mockPayloadFactory->shouldReceive('setTtl')->withAnyArgs()->andReturnSelf()->byDefault();
        // ... (其他 payloadFactory mock) ...
        $this->mockPayloadFactory->shouldReceive('getIssuer')->andReturn('test-issuer')->byDefault();
        $this->mockPayloadFactory->shouldReceive('getAudience')->andReturn('test-audience')->byDefault();
        $this->mockPayloadFactory->shouldReceive('generateJti')->andReturn('mocked_jti_123')->byDefault();
        $this->mockPayloadFactory->shouldReceive('getCurrentTime')->andReturn(new DateTimeImmutable())->byDefault();
        $this->mockPayloadFactory->shouldReceive('getNbfOffsetSeconds')->andReturn(0)->byDefault();
        $this->mockPayloadFactory->shouldReceive('getTtl')->andReturn(60)->byDefault();


        // --- 配置我们自己的 Validator ---
        $this->mockOurValidator->shouldReceive('setRequiredClaims')->withAnyArgs()->andReturnSelf()->byDefault();
        $this->mockOurValidator->shouldReceive('setLeeway')->withAnyArgs()->andReturnSelf()->byDefault();
        $this->mockOurValidator->shouldReceive('validate')->withAnyArgs()->andReturnUndefined()->byDefault();
        $this->mockOurValidator->shouldReceive('getLeeway')->andReturn(0)->byDefault();


        // --- 配置 ContainerInterface ---
        // Manager::initLcobucciConfiguration() 中会 container->make(Signer::class)
        $this->mockContainer->shouldReceive('make')
            ->with(Sha256::class) // 或者其他在 jwt.algo 中配置的 Signer
            ->andReturn(new Sha256()) // 返回真实的 Signer 实例
            ->byDefault();
        // 如果测试非对称加密，需要确保相应的 Signer (Rsa\Sha256, Ecdsa\Sha256) 也能被 make
        // $this->mockContainer->shouldReceive('make')->with(\Lcobucci\JWT\Signer\Rsa\Sha256::class)->andReturn(new \Lcobucci\JWT\Signer\Rsa\Sha256());

        // Manager::issueToken 和 Manager::parse (内部的封装) 中会 make(Token::class)
        $this->mockContainer->shouldReceive('make')
            ->with(Token::class, Mockery::on(function ($args) {
                return isset($args['lcobucciToken']) && ($args['lcobucciToken'] instanceof LcobucciPlainToken || $args['lcobucciToken'] instanceof \Lcobucci\JWT\UnencryptedToken);
            }))
            ->andReturnUsing(function ($class, $args) {
                return new Token($args['lcobucciToken']);
            })->byDefault();


        // 实例化 Manager
        // Manager 的构造函数会调用 initLcobucciConfiguration()，
        // 它会基于 mockHyperfConfig 和 mockContainer 来创建真实的 Lcobucci\JWT\Configuration 实例
        $this->manager = new Manager(
            $this->mockContainer,
            $this->mockHyperfConfig,
            $this->mockOurValidator, // 使用新名
            $this->mockBlacklist,
            $this->mockRequestParserFactory,
            $this->mockPayloadFactory
        );
    }

    public function testIssueTokenSuccessfully(): void
    {
        $customClaims = ['user_id' => 1, 'data' => 'sample'];
        $subject = 1;

        // PayloadFactory 的行为已经在 setUp 中被 mock
        // Manager 会调用 payloadFactory 的方法获取标准声明的值

        // Lcobucci Configuration 相关的 mock (如果 Manager 不自己创建真实 Configuration)
        // 或者，更简单的方式是，让 initLcobucciConfiguration 运行，它会创建真实的 LcobucciConfiguration
        // 只需要确保 mockHyperfConfig 提供了正确的配置值即可。
        // setUp 中已经 mock 了 HyperfConfig 以便 HS256 能被创建。

        $token = $this->manager->issueToken($customClaims, $subject);

        $this->assertInstanceOf(TokenInterface::class, $token);
        $this->assertNotEmpty($token->toString());
        // 可以进一步断言 token 中的声明，但这更像是测试 PayloadFactory + Lcobucci
    }


    public function testParseValidTokenSuccessfully(): void
    {
        $now = new DateTimeImmutable();
        $testTokenString = $this->generateTestHs256TokenString([ // 使用辅助方法生成一个有效的token字符串
            'iss' => 'test-issuer',
            'aud' => 'test-audience',
            'jti' => 'valid_jti',
            'iat' => $now->getTimestamp(),
            'nbf' => $now->getTimestamp(),
            'exp' => $now->add(new DateInterval('PT1H'))->getTimestamp(),
            'user_id' => 123,
        ], 'test_secret_key_for_hs256_at_least_32_bytes_long');

        // Mock Blacklist::has() 返回 false (不在黑名单)
        $this->mockBlacklist->shouldReceive('has')->once()->with(Mockery::type(TokenInterface::class))->andReturn(false);

        // Mock Validator::validate() 不抛异常
        $this->mockOurValidator->shouldReceive('validate')->once()->with(Mockery::type(TokenInterface::class), true, [])->andReturnUndefined();

        $parsedToken = $this->manager->parse($testTokenString);

        $this->assertInstanceOf(TokenInterface::class, $parsedToken);
        $this->assertEquals(123, $parsedToken->getClaim('user_id'));
        $this->assertEquals('valid_jti', $parsedToken->getId());
    }

    public function testParseTokenThrowsTokenInvalidExceptionIfBlacklisted(): void
    {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Token has been blacklisted.');

        $now = new DateTimeImmutable();
        $testTokenString = $this->generateTestHs256TokenString([
            'exp' => $now->add(new DateInterval('PT1H'))->getTimestamp(),
            // 其他必要声明...
            'iat' => $now->getTimestamp(),
            'nbf' => $now->getTimestamp(),
            'jti' => 'blacklisted_jti'
        ], 'test_secret_key_for_hs256_at_least_32_bytes_long');

        // Mock Blacklist::has() 返回 true
        $this->mockBlacklist->shouldReceive('has')->once()->andReturn(true);
        // Validator::validate 不应该被调用
        $this->mockOurValidator->shouldNotReceive('validate');

        $this->manager->parse($testTokenString);
    }

    public function testParseTokenThrowsTokenExpiredException(): void
    {
        $this->expectException(TokenExpiredException::class);

        $now = new DateTimeImmutable();
        $testTokenString = $this->generateTestHs256TokenString([
            'exp' => $now->sub(new DateInterval('PT1S'))->getTimestamp(), // 已过期
            // 其他必要声明...
            'iat' => $now->sub(new DateInterval('PT1H'))->getTimestamp(),
            'nbf' => $now->sub(new DateInterval('PT1H'))->getTimestamp(),
            'jti' => 'expired_jti'
        ], 'test_secret_key_for_hs256_at_least_32_bytes_long');

        // Lcobucci 的 validator 会先检测到过期
        // Blacklist 和我们自己的 Validator 不会被调用
        $this->mockBlacklist->shouldNotReceive('has');
        $this->mockOurValidator->shouldNotReceive('validate');

        $this->manager->parse($testTokenString);
    }

    public function testParseTokenFromRequestSuccessfully(): void
    {
        $mockRequest = Mockery::mock(ServerRequestInterface::class);
        $mockParser = Mockery::mock(RequestParserInterface::class);
        $now = new DateTimeImmutable();
        $testTokenString = $this->generateTestHs256TokenString([
            'exp' => $now->add(new DateInterval('PT1H'))->getTimestamp(),
            'iat' => $now->getTimestamp(), 'nbf' => $now->getTimestamp(), 'jti' => 'from_req_jti'
        ], 'test_secret_key_for_hs256_at_least_32_bytes_long');

        $this->mockRequestParserFactory->shouldReceive('getParserChain')->once()->andReturn([$mockParser]);
        $mockParser->shouldReceive('parse')->with($mockRequest)->once()->andReturn($testTokenString);

        $this->mockBlacklist->shouldReceive('has')->once()->andReturn(false);
        $this->mockOurValidator->shouldReceive('validate')->once()->andReturnUndefined();

        $token = $this->manager->parseTokenFromRequest($mockRequest);
        $this->assertInstanceOf(TokenInterface::class, $token);
        $this->assertEquals('from_req_jti', $token->getId());
    }

    public function testParseTokenFromRequestReturnsNullIfNoTokenFound(): void
    {
        $mockRequest = Mockery::mock(ServerRequestInterface::class);
        $mockParser = Mockery::mock(RequestParserInterface::class);

        $this->mockRequestParserFactory->shouldReceive('getParserChain')->once()->andReturn([$mockParser]);
        $mockParser->shouldReceive('parse')->with($mockRequest)->once()->andReturn(null); // 解析器未找到token

        $this->assertNull($this->manager->parseTokenFromRequest($mockRequest));
    }

    public function testRefreshTokenSuccessfully(): void
    {
        $now = new DateTimeImmutable();
        // 旧 token，未过期，但在刷新期内（这里简化，只要能被轻量级解析即可）
        $oldTokenJti = 'old_refreshable_jti';
        $oldTokenExp = $now->add(new DateInterval('PT30M')); // 假设30分钟后过期
        $oldTokenString = $this->generateTestHs256TokenString([
            'jti' => $oldTokenJti,
            'exp' => $oldTokenExp->getTimestamp(),
            'iat' => $now->getTimestamp(),
            'nbf' => $now->getTimestamp(),
            'user_id' => 'user_to_refresh',
            'sub' => 'user_to_refresh_sub'
        ], 'test_secret_key_for_hs256_at_least_32_bytes_long');

        // Mock Blacklist 对旧 token 的行为
        $this->mockBlacklist->shouldReceive('has')->once()
            ->with(Mockery::on(function (TokenInterface $token) use ($oldTokenJti) {
                return $token->getId() === $oldTokenJti;
            }))
            ->andReturn(false); // 旧 token 不在黑名单

        $this->mockBlacklist->shouldReceive('add')->once()
            ->with(Mockery::on(function (TokenInterface $token) use ($oldTokenJti) {
                return $token->getId() === $oldTokenJti;
            }), Mockery::type('int')) // 第二个参数是 TTL
            ->andReturn(true); // 旧 token 成功加入黑名单

        // PayloadFactory 行为 (用于生成新 token)
        $this->mockPayloadFactory->shouldReceive('getClaimsToRefresh')->andReturn(['iat', 'exp', 'nbf', 'jti'])->byDefault();
        // issueToken 的其他 PayloadFactory 调用已在 setUp 中 mock

        $newToken = $this->manager->refreshToken($oldTokenString, false, false); // resetClaims = false

        $this->assertInstanceOf(TokenInterface::class, $newToken);
        $this->assertNotEquals($oldTokenJti, $newToken->getId()); // 新 token 应该有新的 JTI
        $this->assertEquals('user_to_refresh_sub', $newToken->getSubject()); // sub 应该被保留 (因为 resetClaims=false)
        $this->assertEquals('user_to_refresh', $newToken->getClaim('user_id')); // 自定义声明应被保留
    }


    public function testInvalidateTokenSuccessfully(): void
    {
        $jti = 'jti_to_invalidate';
        $mockTokenObject = Mockery::mock(TokenInterface::class);
        $mockTokenObject->shouldReceive('getId')->andReturn($jti);

        $this->mockBlacklist->shouldReceive('add')->once()
            ->with($mockTokenObject, null) // 默认 grace period
            ->andReturn(true);

        $this->assertSame($this->manager, $this->manager->invalidate($mockTokenObject));
    }

    public function testInvalidateTokenFailsIfBlacklistAddFails(): void
    {
        $this->expectException(JwtException::class);
        // 根据 Manager::invalidate() 的实现，它会检查 Blacklist::add() 的返回值
        // 或者捕获 Blacklist::add() 可能抛出的异常

        $mockTokenObject = Mockery::mock(TokenInterface::class);
        $mockTokenObject->shouldReceive('getId')->andReturn('some_jti');

        $this->mockBlacklist->shouldReceive('add')->once()->andReturn(false); // 模拟加入黑名单失败

        $this->manager->invalidate($mockTokenObject);
    }


    // --- 辅助方法 ---

    /**
     * 生成一个用于测试的 HS256 签名的 JWT 字符串。
     */
    protected function generateTestHs256TokenString(array $claims, string $secret): string
    {
        $config = Configuration::forSymmetricSigner(new Sha256(), InMemory::plainText($secret));
        $builder = $config->builder();

        // 先处理需要 DateTimeImmutable 对象的标准时间声明
        if (isset($claims['iat']) && is_int($claims['iat'])) {
            $builder = $builder->issuedAt(new DateTimeImmutable('@' . $claims['iat']));
            unset($claims['iat']); // 从数组中移除，避免被 withClaim 处理
        }
        if (isset($claims['nbf']) && is_int($claims['nbf'])) {
            $builder = $builder->canOnlyBeUsedAfter(new DateTimeImmutable('@' . $claims['nbf']));
            unset($claims['nbf']);
        }
        if (isset($claims['exp']) && is_int($claims['exp'])) {
            $builder = $builder->expiresAt(new DateTimeImmutable('@' . $claims['exp']));
            unset($claims['exp']);
        }

        // 处理其他标准声明
        if (isset($claims['iss'])) {
            $builder = $builder->issuedBy($claims['iss']);
            unset($claims['iss']);
        }
        if (isset($claims['sub'])) {
            $builder = $builder->relatedTo((string)$claims['sub']);
            unset($claims['sub']);
        }
        if (isset($claims['aud'])) {
            $audience = $claims['aud'];
            $builder = $builder->permittedFor(...(is_array($audience) ? $audience : [$audience]));
            unset($claims['aud']);
        }
        if (isset($claims['jti'])) {
            $builder = $builder->identifiedBy($claims['jti']);
            unset($claims['jti']);
        }

        // 处理剩余的自定义声明
        foreach ($claims as $name => $value) {
            $builder = $builder->withClaim($name, $value);
        }

        return $builder->getToken($config->signer(), $config->signingKey())->toString();
    }
}