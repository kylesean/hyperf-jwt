<?php

declare(strict_types=1);

namespace FriendsOfHyperf\Jwt\Tests\Unit;

use DateTimeImmutable;
use FriendsOfHyperf\Jwt\Exception\TokenExpiredException;
use FriendsOfHyperf\Jwt\Exceptions\MalformedTokenException;
use FriendsOfHyperf\Jwt\Exceptions\TokenNotBeforeException;
use FriendsOfHyperf\Jwt\Exceptions\TokenSignatureInvalidException;
use FriendsOfHyperf\Jwt\Jwt;
use FriendsOfHyperf\Jwt\Tests\TestCase;
use Lcobucci\Clock\FrozenClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\Parser as LcobucciTokenParser;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;

// 我们将定义的异常

// 我们将定义的异常

// 我们将定义的异常 (例如签名、格式问题)

// 我们将定义的异常

// 用于签名验证

// 用于 nbf, iat, exp 验证

// 用于控制时间，方便测试过期等场景
// Alias to avoid conflict

/**
 * @covers \FriendsOfHyperf\Jwt\Jwt
 * @covers \FriendsOfHyperf\Jwt\Exceptions\InvalidTokenException
 * @covers \FriendsOfHyperf\Jwt\Exception\TokenExpiredException
 * @covers \FriendsOfHyperf\Jwt\Exception\TokenInvalidException
 * @covers \FriendsOfHyperf\Jwt\Exceptions\TokenNotBeforeException
 */
class JwtTest extends TestCase
{
    private Configuration $config;
    private InMemory $signingKey;
    private Sha256 $signer;
    private Jwt $jwt;

    protected function setUp(): void
    {
        parent::setUp();
        // 在每个测试开始前，都准备好一套标准的配置和 Jwt 实例
        // 这样可以避免在每个测试方法中重复配置代码
        $this->signer = new Sha256();
        // 使用一个固定的密钥，方便测试token的生成和解析
        $this->signingKey = InMemory::plainText('your-very-secure-secret-key-for-testing-12345');

        // 配置 lcobucci/jwt
        // 注意：为了能捕获并测试 lcobucci/jwt 抛出的特定验证异常，
        // 我们需要在 Configuration 中设置 Validator 和约束。
        $this->config = Configuration::forSymmetricSigner(
            $this->signer,
            $this->signingKey
        );

        // 添加基础的验证约束：签名必须匹配
        $this->config->setValidationConstraints(
            new SignedWith($this->signer, $this->signingKey)
        // StrictValidAt 将在需要时动态添加，因为 FrozenClock 的缘故
        );

        $this->jwt = new Jwt($this->config);
    }

    // --- Generate Tests (from previous steps, assumed to be here) ---
    public function testGenerateBasicToken(): void
    {
        $userId = 'test_user_123';
        $customClaims = ['role' => 'admin'];
        $ttl = 3600;
        $tokenString = $this->jwt->generate($userId, $customClaims, $ttl);
        $this->assertIsString($tokenString);

        $parsedToken = $this->config->parser()->parse($tokenString);
        $this->assertInstanceOf(Token::class, $parsedToken);
        $this->assertEquals($userId, $parsedToken->claims()->get('sub'));
        $this->assertEquals('admin', $parsedToken->claims()->get('role'));
    }

    public function testGenerateTokenUsesDefaultTtlWhenNotProvided(): void
    {
        $userId = 'test_user_default_ttl';
        $tokenString = $this->jwt->generate($userId);
        $parsedToken = $this->config->parser()->parse($tokenString);
        $this->assertTrue($parsedToken->claims()->has('exp'));
        $this->assertEquals(
            $parsedToken->claims()->get('iat')->getTimestamp() + 3600,
            $parsedToken->claims()->get('exp')->getTimestamp()
        );
    }

    public function testGenerateTokenWithZeroTtl(): void
    {
        $userId = 'test_user_zero_ttl';
        $tokenString = $this->jwt->generate($userId, [], 0);
        $parsedToken = $this->config->parser()->parse($tokenString);
        $this->assertEquals(
            $parsedToken->claims()->get('iat')->getTimestamp(),
            $parsedToken->claims()->get('exp')->getTimestamp()
        );
    }

    public function testGenerateTokenWithNullTtlHasNoExpiryClaim(): void
    {
        $userId = 'test_user_null_ttl';

        // $this->jwt 是在 setUp() 中创建的，使用了空的 $jwtConfig
        // Jwt::generate 的逻辑我们之前调整过，当 $ttl 参数显式为 null 时，应不设置 exp
        $tokenString = $this->jwt->generate($userId, [], null);

        // 使用 Lcobucci\JWT\Token\Parser 直接解析，不进行任何验证
        $parser = new LcobucciTokenParser(new JoseEncoder());
        try {
            $parsedToken = $parser->parse($tokenString);
        } catch (\Lcobucci\JWT\Token\InvalidTokenStructure $e) {
            $this->fail("Test setup error: Generated token string has invalid structure: " . $e->getMessage());
        } catch (\Lcobucci\JWT\Encoding\CannotDecodeContent $e) {
            $this->fail("Test setup error: Cannot decode generated token content: " . $e->getMessage());
        }

        // 现在断言 'exp' 声明不存在
        $this->assertFalse(
            $parsedToken->claims()->has('exp'),
            'Token should not have an "exp" claim when TTL is null. Generated token: ' . $tokenString
        );
    }


    // 验证一个完全有效的 Token (签名正确，时间有效) 可以被成功解析。
    public function testParseValidTokenString(): void
    {
        $userId = 'user_for_parsing';
        $customClaims = ['foo' => 'bar'];
        // 生成一个短时间有效的 token，确保在测试运行时它仍然有效
        $generatedTokenString = $this->jwt->generate($userId, $customClaims, 60);

        // 为了测试 StrictValidAt，我们需要一个 clock
        $clock = new FrozenClock(new DateTimeImmutable()); // 当前时间
        $validAtConstraint = new StrictValidAt($clock);
        // 获取新的配置实例，添加 StrictValidAt 约束
        $validationConfig = Configuration::forSymmetricSigner($this->signer, $this->signingKey);
        $validationConfig->setValidationConstraints(
            new SignedWith($this->signer, $this->signingKey),
            $validAtConstraint // 添加时间验证约束
        );
        $jwtWithTimeValidation = new Jwt($validationConfig);


        $parsedToken = $jwtWithTimeValidation->parse($generatedTokenString);

        $this->assertInstanceOf(Token::class, $parsedToken);
        $this->assertEquals($userId, $parsedToken->claims()->get('sub'));
        $this->assertEquals('bar', $parsedToken->claims()->get('foo'));
        $this->assertTrue($parsedToken->claims()->has('exp'));
    }

    // 提供一个非 JWT 格式的字符串，期望 MalformedTokenException (因为解析器会失败)。
    public function testParseMalformedTokenStringThrowsException(): void
    {
        $this->expectException(MalformedTokenException::class); // 期望我们自定义的异常
        //$this->expectExceptionMessage('Invalid token structure'); // 期望的异常消息

        $malformedToken = 'this.is.not.a.valid.jwt';
        $this->jwt->parse($malformedToken); // jwt 实例使用的是没有 StrictValidAt 的 config
    }

    // 提供一个用不同密钥签名的 Token，期望 TokenSignatureInvalidException (因为 SignedWith 约束会失败)。
    public function testParseTokenWithInvalidSignatureThrowsException(): void
    {
        $this->expectException(TokenSignatureInvalidException::class);
        //$this->expectExceptionMessage('Token signature mismatch');
        // 使用不同的密钥生成 Token
        $anotherKey = InMemory::plainText('another-different-secret-key-54321');
        $configWithDifferentKey = Configuration::forSymmetricSigner($this->signer, $anotherKey);
        $jwtWithDifferentKey = new Jwt($configWithDifferentKey);
        $tokenWithWrongSignature = $jwtWithDifferentKey->generate('user_wrong_sig', [], 60);
        // 使用原始的 jwt 实例 (配置了原始密钥) 来解析
        $this->jwt->parse($tokenWithWrongSignature);
    }

    //  生成一个 Token，然后将时间拨到其过期之后，期望 TokenExpiredException。
    public function testParseExpiredTokenThrowsException(): void
    {
        $this->expectException(TokenExpiredException::class);
        // $this->expectExceptionMessage('Token has expired'); // 我们后面再精确这个
        $userId = 'user_expired';
        $ttlInSeconds = 1; // Token 1秒后过期
        // 记录一个精确的 "现在" 时间，用于 Token 生成和时钟控制
        $generationTime = new DateTimeImmutable();
        // ---- 修改 generate 方法以接受签发时间 ----
        // 为了精确控制，我们可能需要稍微修改 Jwt::generate 或创建一个特殊的 token
        // 假设我们能控制 iat, nbf, exp
        $iat = $generationTime;
        $nbf = $generationTime;
        $exp = $generationTime->modify("+{$ttlInSeconds} seconds");
        // 手动构建 Token 字符串，确保时间戳是我们控制的
        $builder = $this->config->builder(); // 使用 setUp 中的 config (只有 SignedWith)
        $tokenString = $builder
            ->issuedAt($iat)
            ->canOnlyBeUsedAfter($nbf)
            ->expiresAt($exp)
            ->relatedTo($userId)
            ->identifiedBy(uniqid())
            ->getToken($this->signer, $this->signingKey) // 使用 setUp 中的 signer 和 key
            ->toString();

        // 设置 FrozenClock 的时间为 Token 过期之后
        $clockTime = $generationTime->modify("+" . ($ttlInSeconds + 2) . " seconds"); // 过期后再加2秒
        $clock = new FrozenClock($clockTime);
        $validAtConstraint = new StrictValidAt($clock);
        // 配置用于解析的 Configuration，确保包含 StrictValidAt
        $parsingConfig = Configuration::forSymmetricSigner($this->signer, $this->signingKey);
        $parsingConfig->setValidationConstraints(
            new SignedWith($this->signer, $this->signingKey),
            $validAtConstraint // 使用我们精确控制的 clock
        );
        $jwtForParsing = new Jwt($parsingConfig);

        $jwtForParsing->parse($tokenString); // 这里应该要抛出异常了

    }

    // 生成一个 nbf 在未来的 Token，然后将时间设置在 nbf 之前，期望 TokenNotBeforeException。
    public function testParseTokenNotYetValidThrowsException(): void
    {
        $this->expectException(TokenNotBeforeException::class);
        $this->expectExceptionMessage('Token is not yet valid');

        // 生成一个 5 秒后才生效的 Token
        $now = new DateTimeImmutable();
        $nbf = $now->modify('+5 seconds');
        $exp = $now->modify('+60 seconds'); // 确保过期时间在 nbf 之后

        // 手动构建 Token 以精确控制 nbf
        $builder = $this->config->builder()
            ->issuedAt($now)
            ->canOnlyBeUsedAfter($nbf)
            ->expiresAt($exp)
            ->relatedTo('user_nbf')
            ->identifiedBy(uniqid());
        $tokenString = $builder->getToken($this->config->signer(), $this->config->signingKey())->toString();

        // 冻结时间在 Token 生效之前
        $clock = new FrozenClock($now->modify('+1 second')); // Token 签发1秒后，但在nbf之前
        $validAtConstraint = new StrictValidAt($clock);

        $validationConfig = Configuration::forSymmetricSigner($this->signer, $this->signingKey);
        $validationConfig->setValidationConstraints(
            new SignedWith($this->signer, $this->signingKey),
            $validAtConstraint
        );
        $jwtWithTimeValidation = new Jwt($validationConfig);

        $jwtWithTimeValidation->parse($tokenString);
    }

    // 主要关心当前时间是否在 nbf 和 exp 之间。iat 在未来本身通常不直接导致 StrictValidAt 失败，除非它影响了 nbf 或 exp 的逻辑。这个测试是为了明确 StrictValidAt 的默认行为。
    public function testParseTokenWithIatInFutureIsValidByDefaultWithStrictValidAt(): void
    {
        // StrictValidAt 默认情况下不认为 iat 在未来是无效的，只要当前时间在 nbf 和 exp 之间。
        // 如果要严格检查 iat 不能在未来，需要额外约束或配置。
        // 这个测试验证默认行为。
        $now = new DateTimeImmutable();
        $iatFuture = $now->modify('+10 seconds'); // iat 在未来10秒
        $nbf = $now; // nbf 是现在
        $exp = $now->modify('+60 seconds'); // exp 在未来60秒

        $builder = $this->config->builder()
            ->issuedAt($iatFuture)
            ->canOnlyBeUsedAfter($nbf)
            ->expiresAt($exp)
            ->relatedTo('user_iat_future')
            ->identifiedBy(uniqid());
        $tokenString = $builder->getToken($this->config->signer(), $this->config->signingKey())->toString();

        // 冻结时间为 "现在"，此时 iat 是未来的，但 nbf 和 exp 是有效的
        $clock = new FrozenClock($now);
        $validAtConstraint = new StrictValidAt($clock);
        $validationConfig = Configuration::forSymmetricSigner($this->signer, $this->signingKey);
        $validationConfig->setValidationConstraints(
            new SignedWith($this->signer, $this->signingKey),
            $validAtConstraint
        );
        $jwtWithTimeValidation = new Jwt($validationConfig);

        $parsedToken = $jwtWithTimeValidation->parse($tokenString); // 应该能成功解析
        $this->assertInstanceOf(Token::class, $parsedToken);
        $this->assertEquals('user_iat_future', $parsedToken->claims()->get('sub'));
    }


}