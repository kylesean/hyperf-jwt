<?php

declare(strict_types=1);

namespace FriendsOfHyperf\Jwt\Tests;

use DateTimeImmutable;
use FriendsOfHyperf\Jwt\Token as OurToken; // 我们要测试的 Token 类
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\DataSet; // 用于创建 lcobucci Token 的 claims
use Lcobucci\JWT\Token\Plain; // lcobucci 的 Plain Token (UnencryptedToken 的一种)
use Lcobucci\JWT\Token\Signature;
use PHPUnit\Framework\TestCase; // 所有测试类继承自这个

/**
 * @internal
 * @coversNothing
 */
class TokenTest extends TestCase
{
    protected Configuration $lcobucciConfig;
    protected Plain $lcobucciPlainToken; // 底层的 lcobucci Token 实例
    protected OurToken $token; // 我们自己封装的 Token 实例

    protected function setUp(): void
    {
        parent::setUp();

        // 准备一个 lcboocci/jwt 的 Plain Token 实例以供测试
        // 我们可以手动构建它，或者使用 Configuration 和 Builder
        // 这里为了简单，我们直接实例化 Plain Token 所需的 DataSet 和 Signature
        // 在实际应用中，这个 Plain Token 是由 lcobucci 的 Parser 或 Builder 生成的

        $this->lcobucciConfig = Configuration::forSymmetricSigner(
            new Sha256(),
            InMemory::plainText(bin2hex(random_bytes(32))) // 随机密钥，内容不重要，因为我们不测试签名验证
        );

        $originalClaims = [
            'jti' => 'test_jti_123',
            'iss' => 'http://example.com',
            'aud' => ['http://example.org', 'http://otherexample.org'],
            'sub' => 'test_subject_456',
            'iat' => new DateTimeImmutable('@' . (time() - 3600)), // 1小时前
            'nbf' => new DateTimeImmutable('@' . (time() - 3000)), // 50分钟前
            'exp' => new DateTimeImmutable('@' . (time() + 3600)), // 1小时后
            'custom_claim' => 'custom_value',
            'another_claim' => 12345,
        ];

        // DataSet 构造函数期望字符串键和混合值。
        // 对于标准时间声明，lcobucci/jwt v5 期望它们是 DateTimeImmutable 对象。
        $claimsForLcobucciDataSet = $originalClaims; // 直接使用原始声明


        $dataSet = new DataSet($claimsForLcobucciDataSet, 'encoded_header.encoded_claims');
        $headersSet = new DataSet(['typ' => 'JWT', 'alg' => 'HS256'], 'encoded_header');
        $signature = new Signature('dummy_signature_hash', 'encoded_signature');

        $this->lcobucciPlainToken = new Plain($headersSet, $dataSet, $signature);
        $this->token = new OurToken($this->lcobucciPlainToken);
    }

    public function testGetLcobucciToken(): void
    {
        $this->assertSame($this->lcobucciPlainToken, $this->token->getLcobucciToken());
    }

    public function testToStringMethod(): void
    {
        // Plain token 的 toString() 方法会返回 "header.claims.signature"
        // 由于我们是手动构造的，需要确保我们的 PlainToken 能正确 toString()
        // 或者我们可以 mock LcobucciPlainToken::toString() 的行为
        // 为了更真实的测试，我们依赖 LcobucciPlainToken 的实际行为
        $this->assertEquals($this->lcobucciPlainToken->toString(), $this->token->toString());
        $this->assertEquals($this->lcobucciPlainToken->toString(), (string) $this->token); // 测试 __toString
    }

    public function testGetId(): void
    {
        $this->assertEquals('test_jti_123', $this->token->getId());
    }

    public function testGetIssuer(): void
    {
        $this->assertEquals('http://example.com', $this->token->getIssuer());
    }

    public function testGetAudience(): void
    {
        $this->assertEquals(['http://example.org', 'http://otherexample.org'], $this->token->getAudience());
    }

    public function testGetSubject(): void
    {
        $this->assertEquals('test_subject_456', $this->token->getSubject());
    }

    public function testGetIssuedAt(): void
    {
        $this->assertInstanceOf(DateTimeImmutable::class, $this->token->getIssuedAt());
        // Lcobucci v5 会将时间戳声明直接解析为 DateTimeImmutable
        // 我们在 setUp 中设置的是时间戳，但 PlainToken 的 claims()->get('iat') 应该返回 DateTimeImmutable
        // 如果不是，我们的 Token 实现中 getIssuedAt() 等方法需要调整。
        // 检查：Lcobucci\JWT\Token\Plain->claims()->get() 对于标准时间声明是否返回 DateTimeImmutable
        // 根据 lcobucci/jwt v4 & v5, $token->claims()->get('iat') 确实返回 DateTimeImmutable 对象。
        $this->assertEquals(time() - 3600, $this->token->getIssuedAt()->getTimestamp(), '', 1.0); // 允许1秒误差
    }

    public function testGetNotBefore(): void
    {
        $this->assertInstanceOf(DateTimeImmutable::class, $this->token->getNotBefore());
        $this->assertEquals(time() - 3000, $this->token->getNotBefore()->getTimestamp(), '', 1.0);
    }

    public function testGetExpirationTime(): void
    {
        $this->assertInstanceOf(DateTimeImmutable::class, $this->token->getExpirationTime());
        $this->assertEquals(time() + 3600, $this->token->getExpirationTime()->getTimestamp(), '', 1.0);
    }

    public function testGetClaim(): void
    {
        $this->assertEquals('custom_value', $this->token->getClaim('custom_claim'));
        $this->assertEquals(12345, $this->token->getClaim('another_claim'));
        $this->assertNull($this->token->getClaim('non_existent_claim'));
    }

    public function testHasClaim(): void
    {
        $this->assertTrue($this->token->hasClaim('custom_claim'));
        $this->assertTrue($this->token->hasClaim('jti'));
        $this->assertFalse($this->token->hasClaim('non_existent_claim'));
    }

    public function testGetAllClaims(): void
    {
        $allClaims = $this->token->getAllClaims();
        $this->assertArrayHasKey('jti', $allClaims);
        $this->assertArrayHasKey('iss', $allClaims);
        $this->assertArrayHasKey('aud', $allClaims);
        $this->assertArrayHasKey('sub', $allClaims);
        $this->assertArrayHasKey('iat', $allClaims);
        $this->assertArrayHasKey('nbf', $allClaims);
        $this->assertArrayHasKey('exp', $allClaims);
        $this->assertArrayHasKey('custom_claim', $allClaims);
        $this->assertEquals('custom_value', $allClaims['custom_claim']);

        // 验证 getAllClaims 返回的是原始值（例如时间戳），还是 DateTimeImmutable 对象
        // 我们的 Token::getAllClaims() 实现是直接返回 lcobucciToken->claims()->all() 的遍历
        // lcobucci/jwt v5 的 claims()->all() 返回的是 ['claimName' => mixedValue]
        // 对于时间声明，它返回的是 DateTimeImmutable 对象。
        $this->assertInstanceOf(DateTimeImmutable::class, $allClaims['iat']);
    }

    public function testGetAudienceWhenItIsSingleStringInLcobucciToken(): void
    {
        // 测试当底层 aud 是单个字符串时的兼容性
        $claims = ['aud' => 'http://singleaudience.org'];
        $dataSet = new DataSet($claims, 'h.c');
        $headersSet = new DataSet([], 'h');
        $signature = new Signature('hash', 'sig');
        $lcobucciTokenWithSingleAud = new Plain($headersSet, $dataSet, $signature);
        $ourToken = new OurToken($lcobucciTokenWithSingleAud);

        $this->assertEquals(['http://singleaudience.org'], $ourToken->getAudience());
    }

    public function testGettersForMissingStandardClaims(): void
    {
        // 测试当标准声明不存在时，对应的 getter 方法返回 null
        $emptyDataSet = new DataSet([], 'h.c');
        $headersSet = new DataSet([], 'h');
        $signature = new Signature('hash', 'sig');
        $lcobucciTokenWithoutClaims = new Plain($headersSet, $emptyDataSet, $signature);
        $ourToken = new OurToken($lcobucciTokenWithoutClaims);

        $this->assertNull($ourToken->getId());
        $this->assertNull($ourToken->getIssuer());
        $this->assertEquals([], $ourToken->getAudience()); // aud 缺失时应返回空数组
        $this->assertNull($ourToken->getSubject());
        $this->assertNull($ourToken->getIssuedAt());
        $this->assertNull($ourToken->getNotBefore());
        $this->assertNull($ourToken->getExpirationTime());
    }
}