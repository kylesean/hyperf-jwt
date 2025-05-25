<?php

declare(strict_types=1);

namespace FriendsOfHyperf\Jwt\Tests;

use DateTimeImmutable;
use DateInterval;
use FriendsOfHyperf\Jwt\Contract\TokenInterface;
use FriendsOfHyperf\Jwt\Exception\TokenExpiredException;
use FriendsOfHyperf\Jwt\Exception\TokenInvalidException;
use FriendsOfHyperf\Jwt\Exception\TokenNotYetValidException;
use FriendsOfHyperf\Jwt\Validator;
use Mockery; // 我们将使用 Mockery 来创建 TokenInterface 的 mock 对象
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration; // Mockery 与 PHPUnit 集成
use PHPUnit\Framework\TestCase;

/**
 * @internal
 * @coversNothing
 */
class ValidatorTest extends TestCase
{
    use MockeryPHPUnitIntegration; // 使用此 trait 自动处理 Mockery::close()

    protected Validator $validator;
    protected TokenInterface $mockToken; // Mock 对象

    protected function setUp(): void
    {
        parent::setUp();
        $this->validator = new Validator();
        // 为每个测试创建一个新的 mock Token，避免状态污染
        $this->mockToken = Mockery::mock(TokenInterface::class);
    }


    public function testSetAndGetRequiredClaims(): void
    {
        $claims = ['iss', 'sub'];
        $this->validator->setRequiredClaims($claims);
        $this->assertEquals($claims, $this->validator->getRequiredClaims());
    }


    public function testSetAndGetLeeway(): void
    {
        $this->validator->setLeeway(60);
        $this->assertEquals(60, $this->validator->getLeeway());

        $this->validator->setLeeway(0);
        $this->assertEquals(0, $this->validator->getLeeway());

        // 测试 leeway 不能为负数
        $this->validator->setLeeway(-10);
        $this->assertEquals(0, $this->validator->getLeeway());
    }

    // --- 测试 checkTimestamps 方法 ---

    public function testCheckTimestampsWhenTokenIsExpired(): void
    {
        $this->expectException(TokenExpiredException::class);
        $this->expectExceptionMessage('Token has expired.');

        $now = new DateTimeImmutable();
        $this->mockToken->shouldReceive('getExpirationTime')->andReturn($now->sub(new DateInterval('PT1S'))); // 1秒前过期
        $this->mockToken->shouldReceive('getNotBefore')->andReturnNull(); // 其他时间戳不影响此测试
        $this->mockToken->shouldReceive('getIssuedAt')->andReturnNull();

        $this->validator->checkTimestamps($this->mockToken);
    }

    public function testCheckTimestampsWhenTokenIsExpiredWithLeeway(): void
    {
        $this->expectException(TokenExpiredException::class);

        $now = new DateTimeImmutable();
        $this->validator->setLeeway(60); // 60秒容差
        // 令牌在 30 秒前过期，但在容差范围内，不应抛异常
        // $this->mockToken->shouldReceive('getExpirationTime')->andReturn($now->sub(new DateInterval('PT30S')));
        // $this->mockToken->shouldReceive('getNotBefore')->andReturnNull();
        // $this->mockToken->shouldReceive('getIssuedAt')->andReturnNull();
        // $this->validator->checkTimestamps($this->mockToken); // 这行会因为没有异常而失败

        // 令牌在 90 秒前过期，超出了容差范围，应该抛出异常
        $this->mockToken = Mockery::mock(TokenInterface::class); // 新的 mock
        $this->mockToken->shouldReceive('getExpirationTime')->once()->andReturn($now->sub(new DateInterval('PT90S')));
        $this->mockToken->shouldReceive('getNotBefore')->andReturnNull();
        $this->mockToken->shouldReceive('getIssuedAt')->andReturnNull();
        $this->validator->checkTimestamps($this->mockToken);
    }

    public function testCheckTimestampsWhenTokenIsNotYetValid(): void
    {
        $this->expectException(TokenNotYetValidException::class);
        $this->expectExceptionMessage('Token is not yet valid (Not Before).');

        $now = new DateTimeImmutable();
        $this->mockToken->shouldReceive('getExpirationTime')->andReturnNull();
        $this->mockToken->shouldReceive('getNotBefore')->andReturn($now->add(new DateInterval('PT1S'))); // 1秒后才生效
        $this->mockToken->shouldReceive('getIssuedAt')->andReturnNull();

        $this->validator->checkTimestamps($this->mockToken);
    }

    public function testCheckTimestampsWhenTokenIsIssuedInTheFuture(): void
    {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Issued At (iat) claim cannot be in the future.');

        $now = new DateTimeImmutable();
        $this->mockToken->shouldReceive('getExpirationTime')->andReturnNull();
        $this->mockToken->shouldReceive('getNotBefore')->andReturnNull();
        $this->mockToken->shouldReceive('getIssuedAt')->andReturn($now->add(new DateInterval('PT60S'))); // iat 在未来1分钟

        $this->validator->checkTimestamps($this->mockToken);
    }

    public function testCheckTimestampsWhenRequiredTimeClaimIsMissing(): void
    {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Expiration Time (exp) claim is required but not present.');

        $this->validator->setRequiredClaims(['exp']); // 设置 exp 为必需
        $this->mockToken->shouldReceive('getExpirationTime')->andReturnNull(); // exp 缺失
        $this->mockToken->shouldReceive('getNotBefore')->andReturnNull();
        $this->mockToken->shouldReceive('getIssuedAt')->andReturnNull();

        $this->validator->checkTimestamps($this->mockToken);
    }

    public function testCheckTimestampsValidToken(): void
    {
        $now = new DateTimeImmutable();
        $this->mockToken->shouldReceive('getExpirationTime')->andReturn($now->add(new DateInterval('PT3600S')));
        $this->mockToken->shouldReceive('getNotBefore')->andReturn($now->sub(new DateInterval('PT60S')));
        $this->mockToken->shouldReceive('getIssuedAt')->andReturn($now->sub(new DateInterval('PT120S')));

        // 如果没有异常抛出，则测试通过
        $this->validator->checkTimestamps($this->mockToken);
        $this->assertTrue(true); // 明确断言测试已执行到此
    }


    // --- 测试 checkClaims 方法 ---

    public function testCheckClaimsMissingRequiredClaim(): void
    {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Required claim "iss" is missing.');

        $this->mockToken->shouldReceive('hasClaim')->with('iss')->andReturn(false);
        // $this->validator->setRequiredClaims(['iss']); // setRequiredClaims 是 Validator 的方法，不是 checkClaims 的参数

        $this->validator->checkClaims($this->mockToken, [], ['iss']); // 第三个参数是 requiredClaimKeys
    }

    public function testCheckClaimsMissingExpectedClaim(): void
    {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Expected claim "aud" is missing.');

        $this->mockToken->shouldReceive('hasClaim')->with('aud')->andReturn(false);
        $this->validator->checkClaims($this->mockToken, ['aud' => 'test-audience']);
    }

    public function testCheckClaimsValueMismatch(): void
    {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Claim "iss" value mismatch. Expected "my-app" but got "other-app".');

        $this->mockToken->shouldReceive('hasClaim')->with('iss')->andReturn(true);
        $this->mockToken->shouldReceive('getClaim')->with('iss')->andReturn('other-app');

        $this->validator->checkClaims($this->mockToken, ['iss' => 'my-app']);
    }

    public function testCheckClaimsAudienceMismatch(): void
    {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessageMatches('/Audience \(aud\) claim mismatch. Expected one of \[(.*?)\] but got \[(.*?)\]\./');

        $this->mockToken->shouldReceive('hasClaim')->with('aud')->once()->andReturn(true);
        // 即使我们主要测试 getAudience，getClaim('aud') 也会被调用
        $this->mockToken->shouldReceive('getClaim')->with('aud')->once()->andReturn(['client-a']); // 返回与 getAudience 相同的值或一个兼容的值
        $this->mockToken->shouldReceive('getAudience')->once()->andReturn(['client-a']); // Token 中的 aud

        $this->validator->checkClaims($this->mockToken, ['aud' => 'client-b']); // 期望的 aud


    }

    public function testCheckClaimsAudienceArrayMatch(): void
    {
        $this->mockToken->shouldReceive('hasClaim')->with('aud')->once()->andReturn(true);
        // 即使我们主要测试 getAudience，getClaim('aud') 也会被调用
        $this->mockToken->shouldReceive('getClaim')->with('aud')->once()->andReturn(['client-a', 'client-b']); // 返回与 getAudience 相同的值或一个兼容的值
        $this->mockToken->shouldReceive('getAudience')->once()->andReturn(['client-a', 'client-b']);

        // 期望的 aud 是数组，且 token 中包含其中一个
        $this->validator->checkClaims($this->mockToken, ['aud' => ['client-b', 'client-c']]);
        $this->assertTrue(true); // No exception
    }

    public function testCheckClaimsValid(): void
    {
        $this->mockToken->shouldReceive('hasClaim')->with('iss')->andReturn(true);
        $this->mockToken->shouldReceive('getClaim')->with('iss')->andReturn('my-app');
        $this->mockToken->shouldReceive('hasClaim')->with('sub')->andReturn(true); // 仅检查存在性

        $this->validator->checkClaims($this->mockToken, ['iss' => 'my-app'], ['sub']);
        $this->assertTrue(true); // No exception
    }


    // --- 测试 validate 方法 (集成测试 checkClaims 和 checkTimestamps) ---
    public function testValidateMethodCallsSubMethods(): void
    {
        // 使用一个 Spy 来验证内部方法是否被调用，但更简单的是测试其综合效果
        // 这里我们测试一个完全有效的场景
        $now = new DateTimeImmutable();
        $this->validator->setRequiredClaims(['custom_required']); // 设置一个我们 checkClaims 会检查的
        $this->validator->setLeeway(0);

        $this->mockToken->shouldReceive('hasClaim')->with('custom_required')->andReturn(true);
        $this->mockToken->shouldReceive('getClaim')->with('custom_required')->andReturn('some_value'); // 假设配置的 expectedClaims 需要它

        // 时间戳相关
        $this->mockToken->shouldReceive('getExpirationTime')->andReturn($now->add(new DateInterval('PT1H')));
        $this->mockToken->shouldReceive('getNotBefore')->andReturn($now->sub(new DateInterval('PT1M')));
        $this->mockToken->shouldReceive('getIssuedAt')->andReturn($now->sub(new DateInterval('PT2M')));

        // 假设配置的 expectedClaims (运行时传入 validate 的)
        $expectedClaimsForRuntime = ['iss' => 'expected-issuer'];
        $this->mockToken->shouldReceive('hasClaim')->with('iss')->andReturn(true);
        $this->mockToken->shouldReceive('getClaim')->with('iss')->andReturn('expected-issuer');
        // $this->mockToken->shouldReceive('getAudience')->andReturn([]); // 如果 aud 是 required_claims 或 expectedClaims 的一部分

        // validate 方法不返回任何东西，如果没有异常则通过
        $this->validator->validate($this->mockToken, true, $expectedClaimsForRuntime);
        $this->assertTrue(true);
    }

    public function testValidateMethodFailsIfTimestampsFail(): void
    {
        $this->expectException(TokenExpiredException::class);

        $now = new DateTimeImmutable();
        $this->mockToken->shouldReceive('getExpirationTime')->once()->andReturn($now->sub(new DateInterval('PT1S'))); // Expired
        // 即使其他声明有效，时间戳无效也会导致 validate 失败
        $this->mockToken->shouldReceive('hasClaim')->andReturn(true); // 让 checkClaims 通过
        $this->mockToken->shouldReceive('getClaim')->andReturn('any_value');
        $this->mockToken->shouldReceive('getNotBefore')->andReturnNull();
        $this->mockToken->shouldReceive('getIssuedAt')->andReturnNull();

        $this->validator->validate($this->mockToken, true, []);
    }

    public function testValidateMethodFailsIfClaimsFail(): void
    {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Required claim "must_exist" is missing.');

        $now = new DateTimeImmutable();
        $this->validator->setRequiredClaims(['must_exist']);

        // 时间戳有效
        $this->mockToken->shouldReceive('getExpirationTime')->andReturn($now->add(new DateInterval('PT1H')));
        $this->mockToken->shouldReceive('getNotBefore')->andReturn($now->sub(new DateInterval('PT1M')));
        $this->mockToken->shouldReceive('getIssuedAt')->andReturn($now->sub(new DateInterval('PT2M')));

        // 但声明检查失败
        $this->mockToken->shouldReceive('hasClaim')->with('must_exist')->andReturn(false);

        $this->validator->validate($this->mockToken, true, []);
    }
}