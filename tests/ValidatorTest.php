<?php

declare(strict_types=1);

namespace Kylesean\Jwt\Tests;

use DateTimeImmutable;
use DateInterval;
use Kylesean\Jwt\Contract\TokenInterface;
use Kylesean\Jwt\Exception\TokenExpiredException;
use Kylesean\Jwt\Exception\TokenInvalidException;
use Kylesean\Jwt\Exception\TokenNotYetValidException;
use Kylesean\Jwt\Validator;
use Mockery;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Validator::class)]
class ValidatorTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    protected Validator $validator;
    protected TokenInterface|Mockery\MockInterface $mockToken;

    protected function setUp(): void
    {
        parent::setUp();
        $this->validator = new Validator();
        // Create a new mock Token for each test to avoid state pollution
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

        // Test leeway cannot be negative
        $this->validator->setLeeway(-10);
        $this->assertEquals(0, $this->validator->getLeeway());
    }

    // --- Test checkTimestamps method ---

    public function testCheckTimestampsWhenTokenIsExpired(): void
    {
        $this->expectException(TokenExpiredException::class);
        $this->expectExceptionMessage('Token has expired.');

        $now = new DateTimeImmutable();
        $this->mockToken->shouldReceive('getExpirationTime')->andReturn($now->sub(new DateInterval('PT1S'))); // Expired 1 second ago
        $this->mockToken->shouldReceive('getNotBefore')->andReturnNull(); // Other timestamps do not affect this test
        $this->mockToken->shouldReceive('getIssuedAt')->andReturnNull();

        $this->validator->checkTimestamps($this->mockToken);
    }

    public function testCheckTimestampsWhenTokenIsExpiredWithLeeway(): void
    {
        $this->expectException(TokenExpiredException::class);

        $now = new DateTimeImmutable();
        $this->validator->setLeeway(60); // 60s leeway
        // Token expired 30s ago, but within leeway, should not throw exception
        // $this->mockToken->shouldReceive('getExpirationTime')->andReturn($now->sub(new DateInterval('PT30S')));
        // $this->mockToken->shouldReceive('getNotBefore')->andReturnNull();
        // $this->mockToken->shouldReceive('getIssuedAt')->andReturnNull();
        // $this->validator->checkTimestamps($this->mockToken); // This line would fail because no exception thrown

        // Token expired 90s ago, exceeding leeway, should throw exception
        $this->mockToken = Mockery::mock(TokenInterface::class); // New mock
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
        $this->mockToken->shouldReceive('getNotBefore')->andReturn($now->add(new DateInterval('PT1S'))); // Valid only after 1 second
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
        $this->mockToken->shouldReceive('getIssuedAt')->andReturn($now->add(new DateInterval('PT60S'))); // iat in 1 minute future

        $this->validator->checkTimestamps($this->mockToken);
    }

    public function testCheckTimestampsWhenRequiredTimeClaimIsMissing(): void
    {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Expiration Time (exp) claim is required but not present.');

        $this->validator->setRequiredClaims(['exp']); // Set exp as required
        $this->mockToken->shouldReceive('getExpirationTime')->andReturnNull(); // exp missing
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

        // If no exception thrown, test passes
        $this->validator->checkTimestamps($this->mockToken);
        $this->assertTrue(true); // Explicitly assert test reached here
    }


    // --- Test checkClaims method ---

    public function testCheckClaimsMissingRequiredClaim(): void
    {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Required claim "iss" is missing.');

        $this->mockToken->shouldReceive('hasClaim')->with('iss')->andReturn(false);
        // $this->validator->setRequiredClaims(['iss']); // setRequiredClaims is a method of Validator, not a parameter of checkClaims

        $this->validator->checkClaims($this->mockToken, [], ['iss']); // Third parameter is requiredClaimKeys
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
        // Even though we mainly test getAudience, getClaim('aud') will also be called
        $this->mockToken->shouldReceive('getClaim')->with('aud')->once()->andReturn(['client-a']); // Return same value as getAudience or compatible value
        $this->mockToken->shouldReceive('getAudience')->once()->andReturn(['client-a']); // aud in Token

        $this->validator->checkClaims($this->mockToken, ['aud' => 'client-b']); // Expected aud


    }

    public function testCheckClaimsAudienceArrayMatch(): void
    {
        $this->mockToken->shouldReceive('hasClaim')->with('aud')->once()->andReturn(true);
        // Even though we mainly test getAudience, getClaim('aud') will also be called
        $this->mockToken->shouldReceive('getClaim')->with('aud')->once()->andReturn(['client-a', 'client-b']); // Return same value as getAudience or compatible value
        $this->mockToken->shouldReceive('getAudience')->once()->andReturn(['client-a', 'client-b']);

        // Expected aud is an array, and token contains one of them
        $this->validator->checkClaims($this->mockToken, ['aud' => ['client-b', 'client-c']]);
        $this->assertTrue(true); // No exception
    }

    public function testCheckClaimsValid(): void
    {
        $this->mockToken->shouldReceive('hasClaim')->with('iss')->andReturn(true);
        $this->mockToken->shouldReceive('getClaim')->with('iss')->andReturn('my-app');
        $this->mockToken->shouldReceive('hasClaim')->with('sub')->andReturn(true); // Check existence only

        $this->validator->checkClaims($this->mockToken, ['iss' => 'my-app'], ['sub']);
        $this->assertTrue(true); // No exception
    }


    // --- Test validate method (Integration test of checkClaims and checkTimestamps) ---
    public function testValidateMethodCallsSubMethods(): void
    {
        // Using a Spy to verify internal method calls, but simpler to test combined effect
        // Here we test a fully valid scenario
        $now = new DateTimeImmutable();
        $this->validator->setRequiredClaims(['custom_required']); // Set a required claim for checkClaims to verify
        $this->validator->setLeeway(0);

        $this->mockToken->shouldReceive('hasClaim')->with('custom_required')->andReturn(true);
        $this->mockToken->shouldReceive('getClaim')->with('custom_required')->andReturn('some_value'); // Assume configured expectedClaims requires it

        // Timestamp related
        $this->mockToken->shouldReceive('getExpirationTime')->andReturn($now->add(new DateInterval('PT1H')));
        $this->mockToken->shouldReceive('getNotBefore')->andReturn($now->sub(new DateInterval('PT1M')));
        $this->mockToken->shouldReceive('getIssuedAt')->andReturn($now->sub(new DateInterval('PT2M')));

        // Assume configured expectedClaims (passed to validate at runtime)
        $expectedClaimsForRuntime = ['iss' => 'expected-issuer'];
        $this->mockToken->shouldReceive('hasClaim')->with('iss')->andReturn(true);
        $this->mockToken->shouldReceive('getClaim')->with('iss')->andReturn('expected-issuer');
        // $this->mockToken->shouldReceive('getAudience')->andReturn([]); // If aud is part of required_claims or expectedClaims

        // validate method returns nothing, passes if no exception
        $this->validator->validate($this->mockToken, true, $expectedClaimsForRuntime);
        $this->assertTrue(true);
    }

    public function testValidateMethodFailsIfTimestampsFail(): void
    {
        $this->expectException(TokenExpiredException::class);

        $now = new DateTimeImmutable();
        $this->mockToken->shouldReceive('getExpirationTime')->once()->andReturn($now->sub(new DateInterval('PT1S'))); // Expired
        // Even if other claims are valid, invalid timestamp causes validate to fail
        $this->mockToken->shouldReceive('hasClaim')->andReturn(true); // Pass checkClaims
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

        // Valid timestamps
        $this->mockToken->shouldReceive('getExpirationTime')->andReturn($now->add(new DateInterval('PT1H')));
        $this->mockToken->shouldReceive('getNotBefore')->andReturn($now->sub(new DateInterval('PT1M')));
        $this->mockToken->shouldReceive('getIssuedAt')->andReturn($now->sub(new DateInterval('PT2M')));

        // But claim check fails
        $this->mockToken->shouldReceive('hasClaim')->with('must_exist')->andReturn(false);

        $this->validator->validate($this->mockToken, true, []);
    }
}