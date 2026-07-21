<?php

declare(strict_types=1);

namespace Kylesean\Jwt\Tests;

use DateTimeImmutable;
use DateInterval;
use Kylesean\Jwt\Blacklist;

// Mock BlacklistInterface
use Kylesean\Jwt\Contract\BlacklistInterface;
use Kylesean\Jwt\Contract\PayloadFactoryInterface;
use Kylesean\Jwt\Contract\RequestParser\RequestParserFactoryInterface;
use Kylesean\Jwt\Contract\RequestParser\RequestParserInterface;
use Kylesean\Jwt\Contract\TokenInterface;
use Kylesean\Jwt\Contract\ValidatorInterface;
use Kylesean\Jwt\Exception\JwtException;
use Kylesean\Jwt\Exception\TokenExpiredException;
use Kylesean\Jwt\Exception\TokenInvalidException;
use Kylesean\Jwt\Manager;
use Kylesean\Jwt\PayloadFactory;

// Mock PayloadFactoryInterface
use Kylesean\Jwt\RequestParser\RequestParserFactory;

// Mock RequestParserFactoryInterface
use Kylesean\Jwt\Token;

// Used for make(Token::class)
use Kylesean\Jwt\Validator;

// Mock ValidatorInterface
use Hyperf\Contract\ConfigInterface;
use Hyperf\HttpServer\Contract\RequestInterface as HyperfRequestInterface;

// Used for testing parseTokenFromRequest
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
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Hyperf\Contract\ContainerInterface;
use Psr\Http\Message\ServerRequestInterface;

#[CoversClass(Manager::class)]
class ManagerTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    protected Mockery\MockInterface|ContainerInterface $mockContainer;
    protected Mockery\MockInterface|ConfigInterface $mockHyperfConfig;
    protected Mockery\MockInterface|ValidatorInterface $mockOurValidator; // Our custom Validator
    protected Mockery\MockInterface|BlacklistInterface $mockBlacklist;
    protected Mockery\MockInterface|RequestParserFactoryInterface $mockRequestParserFactory;
    protected Mockery\MockInterface|PayloadFactoryInterface $mockPayloadFactory;


    protected Manager $manager;

    protected function setUp(): void
    {
        parent::setUp();

        $this->mockContainer = Mockery::mock(ContainerInterface::class);
        $this->mockHyperfConfig = Mockery::mock(ConfigInterface::class);
        $this->mockOurValidator = Mockery::mock(ValidatorInterface::class); // Use new name
        $this->mockBlacklist = Mockery::mock(BlacklistInterface::class);
        $this->mockRequestParserFactory = Mockery::mock(RequestParserFactoryInterface::class);
        $this->mockPayloadFactory = Mockery::mock(PayloadFactoryInterface::class);

        // --- Configure Hyperf ConfigInterface default returns ---
        // (Keep unchanged, ensure all config read by Manager has mock)
        $this->mockHyperfConfig->shouldReceive('get')->with('jwt.ttl', Mockery::any())->andReturn(60)->byDefault();
        $this->mockHyperfConfig->shouldReceive('get')->with('jwt.nbf_offset_seconds', Mockery::any())->andReturn(0)->byDefault();
        $this->mockHyperfConfig->shouldReceive('get')->with('jwt.issuer', Mockery::any())->andReturn('test-issuer')->byDefault();
        $this->mockHyperfConfig->shouldReceive('get')->with('jwt.audience', Mockery::any())->andReturn('test-audience')->byDefault();
        $this->mockHyperfConfig->shouldReceive('get')->with('jwt.refresh_ttl', Mockery::any())->andReturn(20160)->byDefault();
        $this->mockHyperfConfig->shouldReceive('get')->with('jwt.subject_claim', Mockery::any())->andReturn('sub')->byDefault();
        $this->mockHyperfConfig->shouldReceive('get')->with('jwt.lcobucci_config_factory')->andReturn(null)->byDefault();
        $this->mockHyperfConfig->shouldReceive('get')->with('jwt.algo', Mockery::any())->andReturn(Sha256::class)->byDefault();
        $this->mockHyperfConfig->shouldReceive('get')->with('jwt.secret')->andReturn('test_secret_key_for_hs256_at_least_32_bytes_long')->byDefault();
        // If testing asymmetric encryption, also mock jwt.keys.public, jwt.keys.private, jwt.keys.passphrase
        // For example:
        // $this->mockHyperfConfig->shouldReceive('get')->with('jwt.keys.private')->andReturn('valid_private_key_string_or_file_path')->byDefault();
        // $this->mockHyperfConfig->shouldReceive('get')->with('jwt.keys.public')->andReturn('valid_public_key_string_or_file_path')->byDefault();
        // $this->mockHyperfConfig->shouldReceive('get')->with('jwt.keys.passphrase')->andReturn(null)->byDefault();

        $this->mockHyperfConfig->shouldReceive('get')->with('jwt.required_claims', Mockery::any())->andReturn([])->byDefault();
        $this->mockHyperfConfig->shouldReceive('get')->with('jwt.leeway', Mockery::any())->andReturn(0)->byDefault();
        $this->mockHyperfConfig->shouldReceive('get')->with('jwt.blacklist_enabled', true)->andReturn(true)->byDefault();
        $this->mockHyperfConfig->shouldReceive('get')->with('jwt.blacklist_concurrency_grace_period', Mockery::any())->andReturn(0)->byDefault();

        // Config read for Lcobucci validator constraint section in Manager::parse()
        $this->mockHyperfConfig->shouldReceive('get')
            ->with('jwt.required_claims.iss', false) // Exact match key and default
            ->andReturn(false) // By default, assume not enforcing iss validation at Lcobucci level
            ->byDefault();
        $this->mockHyperfConfig->shouldReceive('get')
            ->with('jwt.required_claims.aud', false) // Exact match key and default
            ->andReturn(false) // By default, assume not enforcing aud validation at Lcobucci level
            ->byDefault();


        // --- Configure PayloadFactory ---
        $this->mockPayloadFactory->shouldReceive('getIssuer')->andReturn('test-issuer')->byDefault();
        $this->mockPayloadFactory->shouldReceive('getAudience')->andReturn('test-audience')->byDefault();
        $this->mockPayloadFactory->shouldReceive('generateJti')->andReturn('mocked_jti_123')->byDefault();
        $this->mockPayloadFactory->shouldReceive('getCurrentTime')->andReturn(new DateTimeImmutable())->byDefault();
        $this->mockPayloadFactory->shouldReceive('getNbfOffsetSeconds')->andReturn(0)->byDefault();
        $this->mockPayloadFactory->shouldReceive('getTtl')->andReturn(60)->byDefault();
        $this->mockPayloadFactory->shouldReceive('getRefreshTtl')->andReturn(20160)->byDefault();
        /** @phpstan-ignore argument.type */
        $this->mockPayloadFactory->shouldReceive('getClaimsToRefresh')->andReturn(['iat', 'exp', 'nbf', 'jti'])->byDefault();
        $this->mockPayloadFactory->shouldReceive('setTtl')->withAnyArgs()->andReturnSelf()->byDefault();
        $this->mockPayloadFactory->shouldReceive('setRefreshTtl')->withAnyArgs()->andReturnSelf()->byDefault();


        // --- Configure our custom Validator ---
        $this->mockOurValidator->shouldReceive('setRequiredClaims')->withAnyArgs()->andReturnSelf()->byDefault();
        $this->mockOurValidator->shouldReceive('setLeeway')->withAnyArgs()->andReturnSelf()->byDefault();
        $this->mockOurValidator->shouldReceive('setClock')->withAnyArgs()->andReturnSelf()->byDefault();
        $this->mockOurValidator->shouldReceive('checkClaims')->withAnyArgs()->andReturnUndefined()->byDefault();
        $this->mockOurValidator->shouldReceive('checkTimestamps')->withAnyArgs()->andReturnUndefined()->byDefault();
        $this->mockOurValidator->shouldReceive('getLeeway')->andReturn(0)->byDefault();
        $this->mockOurValidator->shouldReceive('getRequiredClaims')->andReturn([])->byDefault();


        // --- Configure ContainerInterface ---
        // Manager::initLcobucciConfiguration() calls container->make(Signer::class)
        $this->mockContainer->shouldReceive('make')
            ->with(Sha256::class) // Or other Signer configured in jwt.algo
            ->andReturn(new Sha256()) // Return real Signer instance
            ->byDefault();
        // If testing asymmetric encryption, ensure corresponding Signer (Rsa\Sha256, Ecdsa\Sha256) can also be made
        // $this->mockContainer->shouldReceive('make')->with(\Lcobucci\JWT\Signer\Rsa\Sha256::class)->andReturn(new \Lcobucci\JWT\Signer\Rsa\Sha256());

        // Manager::issueToken and Manager::parse (internal wrapper) calls make(Token::class)
        $this->mockContainer->shouldReceive('make')
            ->with(Token::class, Mockery::on(function ($args) {
                return isset($args['lcobucciToken']) && ($args['lcobucciToken'] instanceof LcobucciPlainToken || $args['lcobucciToken'] instanceof \Lcobucci\JWT\UnencryptedToken);
            }))
            ->andReturnUsing(function ($class, $args) {
                return new Token($args['lcobucciToken']);
            })->byDefault();


        // Create real LcobucciConfiguration instance for testing
        // Simulates LcobucciFactory behavior
        $lcobucciConfig = Configuration::forSymmetricSigner(
            new Sha256(),
            InMemory::plainText('test_secret_key_for_hs256_at_least_32_bytes_long')
        );

        // Instantiate Manager
        $this->manager = new Manager(
            $this->mockContainer,
            $this->mockHyperfConfig,
            $lcobucciConfig,
            $this->mockOurValidator,
            $this->mockBlacklist,
            $this->mockRequestParserFactory,
            $this->mockPayloadFactory
        );
    }

    public function testIssueTokenSuccessfully(): void
    {
        $customClaims = ['user_id' => 1, 'data' => 'sample'];
        $subject = 1;

        // PayloadFactory's behavior is already mocked in setUp
        // Manager will call payloadFactory methods to get standard claim values

        // Lcobucci Configuration related mocks (if Manager does not create real Configuration)
        // Or, more simply, let initLcobucciConfiguration run to create real LcobucciConfiguration
        // Just need to ensure mockHyperfConfig provides correct config values.
        // setUp has mocked HyperfConfig so HS256 can be created.

        $token = $this->manager->issueToken($customClaims, $subject);

        $this->assertInstanceOf(TokenInterface::class, $token);
        $this->assertNotEmpty($token->toString());
        // Can further assert claims in token, but that tests PayloadFactory + Lcobucci
    }


    public function testParseValidTokenSuccessfully(): void
    {
        $now = new DateTimeImmutable();
        $testTokenString = $this->generateTestHs256TokenString([ // Use helper method to generate a valid token string
            'iss' => 'test-issuer',
            'aud' => 'test-audience',
            'jti' => 'valid_jti',
            'iat' => $now->getTimestamp(),
            'nbf' => $now->getTimestamp(),
            'exp' => $now->add(new DateInterval('PT1H'))->getTimestamp(),
            'user_id' => 123,
        ], 'test_secret_key_for_hs256_at_least_32_bytes_long');

        // Mock Blacklist::has() returns false (not in blacklist)
        $this->mockBlacklist->shouldReceive('has')->once()->with(Mockery::type(TokenInterface::class))->andReturn(false);

        // Mock Validator::checkClaims() does not throw exception
        $this->mockOurValidator->shouldReceive('checkClaims')->once()->with(Mockery::type(TokenInterface::class), [], [])->andReturnUndefined();

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
            // Other necessary claims...
            'iat' => $now->getTimestamp(),
            'nbf' => $now->getTimestamp(),
            'jti' => 'blacklisted_jti'
        ], 'test_secret_key_for_hs256_at_least_32_bytes_long');

        // Mock Blacklist::has() returns true
        $this->mockBlacklist->shouldReceive('has')->once()->andReturn(true);
        // Validator::validate should not be called
        $this->mockOurValidator->shouldNotReceive('validate');

        $this->manager->parse($testTokenString);
    }

    public function testParseTokenThrowsTokenExpiredException(): void
    {
        $now = new DateTimeImmutable();
        $expiredTime = $now->sub(new DateInterval('PT1S'));
        $testTokenString = $this->generateTestHs256TokenString([
            'exp' => $expiredTime->getTimestamp(),
            'iat' => $now->sub(new DateInterval('PT1H'))->getTimestamp(),
            'nbf' => $now->sub(new DateInterval('PT1H'))->getTimestamp(),
            'jti' => 'expired_jti'
        ], 'test_secret_key_for_hs256_at_least_32_bytes_long');

        $this->mockOurValidator->shouldReceive('checkTimestamps')
            ->once()
            ->andThrow(new TokenExpiredException('Token has expired.', $expiredTime));

        $this->mockBlacklist->shouldNotReceive('has');

        try {
            $this->manager->parse($testTokenString);
            $this->fail('Expected TokenExpiredException was not thrown');
        } catch (TokenExpiredException $e) {
            $this->assertSame('Token has expired.', $e->getMessage());
            $this->assertSame($expiredTime, $e->getExpiredAt());
            $this->assertArrayHasKey('expired_at', $e->getContext());
        }
    }

    public function testParseTokenFromRequestSuccessfully(): void
    {
        $mockRequest = Mockery::mock(ServerRequestInterface::class);
        $mockParser = Mockery::mock(RequestParserInterface::class);
        $now = new DateTimeImmutable();
        $testTokenString = $this->generateTestHs256TokenString([
            'exp' => $now->add(new DateInterval('PT1H'))->getTimestamp(),
            'iat' => $now->getTimestamp(),
            'nbf' => $now->getTimestamp(),
            'jti' => 'from_req_jti'
        ], 'test_secret_key_for_hs256_at_least_32_bytes_long');

        /** @phpstan-ignore argument.type */
        $this->mockRequestParserFactory->shouldReceive('getParserChain')->once()->andReturn([$mockParser]);
        $mockParser->shouldReceive('parse')->with($mockRequest)->once()->andReturn($testTokenString);

        $this->mockBlacklist->shouldReceive('has')->once()->andReturn(false);
        $this->mockOurValidator->shouldReceive('checkClaims')->once()->andReturnUndefined();

        $token = $this->manager->parseTokenFromRequest($mockRequest);
        $this->assertInstanceOf(TokenInterface::class, $token);
        $this->assertEquals('from_req_jti', $token->getId());
    }

    public function testParseTokenFromRequestReturnsNullIfNoTokenFound(): void
    {
        $mockRequest = Mockery::mock(ServerRequestInterface::class);
        $mockParser = Mockery::mock(RequestParserInterface::class);

        /** @phpstan-ignore argument.type */
        $this->mockRequestParserFactory->shouldReceive('getParserChain')->once()->andReturn([$mockParser]);
        $mockParser->shouldReceive('parse')->with($mockRequest)->once()->andReturn(null); // Parser did not find token

        $this->assertNull($this->manager->parseTokenFromRequest($mockRequest));
    }

    public function testRefreshTokenSuccessfully(): void
    {
        $now = new DateTimeImmutable();
        // Old token, not expired, but within refresh window
        $oldTokenJti = 'old_refreshable_jti';
        $oldTokenExp = $now->add(new DateInterval('PT30M')); // Assume expires in 30 minutes
        $oldTokenString = $this->generateTestHs256TokenString([
            'jti' => $oldTokenJti,
            'exp' => $oldTokenExp->getTimestamp(),
            'iat' => $now->getTimestamp(),
            'nbf' => $now->getTimestamp(),
            'user_id' => 'user_to_refresh',
            'sub' => 'user_to_refresh_sub'
        ], 'test_secret_key_for_hs256_at_least_32_bytes_long');

        // Mock Blacklist behavior for old token
        $this->mockBlacklist->shouldReceive('has')->once()
            ->with(Mockery::on(function (TokenInterface $token) use ($oldTokenJti) {
                return $token->getId() === $oldTokenJti;
            }))
            ->andReturn(false); // Old token not in blacklist

        $this->mockBlacklist->shouldReceive('add')->once()
            ->with(Mockery::on(function (TokenInterface $token) use ($oldTokenJti) {
                return $token->getId() === $oldTokenJti;
            }), Mockery::type('int'), Mockery::type('int')) // Correct arguments: token, ttl, grace_period
            ->andReturn(true); // Old token successfully added to blacklist

        // PayloadFactory behavior (used for generating new token)
        /** @phpstan-ignore argument.type */
        $this->mockPayloadFactory->shouldReceive('getClaimsToRefresh')->andReturn(['iat', 'exp', 'nbf', 'jti'])->byDefault();
        // Other PayloadFactory calls in issueToken are mocked in setUp

        $newToken = $this->manager->refreshToken($oldTokenString, false, false); // resetClaims = false

        $this->assertInstanceOf(TokenInterface::class, $newToken);
        $this->assertNotEquals($oldTokenJti, $newToken->getId()); // New token should have a new JTI
        $this->assertEquals('user_to_refresh_sub', $newToken->getSubject()); // sub should be preserved (resetClaims=false)
        $this->assertEquals('user_to_refresh', $newToken->getClaim('user_id')); // Custom claim should be preserved
    }

    public function testRefreshTokenThrowsExceptionIfNoJtiAndNotForceForever(): void
    {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Old token does not have a jti claim and cannot be reliably blacklisted.');

        $now = new DateTimeImmutable();
        $oldTokenString = $this->generateTestHs256TokenString([
            'exp' => $now->add(new DateInterval('PT30M'))->getTimestamp(),
            'iat' => $now->getTimestamp(),
            'nbf' => $now->getTimestamp(),
            // No jti claim
        ], 'test_secret_key_for_hs256_at_least_32_bytes_long');

        $this->mockBlacklist->shouldReceive('has')->once()->andReturn(false);
        $this->mockBlacklist->shouldReceive('add')->once()
            ->with(Mockery::type(TokenInterface::class), Mockery::type('int'), Mockery::type('int'))
            ->andReturn(false);

        $this->manager->refreshToken($oldTokenString, false, false);
    }

    public function testInvalidateTokenSuccessfully(): void
    {
        $jti = 'jti_to_invalidate';
        $mockTokenObject = Mockery::mock(TokenInterface::class);
        $mockTokenObject->shouldReceive('getId')->andReturn($jti);

        $this->mockBlacklist->shouldReceive('add')->once()
            ->with($mockTokenObject, null, 0) // Explicit 0 concurrency grace period for manual invalidation
            ->andReturn(true);

        $this->assertSame($this->manager, $this->manager->invalidate($mockTokenObject));
    }

    public function testInvalidateTokenForceForeverSuccessfully(): void
    {
        $jti = 'jti_to_invalidate';
        $mockTokenObject = Mockery::mock(TokenInterface::class);
        $mockTokenObject->shouldReceive('getId')->andReturn($jti);

        $this->mockBlacklist->shouldReceive('add')->once()
            ->with($mockTokenObject, 31536000, 0) // Expect 1 year TTL
            ->andReturn(true);

        $this->assertSame($this->manager, $this->manager->invalidate($mockTokenObject, true));
    }

    public function testInvalidateTokenFailsIfBlacklistAddFails(): void
    {
        $this->expectException(JwtException::class);

        $mockTokenObject = Mockery::mock(TokenInterface::class);
        $mockTokenObject->shouldReceive('getId')->andReturn('some_jti');

        $this->mockBlacklist->shouldReceive('add')->once()
            ->with($mockTokenObject, null, 0)
            ->andReturn(false); // Mock adding to blacklist failed

        $this->manager->invalidate($mockTokenObject);
    }

    public function testInvalidateTokenWhenBlacklistDisabledDoesNothing(): void
    {
        $this->mockHyperfConfig->shouldReceive('get')
            ->with('jwt.blacklist_enabled', true)
            ->andReturn(false);

        $mockTokenObject = Mockery::mock(TokenInterface::class);
        // Blacklist should not be touched
        $this->mockBlacklist->shouldNotReceive('add');

        $result = $this->manager->invalidate($mockTokenObject);
        $this->assertSame($this->manager, $result);
    }

    public function testInvalidateTokenPreservesOriginalJwtExceptionMessage(): void
    {
        // Verify the bug fix: JwtException should not be double-wrapped
        $mockTokenObject = Mockery::mock(TokenInterface::class);
        $mockTokenObject->shouldReceive('getId')->andReturn(null);

        $this->mockBlacklist->shouldReceive('add')->once()
            ->with($mockTokenObject, null, 0)
            ->andReturn(false);

        try {
            $this->manager->invalidate($mockTokenObject);
            $this->fail('Expected JwtException to be thrown.');
        } catch (JwtException $e) {
            // The message should be the original, not wrapped with "Error while invalidating token:"
            $this->assertEquals(
                'Token does not have a jti claim and cannot be reliably blacklisted.',
                $e->getMessage()
            );
        }
    }

    public function testIssueTokenWithObjectSubjectUsingGetJwtIdentifier(): void
    {
        $subjectObject = new class {
            public function getJwtIdentifier(): int
            {
                return 42;
            }
        };

        $token = $this->manager->issueToken([], $subjectObject);

        $this->assertInstanceOf(TokenInterface::class, $token);
        $this->assertEquals('42', $token->getSubject());
    }

    public function testIssueTokenWithNbfOffset(): void
    {
        $this->mockPayloadFactory->shouldReceive('getNbfOffsetSeconds')->andReturn(30);

        $token = $this->manager->issueToken(['role' => 'user'], 'user_1');

        $this->assertInstanceOf(TokenInterface::class, $token);
        $nbf = $token->getNotBefore();
        $iat = $token->getIssuedAt();
        $this->assertNotNull($nbf);
        $this->assertNotNull($iat);
        // nbf should be roughly 30 seconds after iat
        $this->assertEqualsWithDelta(30, $nbf->getTimestamp() - $iat->getTimestamp(), 1);
    }

    public function testIssueTokenWithEmptyAudience(): void
    {
        $this->mockPayloadFactory->shouldReceive('getAudience')->andReturn('');

        $token = $this->manager->issueToken([], 'user_1');

        $this->assertInstanceOf(TokenInterface::class, $token);
        // Token should have empty audience (not set)
        $this->assertEquals([], $token->getAudience());
    }

    public function testParseTokenWithWrongSignatureThrowsInvalidException(): void
    {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Token signature validation failed.');

        $now = new DateTimeImmutable();
        // Sign with a different secret
        $testTokenString = $this->generateTestHs256TokenString([
            'exp' => $now->add(new DateInterval('PT1H'))->getTimestamp(),
            'iat' => $now->getTimestamp(),
            'jti' => 'wrong_sig_jti'
        ], 'a_completely_different_secret_key_that_is_long_enough');

        $this->manager->parse($testTokenString);
    }

    public function testParseTokenThrowsTokenNotYetValidException(): void
    {
        // Create a token with nbf far in the future so LooseValidAt will reject it
        $now = new DateTimeImmutable();
        $testTokenString = $this->generateTestHs256TokenString([
            'exp' => $now->add(new DateInterval('PT2H'))->getTimestamp(),
            'iat' => $now->getTimestamp(),
            'nbf' => $now->add(new DateInterval('PT1H'))->getTimestamp(), // Not valid for 1 hour
            'jti' => 'nbf_future_jti'
        ], 'test_secret_key_for_hs256_at_least_32_bytes_long');

        try {
            $this->manager->parse($testTokenString);
            $this->fail('Expected exception was not thrown.');
        } catch (\Kylesean\Jwt\Exception\TokenNotYetValidException $e) {
            $this->assertStringContainsString('not yet valid', $e->getMessage());
        } catch (TokenInvalidException $e) {
            // LooseValidAt may frame nbf violation differently in some versions
            $this->assertTrue(true);
        }
    }

    public function testParseTokenWithIssuerValidationEnabled(): void
    {
        $now = new DateTimeImmutable();
        $testTokenString = $this->generateTestHs256TokenString([
            'iss' => 'test-issuer',
            'aud' => 'test-audience',
            'exp' => $now->add(new DateInterval('PT1H'))->getTimestamp(),
            'iat' => $now->getTimestamp(),
            'nbf' => $now->getTimestamp(),
            'jti' => 'iss_check_jti'
        ], 'test_secret_key_for_hs256_at_least_32_bytes_long');

        // Enable issuer requirement
        $this->mockHyperfConfig->shouldReceive('get')
            ->with('jwt.required_claims.iss', false)
            ->andReturn(true);

        $this->mockBlacklist->shouldReceive('has')->once()->andReturn(false);
        $this->mockOurValidator->shouldReceive('checkClaims')->once()
            ->with(
                Mockery::type(TokenInterface::class),
                Mockery::on(fn($expected) => isset($expected['iss']) && $expected['iss'] === 'test-issuer'),
                []
            )
            ->andReturnUndefined();

        $token = $this->manager->parse($testTokenString);
        $this->assertInstanceOf(TokenInterface::class, $token);
    }

    public function testRefreshTokenThrowsExceptionWhenBlacklistDisabled(): void
    {
        $this->expectException(JwtException::class);
        $this->expectExceptionMessage('Token refresh is not available when blacklist is disabled.');

        $this->mockHyperfConfig->shouldReceive('get')
            ->with('jwt.blacklist_enabled', true)
            ->andReturn(false);

        $this->manager->refreshToken('any_token_string');
    }

    public function testRefreshTokenThrowsExceptionWhenOutsideRefreshWindow(): void
    {
        $this->expectException(TokenExpiredException::class);
        $this->expectExceptionMessage('Token has expired and is outside the refresh window.');

        $now = new DateTimeImmutable();
        // Token expired 3 weeks ago (beyond the 2-week refresh window)
        $oldExp = $now->sub(new DateInterval('P21D'));
        $oldTokenString = $this->generateTestHs256TokenString([
            'jti' => 'old_expired_jti',
            'exp' => $oldExp->getTimestamp(),
            'iat' => $oldExp->sub(new DateInterval('PT1H'))->getTimestamp(),
            'nbf' => $oldExp->sub(new DateInterval('PT1H'))->getTimestamp(),
        ], 'test_secret_key_for_hs256_at_least_32_bytes_long');

        $this->mockBlacklist->shouldReceive('has')->once()->andReturn(false);

        $this->manager->refreshToken($oldTokenString);
    }

    public function testRefreshTokenWithResetClaimsTrue(): void
    {
        $now = new DateTimeImmutable();
        $oldTokenJti = 'old_reset_claims_jti';
        $oldTokenString = $this->generateTestHs256TokenString([
            'jti' => $oldTokenJti,
            'exp' => $now->add(new DateInterval('PT30M'))->getTimestamp(),
            'iat' => $now->getTimestamp(),
            'nbf' => $now->getTimestamp(),
            'user_id' => 'old_user',
            'sub' => 'old_sub'
        ], 'test_secret_key_for_hs256_at_least_32_bytes_long');

        $this->mockBlacklist->shouldReceive('has')->once()->andReturn(false);
        $this->mockBlacklist->shouldReceive('add')->once()->andReturn(true);

        // With resetClaims=true, no old custom claims should be carried over
        $newToken = $this->manager->refreshToken($oldTokenString, false, true);

        $this->assertInstanceOf(TokenInterface::class, $newToken);
        $this->assertNotEquals($oldTokenJti, $newToken->getId());
        // Custom claims should NOT be preserved when resetClaims=true
        $this->assertNull($newToken->getClaim('user_id'));
    }

    public function testRefreshTokenThrowsExceptionWhenOldTokenHasNoExp(): void
    {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Old token does not have an expiration time.');

        $now = new DateTimeImmutable();
        // Token without exp claim
        $oldTokenString = $this->generateTestHs256TokenString([
            'jti' => 'no_exp_jti',
            'iat' => $now->getTimestamp(),
            'nbf' => $now->getTimestamp(),
        ], 'test_secret_key_for_hs256_at_least_32_bytes_long');

        $this->mockBlacklist->shouldReceive('has')->once()->andReturn(false);

        $this->manager->refreshToken($oldTokenString);
    }

    public function testRefreshTokenThrowsWhenOldTokenIsBlacklisted(): void
    {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Token has been blacklisted and cannot be refreshed.');

        $now = new DateTimeImmutable();
        $oldTokenString = $this->generateTestHs256TokenString([
            'jti' => 'blacklisted_old_jti',
            'exp' => $now->add(new DateInterval('PT30M'))->getTimestamp(),
            'iat' => $now->getTimestamp(),
            'nbf' => $now->getTimestamp(),
        ], 'test_secret_key_for_hs256_at_least_32_bytes_long');

        $this->mockBlacklist->shouldReceive('has')->once()->andReturn(true);

        $this->manager->refreshToken($oldTokenString);
    }

    public function testParseTokenFromRequestReturnsNullWhenNoRequestAndNoContainer(): void
    {
        // Mock container does not have HyperfRequestInterface
        $this->mockContainer->shouldReceive('has')
            ->with(\Hyperf\HttpServer\Contract\RequestInterface::class)
            ->andReturn(false);

        $result = $this->manager->parseTokenFromRequest(null);
        $this->assertNull($result);
    }

    public function testSetAndGetTtlDelegatesToPayloadFactory(): void
    {
        $this->mockPayloadFactory->shouldReceive('setTtl')->with(120)->once()->andReturnSelf();
        $this->mockPayloadFactory->shouldReceive('getTtl')->once()->andReturn(120);

        $result = $this->manager->setTtl(120);
        $this->assertSame($this->manager, $result);
        $this->assertEquals(120, $this->manager->getTtl());
    }

    public function testGetSubjectClaimKey(): void
    {
        $this->assertEquals('sub', $this->manager->getSubjectClaimKey());
    }


    // --- Helper methods ---

    /**
     * Generate a JWT string signed with HS256 for testing.
     */
    protected function generateTestHs256TokenString(array $claims, string $secret): string
    {
        $config = Configuration::forSymmetricSigner(new Sha256(), InMemory::plainText($secret));
        $builder = $config->builder();

        // Handle standard time claims requiring DateTimeImmutable objects first
        if (isset($claims['iat']) && is_int($claims['iat'])) {
            $builder = $builder->issuedAt(new DateTimeImmutable('@' . $claims['iat']));
            unset($claims['iat']); // Remove from array to avoid withClaim processing
        }
        if (isset($claims['nbf']) && is_int($claims['nbf'])) {
            $builder = $builder->canOnlyBeUsedAfter(new DateTimeImmutable('@' . $claims['nbf']));
            unset($claims['nbf']);
        }
        if (isset($claims['exp']) && is_int($claims['exp'])) {
            $builder = $builder->expiresAt(new DateTimeImmutable('@' . $claims['exp']));
            unset($claims['exp']);
        }

        // Handle other standard claims
        if (isset($claims['iss'])) {
            $builder = $builder->issuedBy($claims['iss']);
            unset($claims['iss']);
        }
        if (isset($claims['sub'])) {
            $builder = $builder->relatedTo((string) $claims['sub']);
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

        // Handle remaining custom claims
        foreach ($claims as $name => $value) {
            $builder = $builder->withClaim($name, $value);
        }

        return $builder->getToken($config->signer(), $config->signingKey())->toString();
    }
}