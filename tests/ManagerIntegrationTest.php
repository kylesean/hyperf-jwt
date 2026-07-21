<?php

declare(strict_types=1);

namespace Kylesean\Jwt\Tests;

use DateInterval;
use DateTimeImmutable;
use Kylesean\Jwt\Blacklist;
use Kylesean\Jwt\Exception\TokenExpiredException;
use Kylesean\Jwt\Exception\TokenInvalidException;
use Kylesean\Jwt\Exception\TokenNotYetValidException;
use Kylesean\Jwt\Manager;
use Kylesean\Jwt\PayloadFactory;
use Kylesean\Jwt\RequestParser\RequestParserFactory;
use Kylesean\Jwt\Tests\Support\FixedClock;
use Kylesean\Jwt\Tests\Support\InMemoryCache;
use Kylesean\Jwt\Tests\Support\InMemoryCacheFactory;
use Kylesean\Jwt\Tests\Support\InMemoryConfig;
use Kylesean\Jwt\Tests\Support\InMemoryContainer;
use Kylesean\Jwt\Validator;
use Lcobucci\JWT\Configuration as LcobucciConfiguration;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory as LcobucciInMemoryKey;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

/**
 * Integration tests wiring the real Manager + Validator + Blacklist + PayloadFactory
 * together (no ValidatorInterface/BlacklistInterface mocks). These guard the behaviors
 * that pure-mock unit tests cannot see: required-claims enforcement, blacklist TTL
 * calculation on invalidation, and end-to-end refresh semantics.
 */
#[CoversClass(Manager::class)]
#[CoversClass(Validator::class)]
#[CoversClass(Blacklist::class)]
#[CoversClass(PayloadFactory::class)]
class ManagerIntegrationTest extends TestCase
{
    private const SECRET = 'integration_test_secret_key_32_bytes_long!!';

    private InMemoryCache $cache;

    private FixedClock $clock;

    private Manager $manager;

    private LcobucciConfiguration $lcobucciConfig;

    protected function setUp(): void
    {
        parent::setUp();
        $this->cache = new InMemoryCache();
        $this->clock = new FixedClock(new DateTimeImmutable());
        $this->manager = $this->buildManager();
    }

    /**
     * @param array<string, mixed> $configOverrides flat dot-notation config keys
     */
    private function buildManager(array $configOverrides = []): Manager
    {
        $config = new InMemoryConfig(array_merge([
            'jwt.ttl' => 60,
            'jwt.refresh_ttl' => 20160,
            'jwt.nbf_offset_seconds' => 0,
            'jwt.issuer' => 'test-issuer',
            'jwt.audience' => 'test-audience',
            'jwt.subject_claim' => 'sub',
            'jwt.required_claims' => [
                'iss' => true,
                'aud' => true,
                'iat' => true,
                'nbf' => true,
                'exp' => true,
            ],
            'jwt.required_claims.iss' => true,
            'jwt.required_claims.aud' => true,
            'jwt.leeway' => 0,
            'jwt.blacklist_enabled' => true,
            'jwt.blacklist_concurrency_grace_period' => 0,
            'jwt.blacklist_grace_period' => 1209600,
            'jwt.blacklist_cache_prefix' => 'jwt_blacklist_',
            'jwt.token_parsers' => [],
        ], $configOverrides));

        $container = new InMemoryContainer();
        $this->lcobucciConfig = LcobucciConfiguration::forSymmetricSigner(
            new Sha256(),
            LcobucciInMemoryKey::plainText(self::SECRET)
        );

        return new Manager(
            $container,
            $config,
            $this->lcobucciConfig,
            new Validator(),
            new Blacklist(new InMemoryCacheFactory($this->cache), $config),
            new RequestParserFactory($container, $config),
            new PayloadFactory($config, $this->clock),
            $this->clock,
        );
    }

    /**
     * Craft a raw HS256 token string with exactly the given claims, bypassing the
     * Manager's own builder, to simulate externally issued / malformed tokens.
     *
     * @param array<string, mixed> $claims
     */
    private function craftToken(array $claims): string
    {
        $builder = $this->lcobucciConfig->builder();
        foreach ($claims as $name => $value) {
            $builder = match ($name) {
                'iat' => $builder->issuedAt($value),
                'nbf' => $builder->canOnlyBeUsedAfter($value),
                'exp' => $builder->expiresAt($value),
                'iss' => $builder->issuedBy($value),
                'sub' => $builder->relatedTo((string) $value),
                'aud' => $builder->permittedFor(...(is_array($value) ? $value : [$value])),
                'jti' => $builder->identifiedBy($value),
                default => $builder->withClaim($name, $value),
            };
        }

        return $builder->getToken($this->lcobucciConfig->signer(), $this->lcobucciConfig->signingKey())->toString();
    }

    public function testIssueAndParseRoundTrip(): void
    {
        $token = $this->manager->issueToken(['user_id' => 42, 'role' => 'admin'], 'user-7');

        $this->assertSame('user-7', $token->getSubject());
        $this->assertNotNull($token->getId());
        $this->assertNotNull($token->getIssuedAt());
        $this->assertNotNull($token->getNotBefore(), 'Issued tokens must always carry an nbf claim');
        $this->assertNotNull($token->getExpirationTime());
        $this->assertSame('test-issuer', $token->getIssuer());
        $this->assertSame(['test-audience'], $token->getAudience());

        $parsed = $this->manager->parse($token->toString());
        $this->assertNotNull($parsed);
        $this->assertSame(42, $parsed->getClaim('user_id'));
        $this->assertSame('admin', $parsed->getClaim('role'));
        $this->assertSame('user-7', $parsed->getSubject());
    }

    public function testParseRejectsTamperedToken(): void
    {
        $token = $this->manager->issueToken([], 'user-1');
        $parts = explode('.', $token->toString());
        $parts[1] = rtrim(strtr(base64_encode('{"sub":"hacker"}'), '+/', '-_'), '=');
        $tampered = implode('.', $parts);

        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Token signature validation failed.');
        $this->manager->parse($tampered);
    }

    public function testParseRejectsTokenWithoutExpWhenRequired(): void
    {
        $now = $this->clock->now();
        $tokenString = $this->craftToken([
            'iss' => 'test-issuer',
            'aud' => 'test-audience',
            'iat' => $now,
            'nbf' => $now,
        ]);

        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Expiration Time (exp) claim is required but not present.');
        $this->manager->parse($tokenString);
    }

    public function testParseRejectsTokenWithoutNbfWhenRequired(): void
    {
        $now = $this->clock->now();
        $tokenString = $this->craftToken([
            'iss' => 'test-issuer',
            'aud' => 'test-audience',
            'iat' => $now,
            'exp' => $now->add(new DateInterval('PT1H')),
        ]);

        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Not Before (nbf) claim is required but not present.');
        $this->manager->parse($tokenString);
    }

    public function testParseRejectsExpiredToken(): void
    {
        $now = $this->clock->now();
        $tokenString = $this->craftToken([
            'iat' => $now->sub(new DateInterval('PT2H')),
            'nbf' => $now->sub(new DateInterval('PT2H')),
            'exp' => $now->sub(new DateInterval('PT1S')),
        ]);

        $this->expectException(TokenExpiredException::class);
        $this->manager->parse($tokenString);
    }

    public function testParseRejectsNotYetValidToken(): void
    {
        $now = $this->clock->now();
        $tokenString = $this->craftToken([
            'iat' => $now,
            'nbf' => $now->add(new DateInterval('PT1H')),
            'exp' => $now->add(new DateInterval('PT2H')),
        ]);

        $this->expectException(TokenNotYetValidException::class);
        $this->manager->parse($tokenString);
    }

    public function testParseRejectsIssuerMismatch(): void
    {
        $now = $this->clock->now();
        $tokenString = $this->craftToken([
            'iss' => 'evil-issuer',
            'aud' => 'test-audience',
            'iat' => $now,
            'nbf' => $now,
            'exp' => $now->add(new DateInterval('PT1H')),
        ]);

        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessageMatches('/Claim "iss" value mismatch/');
        $this->manager->parse($tokenString);
    }

    public function testParseRejectsAudienceMismatch(): void
    {
        $now = $this->clock->now();
        $tokenString = $this->craftToken([
            'iss' => 'test-issuer',
            'aud' => 'other-audience',
            'iat' => $now,
            'nbf' => $now,
            'exp' => $now->add(new DateInterval('PT1H')),
        ]);

        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessageMatches('/Audience \(aud\) claim mismatch/');
        $this->manager->parse($tokenString);
    }

    public function testInvalidateBlocksParseAndBlacklistEntryCoversRefreshWindow(): void
    {
        $token = $this->manager->issueToken([], 'user-1');
        $this->manager->invalidate($token);

        try {
            $this->manager->parse($token->toString());
            $this->fail('Blacklisted token should not parse.');
        } catch (TokenInvalidException $e) {
            $this->assertSame('Token has been blacklisted.', $e->getMessage());
        }

        // Entry TTL must cover the remaining lifetime (60 min) plus the whole
        // refresh window (20160 min), otherwise the logout could be undone by a
        // later refresh.
        $entry = reset($this->cache->store);
        $this->assertIsArray($entry);
        [$value, $expiresAt] = $entry;
        $this->assertSame(0, $value, 'Manual invalidation must take effect immediately');
        $expectedTtl = 3600 + 20160 * 60;
        $this->assertEqualsWithDelta($expectedTtl, $expiresAt - $this->clock->now()->getTimestamp(), 5);
    }

    public function testInvalidateForceForeverUsesOneYearTtl(): void
    {
        $token = $this->manager->issueToken([], 'user-1');
        $this->manager->invalidate($token, true);

        $entry = reset($this->cache->store);
        $this->assertIsArray($entry);
        [, $expiresAt] = $entry;
        $this->assertEqualsWithDelta(Manager::FOREVER_TTL_SECONDS, $expiresAt - $this->clock->now()->getTimestamp(), 5);
    }

    public function testRefreshTokenBlacklistsOldTokenAndPreservesClaims(): void
    {
        $old = $this->manager->issueToken(['user_id' => 9], 'user-9');
        $new = $this->manager->refreshToken($old->toString());

        $this->assertNotSame($old->getId(), $new->getId());
        $this->assertSame('user-9', $new->getSubject());
        $this->assertSame(9, $new->getClaim('user_id'));

        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Token has been blacklisted.');
        $this->manager->parse($old->toString());
    }

    public function testRefreshedTokenCannotBeRefreshedAgain(): void
    {
        $old = $this->manager->issueToken([], 'user-1');
        $this->manager->refreshToken($old->toString());

        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Token has been blacklisted and cannot be refreshed.');
        $this->manager->refreshToken($old->toString());
    }

    public function testLogoutSurvivesTokenExpiryInsideRefreshWindow(): void
    {
        // Regression test: previously invalidate() stored entries with the 3600s
        // code-default TTL, so a logged-out token became usable (and refreshable
        // into a brand-new token) once the entry expired while still inside its
        // 14-day refresh window. The entry TTL now covers exp + refresh_ttl.
        $token = $this->manager->issueToken([], 'user-1');
        $this->manager->invalidate($token);

        // Fast-forward past the token expiry (ttl 60 min), but well inside the
        // refresh window: the token must still be rejected, refresh included.
        $this->clock->setTo($this->clock->now()->add(new DateInterval('PT2H')));

        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Token has been blacklisted and cannot be refreshed.');
        $this->manager->refreshToken($token->toString());
    }

    public function testNegativeNbfOffsetMakesTokenValidBeforeIat(): void
    {
        $manager = $this->buildManager(['jwt.nbf_offset_seconds' => -60]);
        $token = $manager->issueToken([], 'user-1');

        $iat = $token->getIssuedAt();
        $nbf = $token->getNotBefore();
        $this->assertNotNull($iat);
        $this->assertNotNull($nbf);
        $this->assertSame(-60, $nbf->getTimestamp() - $iat->getTimestamp());

        $this->assertNotNull($manager->parse($token->toString()));
    }

    public function testEmptyIssuerSkipsIssClaimAndValidation(): void
    {
        $manager = $this->buildManager(['jwt.issuer' => '']);
        $token = $manager->issueToken([], 'user-1');

        $this->assertNull($token->getIssuer());
        // required_claims.iss = true, but with no issuer configured the claim is
        // neither issued nor enforced.
        $this->assertNotNull($manager->parse($token->toString()));
    }
}
