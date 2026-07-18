<?php

declare(strict_types=1);

namespace Kylesean\Jwt\Tests;

use DateTimeImmutable;
use Kylesean\Jwt\Blacklist;
use Kylesean\Jwt\Cache\CacheFactory;
use Kylesean\Jwt\Contract\TokenInterface;
use Hyperf\Contract\ConfigInterface;
use Mockery;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\SimpleCache\CacheInterface; // Core dependency for Blacklist
use Psr\Log\LoggerInterface; // Used internally by Blacklist

#[CoversClass(Blacklist::class)]
class BlacklistTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    protected Blacklist $blacklist;
    protected Mockery\MockInterface|CacheInterface $mockCache;
    protected Mockery\MockInterface|ConfigInterface $mockConfig;
    protected Mockery\MockInterface|CacheFactory $mockCacheFactory;

    protected string $defaultCachePrefix = 'jwt_blacklist_';
    protected int $defaultGracePeriod = 3600; // 1 hour in seconds

    protected function setUp(): void
    {
        parent::setUp();

        $this->mockCache = Mockery::mock(CacheInterface::class);
        $this->mockConfig = Mockery::mock(ConfigInterface::class);
        $this->mockCacheFactory = Mockery::mock(CacheFactory::class);

        // Configure CacheFactory mock to return our mockCache
        $this->mockCacheFactory->shouldReceive('get')->andReturn($this->mockCache)->byDefault();

        // Configure ConfigInterface mock default return values
        $this->mockConfig->shouldReceive('get')
            ->with('jwt.blacklist_grace_period', 3600)
            ->andReturn($this->defaultGracePeriod)
            ->byDefault();
        $this->mockConfig->shouldReceive('get')
            ->with('jwt.blacklist_cache_prefix', 'jwt_blacklist_')
            ->andReturn($this->defaultCachePrefix)
            ->byDefault();

        $this->blacklist = new Blacklist($this->mockCacheFactory, $this->mockConfig);
    }

    protected function createMockToken(?string $jti, ?DateTimeImmutable $exp = null): TokenInterface
    {
        $token = Mockery::mock(TokenInterface::class);
        $token->shouldReceive('getId')->andReturn($jti)->byDefault();
        $token->shouldReceive('getExpirationTime')->andReturn($exp)->byDefault();
        $token->shouldReceive('getAllClaims')
            ->andReturnUsing(fn() => ['jti' => $jti, 'exp' => $exp?->getTimestamp()])
            ->byDefault();
        return $token;
    }

    /**
     * Helper method: Generate cache key consistent with Blacklist implementation.
     */
    protected function getExpectedCacheKey(string $jti): string
    {
        return $this->defaultCachePrefix . hash('sha256', $jti);
    }

    public function testAddTokenToBlacklist(): void
    {
        $jti = 'test_jti_123';
        $exp = new DateTimeImmutable('+1 hour');
        $token = $this->createMockToken($jti, $exp);
        $expectedCacheKey = $this->getExpectedCacheKey($jti);

        $this->mockCache->shouldReceive('get')->once()->with($expectedCacheKey)->andReturn(null);
        $this->mockCache->shouldReceive('set')
            ->once()
            ->with($expectedCacheKey, 0, $this->defaultGracePeriod)
            ->andReturn(true);

        $this->assertTrue($this->blacklist->add($token));
    }

    public function testAddTokenWithCustomTtl(): void
    {
        $jti = 'test_jti_custom_ttl';
        $token = $this->createMockToken($jti, new DateTimeImmutable('+2 hours'));
        $customTtl = 1800; // 30 minutes
        $expectedCacheKey = $this->getExpectedCacheKey($jti);

        $this->mockCache->shouldReceive('get')->once()->with($expectedCacheKey)->andReturn(null);
        $this->mockCache->shouldReceive('set')
            ->once()
            ->with($expectedCacheKey, 0, $customTtl)
            ->andReturn(true);

        $this->assertTrue($this->blacklist->add($token, $customTtl));
    }

    public function testAddTokenFailsIfNoJti(): void
    {
        $token = $this->createMockToken(null); // No JTI
        $this->mockCache->shouldNotReceive('set'); // set should not be called
        $this->assertFalse($this->blacklist->add($token));
    }

    public function testAddTokenUsesDefaultGracePeriodIfTokenHasNoExp(): void
    {
        $jti = 'test_jti_no_exp';
        $token = $this->createMockToken($jti, null); // No expiration time
        $expectedCacheKey = $this->getExpectedCacheKey($jti);

        $this->mockCache->shouldReceive('get')->once()->with($expectedCacheKey)->andReturn(null);
        $this->mockCache->shouldReceive('set')
            ->once()
            ->with($expectedCacheKey, 0, $this->defaultGracePeriod)
            ->andReturn(true);

        $this->assertTrue($this->blacklist->add($token));
    }

    public function testHasTokenInBlacklist(): void
    {
        $jti = 'existing_jti';
        $token = $this->createMockToken($jti);
        $expectedCacheKey = $this->getExpectedCacheKey($jti);

        $this->mockCache->shouldReceive('get')->once()->with($expectedCacheKey)->andReturn(0);
        $this->assertTrue($this->blacklist->has($token));

        $this->mockCache->shouldReceive('get')->once()->with($expectedCacheKey)->andReturn(null);
        $this->assertFalse($this->blacklist->has($token));

        $this->mockCache->shouldReceive('get')->once()->with($expectedCacheKey)->andReturn(true);
        $this->assertTrue($this->blacklist->has($token));
    }

    public function testHasTokenReturnsFalseIfNoJti(): void
    {
        $token = $this->createMockToken(null);
        $this->mockCache->shouldNotReceive('get');
        $this->assertFalse($this->blacklist->has($token));
    }

    public function testRemoveTokenFromBlacklist(): void
    {
        $jti = 'jti_to_remove';
        $token = $this->createMockToken($jti);
        $expectedCacheKey = $this->getExpectedCacheKey($jti);

        $this->mockCache->shouldReceive('delete')->once()->with($expectedCacheKey)->andReturn(true);
        $this->assertTrue($this->blacklist->remove($token));
    }

    public function testRemoveTokenFailsIfNoJti(): void
    {
        $token = $this->createMockToken(null);
        $this->mockCache->shouldNotReceive('delete');
        $this->assertFalse($this->blacklist->remove($token));
    }

    public function testClearMethodThrowsException(): void
    {
        $this->expectException(\Kylesean\Jwt\Exception\JwtException::class);
        $this->expectExceptionMessage('Clearing the entire JWT blacklist is unsupported');
        $this->blacklist->clear();
    }

    public function testSetAndGetDefaultGracePeriod(): void
    {
        $this->blacklist->setDefaultGracePeriod(7200);
        $this->assertEquals(7200, $this->blacklist->getDefaultGracePeriod());

        $this->blacklist->setDefaultGracePeriod(0);
        $this->assertEquals(0, $this->blacklist->getDefaultGracePeriod());

        $this->blacklist->setDefaultGracePeriod(-100);
        $this->assertEquals(0, $this->blacklist->getDefaultGracePeriod());
    }

    public function testUsesCustomCachePrefixFromConfig(): void
    {
        $customPrefix = 'my_app_jwt_bl_';
        $this->mockConfig->shouldReceive('get')
            ->with('jwt.blacklist_cache_prefix', 'jwt_blacklist_')
            ->andReturn($customPrefix);

        // Re-create Blacklist instance to apply new config mock
        $blacklistWithCustomPrefix = new Blacklist($this->mockCacheFactory, $this->mockConfig);

        $jti = 'test_jti_custom_prefix';
        $token = $this->createMockToken($jti, new DateTimeImmutable('+1 hour'));
        $expectedCacheKey = $customPrefix . hash('sha256', $jti);

        $this->mockCache->shouldReceive('get')->once()->with($expectedCacheKey)->andReturn(null);
        $this->mockCache->shouldReceive('set')
            ->once()
            ->with($expectedCacheKey, 0, Mockery::any())
            ->andReturn(true);

        $blacklistWithCustomPrefix->add($token);
    }

    public function testAddAndHasTokenWithConcurrencyGracePeriod(): void
    {
        $jti = 'test_jti_concurrency';
        $token = $this->createMockToken($jti);
        $expectedCacheKey = $this->getExpectedCacheKey($jti);
        $concurrencyGracePeriod = 30; // 30 seconds

        // 1. Verify add logic: Stored value is current time plus grace period in seconds
        $this->mockCache->shouldReceive('get')->once()->with($expectedCacheKey)->andReturn(null);
        $this->mockCache->shouldReceive('set')
            ->once()
            ->with($expectedCacheKey, Mockery::on(fn($val) => is_int($val) && $val > time()), $this->defaultGracePeriod)
            ->andReturn(true);

        $this->assertTrue($this->blacklist->add($token, null, $concurrencyGracePeriod));

        // 2. Verify has logic: If within grace period, should not be blacklisted (has returns false)
        $futureTimestamp = time() + 10;
        $this->mockCache->shouldReceive('get')->once()->with($expectedCacheKey)->andReturn($futureTimestamp);
        $this->assertFalse($this->blacklist->has($token));

        // 3. Verify has logic: If grace period passed, should be blacklisted (has returns true)
        $pastTimestamp = time() - 5;
        $this->mockCache->shouldReceive('get')->once()->with($expectedCacheKey)->andReturn($pastTimestamp);
        $this->assertTrue($this->blacklist->has($token));
    }
}