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
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use Psr\SimpleCache\CacheInterface; // CacheInterface 是 Blacklist 依赖的核心
use Psr\Log\LoggerInterface; // Blacklist 内部使用

#[CoversNothing]
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

        // 配置 CacheFactory mock 返回我们的 mockCache
        $this->mockCacheFactory->shouldReceive('get')->andReturn($this->mockCache)->byDefault();

        // 配置 ConfigInterface mock 的默认返回值
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
     * 辅助方法：生成与 Blacklist 实现一致的缓存键。
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
        $expectedValue = $exp->getTimestamp();

        $this->mockCache->shouldReceive('has')->once()->with($expectedCacheKey)->andReturn(false);
        $this->mockCache->shouldReceive('set')
            ->once()
            ->with($expectedCacheKey, true, $this->defaultGracePeriod)
            ->andReturn(true);

        $this->assertTrue($this->blacklist->add($token));
    }

    public function testAddTokenWithCustomTtl(): void
    {
        $jti = 'test_jti_custom_ttl';
        $token = $this->createMockToken($jti, new DateTimeImmutable('+2 hours'));
        $customTtl = 1800; // 30 minutes
        $expectedCacheKey = $this->getExpectedCacheKey($jti);

        $this->mockCache->shouldReceive('has')->once()->with($expectedCacheKey)->andReturn(false);
        $this->mockCache->shouldReceive('set')
            ->once()
            ->with($expectedCacheKey, true, $customTtl)
            ->andReturn(true);

        $this->assertTrue($this->blacklist->add($token, $customTtl));
    }

    public function testAddTokenFailsIfNoJti(): void
    {
        $token = $this->createMockToken(null); // No JTI
        $this->mockCache->shouldNotReceive('set'); // 不应该调用 set
        $this->assertFalse($this->blacklist->add($token));
    }

    public function testAddTokenUsesDefaultGracePeriodIfTokenHasNoExp(): void
    {
        $jti = 'test_jti_no_exp';
        $token = $this->createMockToken($jti, null); // No expiration time
        $expectedCacheKey = $this->getExpectedCacheKey($jti);
        // valueToStore will be time() + defaultGracePeriod
        // We can use a more flexible matcher for the value if exact time() is hard to predict
        // Mockery::on(function($value) { return is_int($value) && $value > time(); })

        $this->mockCache->shouldReceive('has')->once()->with($expectedCacheKey)->andReturn(false);
        $this->mockCache->shouldReceive('set')
            ->once()
            ->with($expectedCacheKey, true, $this->defaultGracePeriod)
            ->andReturn(true);

        $this->assertTrue($this->blacklist->add($token));
    }

    public function testHasTokenInBlacklist(): void
    {
        $jti = 'existing_jti';
        $token = $this->createMockToken($jti);
        $expectedCacheKey = $this->getExpectedCacheKey($jti);

        $this->mockCache->shouldReceive('has')->once()->with($expectedCacheKey)->andReturn(true);
        $this->assertTrue($this->blacklist->has($token));

        $this->mockCache->shouldReceive('has')->once()->with($expectedCacheKey)->andReturn(false);
        $this->assertFalse($this->blacklist->has($token));
    }

    public function testHasTokenReturnsFalseIfNoJti(): void
    {
        $token = $this->createMockToken(null);
        $this->mockCache->shouldNotReceive('has');
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

    public function testClearMethodReturnsFalse(): void
    {
        // Blacklist::clear() 现在返回 false，表示操作不受支持
        $this->mockCache->shouldNotReceive('clear');
        $this->assertFalse($this->blacklist->clear());
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

        // 重新创建 Blacklist 实例以使新的 config mock 生效
        $blacklistWithCustomPrefix = new Blacklist($this->mockCacheFactory, $this->mockConfig);

        $jti = 'test_jti_custom_prefix';
        $token = $this->createMockToken($jti, new DateTimeImmutable('+1 hour'));
        $expectedCacheKey = $customPrefix . hash('sha256', $jti);

        $this->mockCache->shouldReceive('has')->once()->with($expectedCacheKey)->andReturn(false);
        $this->mockCache->shouldReceive('set')
            ->once()
            ->with($expectedCacheKey, Mockery::any(), Mockery::any())
            ->andReturn(true);

        $blacklistWithCustomPrefix->add($token);
    }
}