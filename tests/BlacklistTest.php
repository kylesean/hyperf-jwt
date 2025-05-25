<?php

declare(strict_types=1);

namespace FriendsOfHyperf\Jwt\Tests;

use DateTimeImmutable;
use FriendsOfHyperf\Jwt\Blacklist;
use FriendsOfHyperf\Jwt\Cache\CacheFactory; // 我们会 mock 这个工厂
use FriendsOfHyperf\Jwt\Contract\TokenInterface;
use Hyperf\Contract\ConfigInterface;
use Hyperf\Logger\LoggerFactory; // 用于构造函数，但可以 mock
use Mockery;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\TestCase;
use Psr\SimpleCache\CacheInterface; // CacheInterface 是 Blacklist 依赖的核心
use Psr\Log\LoggerInterface; // Blacklist 内部使用

/**
 * @internal
 * @coversNothing
 */
class BlacklistTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    protected Blacklist $blacklist;
    protected Mockery\MockInterface|CacheInterface $mockCache;
    protected Mockery\MockInterface|ConfigInterface $mockConfig;
    protected Mockery\MockInterface|CacheFactory $mockCacheFactory;
    protected Mockery\MockInterface|LoggerFactory $mockLoggerFactory;
    protected Mockery\MockInterface|LoggerInterface $mockLogger; // Blacklist 内部使用的 logger

    protected string $defaultCachePrefix = 'jwt_blacklist_';
    protected int $defaultGracePeriod = 3600; // 1 hour in seconds

    protected function setUp(): void
    {
        parent::setUp();

        $this->mockCache = Mockery::mock(CacheInterface::class);
        $this->mockConfig = Mockery::mock(ConfigInterface::class);
        $this->mockCacheFactory = Mockery::mock(CacheFactory::class);
        $this->mockLoggerFactory = Mockery::mock(LoggerFactory::class);
        $this->mockLogger = Mockery::mock(LoggerInterface::class)->shouldIgnoreMissing(); // 忽略日志调用细节

        // 配置 CacheFactory mock 返回我们的 mockCache
        $this->mockCacheFactory->shouldReceive('get')->andReturn($this->mockCache)->byDefault();

        // 配置 LoggerFactory mock 返回我们的 mockLogger
        $this->mockLoggerFactory->shouldReceive('get')->with('jwt_blacklist')->andReturn($this->mockLogger)->byDefault();

        // 配置 ConfigInterface mock 的默认返回值
        $this->mockConfig->shouldReceive('get')
            ->with('jwt.blacklist_grace_period', Mockery::any()) // 允许默认值
            ->andReturn($this->defaultGracePeriod)
            ->byDefault();
        $this->mockConfig->shouldReceive('get')
            ->with('jwt.blacklist_cache_prefix')
            ->andReturn(null) // 默认不使用自定义前缀，让 Blacklist 用自己的默认值
            ->byDefault();

        $this->blacklist = new Blacklist($this->mockCacheFactory, $this->mockConfig, $this->mockLoggerFactory);
    }

    protected function createMockToken(?string $jti, ?DateTimeImmutable $exp = null): TokenInterface
    {
        $token = Mockery::mock(TokenInterface::class);
        $token->shouldReceive('getId')->andReturn($jti)->byDefault();
        $token->shouldReceive('getExpirationTime')->andReturn($exp)->byDefault();
        $token->shouldReceive('getAllClaims')->andReturn(['jti' => $jti, 'exp' => $exp ? $exp->getTimestamp() : null])->byDefault();
        return $token;
    }

    public function testAddTokenToBlacklist(): void
    {
        $jti = 'test_jti_123';
        $exp = new DateTimeImmutable('+1 hour');
        $token = $this->createMockToken($jti, $exp);
        $expectedCacheKey = $this->defaultCachePrefix . $jti;
        $expectedValue = $exp->getTimestamp();

        $this->mockCache->shouldReceive('set')
            ->once()
            ->with($expectedCacheKey, $expectedValue, $this->defaultGracePeriod)
            ->andReturn(true);

        $this->assertTrue($this->blacklist->add($token));
    }

    public function testAddTokenWithCustomTtl(): void
    {
        $jti = 'test_jti_custom_ttl';
        $token = $this->createMockToken($jti, new DateTimeImmutable('+2 hours'));
        $customTtl = 1800; // 30 minutes
        $expectedCacheKey = $this->defaultCachePrefix . $jti;

        $this->mockCache->shouldReceive('set')
            ->once()
            ->with($expectedCacheKey, Mockery::type('int'), $customTtl) // 值可以是任何 int
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
        $expectedCacheKey = $this->defaultCachePrefix . $jti;
        // valueToStore will be time() + defaultGracePeriod
        // We can use a more flexible matcher for the value if exact time() is hard to predict
        // Mockery::on(function($value) { return is_int($value) && $value > time(); })

        $this->mockCache->shouldReceive('set')
            ->once()
            ->with($expectedCacheKey, Mockery::type('int'), $this->defaultGracePeriod)
            ->andReturn(true);

        $this->assertTrue($this->blacklist->add($token));
    }

    public function testHasTokenInBlacklist(): void
    {
        $jti = 'existing_jti';
        $token = $this->createMockToken($jti);
        $expectedCacheKey = $this->defaultCachePrefix . $jti;

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
        $expectedCacheKey = $this->defaultCachePrefix . $jti;

        $this->mockCache->shouldReceive('delete')->once()->with($expectedCacheKey)->andReturn(true);
        $this->assertTrue($this->blacklist->remove($token));
    }

    public function testRemoveTokenFailsIfNoJti(): void
    {
        $token = $this->createMockToken(null);
        $this->mockCache->shouldNotReceive('delete');
        $this->assertFalse($this->blacklist->remove($token));
    }

    public function testClearMethodReturnsFalseAsNotSafelyImplemented(): void
    {
        // 当前 Blacklist::clear() 设计为返回 false，因为 PSR-16 不支持按前缀清除
        // 我们不期望 $this->mockCache->clear() 被调用，除非特定配置允许
        $this->mockCache->shouldNotReceive('clear');
        $this->assertFalse($this->blacklist->clear());
    }

    public function testSetAndGetDefaultGracePeriod(): void
    {
        $this->blacklist->setDefaultGracePeriod(7200);
        $this->assertEquals(7200, $this->blacklist->getDefaultGracePeriod());

        $this->blacklist->setDefaultGracePeriod(0); // 0 is allowed, meaning effectively no grace or immediate expiry on add
        $this->assertEquals(0, $this->blacklist->getDefaultGracePeriod());

        // Test negative value defaults to 0 (or positive, depending on implementation, current is > 0 ? $ttl : 0)
        $this->blacklist->setDefaultGracePeriod(-100);
        $this->assertEquals(0, $this->blacklist->getDefaultGracePeriod());
    }

    public function testUsesCustomCachePrefixFromConfig(): void
    {
        $customPrefix = 'my_app_jwt_bl_';
        $this->mockConfig->shouldReceive('get') // 覆盖 setUp 中的默认
        ->with('jwt.blacklist_cache_prefix')
            ->andReturn($customPrefix);

        // 重新创建 Blacklist 实例以使新的 config mock 生效
        $blacklistWithCustomPrefix = new Blacklist($this->mockCacheFactory, $this->mockConfig, $this->mockLoggerFactory);

        $jti = 'test_jti_custom_prefix';
        $token = $this->createMockToken($jti, new DateTimeImmutable('+1 hour'));
        $expectedCacheKey = $customPrefix . $jti;

        $this->mockCache->shouldReceive('set')
            ->once()
            ->with($expectedCacheKey, Mockery::any(), Mockery::any())
            ->andReturn(true);

        $blacklistWithCustomPrefix->add($token);
    }
}