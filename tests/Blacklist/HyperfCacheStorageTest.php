<?php

declare(strict_types=1);

namespace FriendsOfHyperf\Jwt\Tests\Blacklist;

use FriendsOfHyperf\Jwt\Blacklist\HyperfCacheStorage;
use FriendsOfHyperf\Jwt\Contract\BlacklistStorageInterface;
use FriendsOfHyperf\Jwt\Tests\TestCase; // 确保这个 TestCase 继承自 Hyperf\Testing\TestCase
use Psr\SimpleCache\CacheInterface;    // 使用 PSR-16 接口
use Hyperf\Config\Config;              // 用于在测试中手动提供配置
use Hyperf\Contract\ConfigInterface;   // DI 中请求的接口

class HyperfCacheStorageTest extends TestCase // TestCase 继承自 Hyperf\Testing\TestCase
{
    private CacheInterface $cache;
    private BlacklistStorageInterface $storage;

    protected function setUp(): void
    {
        parent::setUp(); // 调用 Hyperf\Testing\TestCase 的 setUp

        // 在 Hyperf\Testing\TestCase 环境中，我们期望容器已经为 PSR-16 CacheInterface
        // 绑定了一个适合测试的内存驱动。
        // 这是基于 hyperf/testing 组件会为核心PSR接口提供默认测试实现的前提。

        // 1. 如果测试环境没有自动配置 ConfigInterface, 我们手动提供一个空的或最小的
        if (!$this->container->has(ConfigInterface::class)) {
            $this->container->set(ConfigInterface::class, new Config([]));
        }

        // 2. 从容器获取 Psr\SimpleCache\CacheInterface
        // Hyperf\Testing\TestCase 应该已经为 PSR-16 CacheInterface 准备好了默认的内存实现
        try {
            $this->cache = $this->container->get(CacheInterface::class);
        } catch (\Throwable $e) {
            // 如果容器没有提供 CacheInterface 的默认实现，测试将失败。
            // 这通常意味着 hyperf/testing 环境没有像预期那样完全引导缓存组件，
            // 或者项目中缺少某些配置使得 testing 组件无法自动配置它。
            // 对于一个包的测试，我们应该尽量减少对应用级配置文件的依赖。
            // 如果 Hyperf Testing 不自动提供内存缓存，我们就必须手动模拟或跳过。
            $this->fail(
                "Failed to get Psr\\SimpleCache\\CacheInterface from container: " . $e->getMessage() . "\n" .
                "Please ensure your Hyperf testing environment provides a default PSR-16 cache implementation (e.g., a memory-based one)." . "\n" .
                "This might require having `hyperf/cache` correctly installed and a basic default cache configuration available for the testing bootstrap."
            );
        }

        // 3. 清理缓存并实例化我们的 Storage
        // 确保 $this->cache 是一个有效的实例
        if (!$this->cache instanceof \Psr\SimpleCache\CacheInterface) {
            $this->fail('Resolved cache service does not implement Psr\SimpleCache\CacheInterface.');
        }

        $this->cache->clear(); // PSR-16 clear()
        $this->storage = new HyperfCacheStorage($this->cache);
    }

    protected function tearDown(): void
    {
        if (class_exists(\Mockery::class)) { // 只有 Mockery 存在时才调用
            \Mockery::close();
        }
        parent::tearDown();
    }

    // --- 测试方法保持不变 ---

    public function testAddAndHas(): void
    {
        $jti = 'test_jti_123';
        $ttl = 60; // seconds
        $this->assertFalse($this->storage->has($jti));
        $this->storage->add($jti, $ttl);
        $this->assertTrue($this->storage->has($jti));
    }

    public function testHasReturnsFalseForExpiredEntry(): void
    {
        $jti = 'test_jti_expired';
        $ttlInSeconds = 1; // 1 second
        $this->storage->add($jti, $ttlInSeconds);
        $this->assertTrue($this->storage->has($jti));

        // 等待缓存过期
        // sleep() 在单元测试中通常应避免，因为它会减慢测试速度。
        // 对于内存缓存如 Symfony ArrayAdapter，过期是基于内部时间戳的。
        // 如果是真正的外部缓存（如 Redis），sleep 是有效的。
        // 鉴于 PSR-16 CacheInterface 没有提供模拟时钟的方法，sleep 是目前最直接的方式。
        // 或者，如果知道具体的内存驱动实现，可以尝试用反射或其他技巧修改其内部时间。
        // 但为了简单和可移植性，暂时保留 sleep。
        sleep($ttlInSeconds + 1);

        $this->assertFalse($this->storage->has($jti));
    }

    public function testAddWithZeroOrNegativeTtl(): void
    {
        $jti1 = 'test_jti_zero_ttl';
        $this->storage->add($jti1, 0);
        // PSR-16 set() 的 $ttl:
        // - null: 使用默认 TTL (通常由缓存池配置)
        // - int: TTL 秒数。如果为0或负数，条目必须立即过期（或者说被删除）。
        $this->assertFalse($this->storage->has($jti1), "JTI added with 0 TTL should be immediately expired/deleted.");

        $jti2 = 'test_jti_negative_ttl';
        $this->storage->add($jti2, -10);
        $this->assertFalse($this->storage->has($jti2), "JTI added with negative TTL should be immediately expired/deleted.");
    }

    public function testPrefixIsApplied(): void
    {
        $jti = 'jti_for_prefix_test';
        $ttl = 60;
        $customPrefix = 'my_app_jwt_blacklist:';

        // 使用自定义前缀实例化
        $prefixedStorage = new HyperfCacheStorage($this->cache, $customPrefix);
        $prefixedStorage->add($jti, $ttl);

        // 验证带前缀的键确实存在于 PSR-16 缓存中
        $this->assertTrue($this->cache->has($customPrefix . $jti), "Raw PSR-16 cache should have the prefixed JTI key.");
        $this->assertTrue($prefixedStorage->has($jti), "Storage with custom prefix should find the JTI.");

        // 创建一个使用默认前缀的 storage
        $defaultPrefix = 'jwt_blacklist:'; // HyperfCacheStorage 中的默认值
        $defaultStorage = new HyperfCacheStorage($this->cache); // 使用默认前缀
        $this->assertFalse($defaultStorage->has($jti), "Storage with default prefix should not find the JTI set with a custom prefix.");

        // 清理测试数据
        $this->cache->delete($customPrefix . $jti);
    }
}