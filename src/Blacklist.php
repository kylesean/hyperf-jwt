<?php

declare(strict_types=1);

namespace FriendsOfHyperf\Jwt;

use FriendsOfHyperf\Jwt\Contract\BlacklistInterface;
use FriendsOfHyperf\Jwt\Contract\TokenInterface;
use FriendsOfHyperf\Jwt\Cache\CacheFactory;
use FriendsOfHyperf\Jwt\Exception\JwtException;
use Psr\SimpleCache\CacheInterface;
use Hyperf\Contract\ConfigInterface;

class Blacklist implements BlacklistInterface
{
    protected CacheInterface $cache;

    protected ConfigInterface $config;

    /**
     * 黑名单条目的默认存活时间（秒）。
     * @var int
     */
    protected int $defaultGracePeriod;

    /**
     * 缓存键的前缀。
     * @var string
     */
    protected string $cachePrefix = 'jwt_blacklist_';


    /**
     * 构造函数。
     *
     * @param CacheFactory $cacheFactory 用于获取缓存驱动的工厂
     * @param ConfigInterface $config Hyperf 配置接口
     */
    public function __construct(CacheFactory $cacheFactory, ConfigInterface $config)
    {
        $this->cache = $cacheFactory->get(); // 获取 jwt.blacklist_cache_driver 配置的缓存实例
        $this->config = $config;
        $this->defaultGracePeriod = (int)$this->config->get('jwt.blacklist_grace_period', 3600); // 默认1小时
        $customPrefix = $this->config->get('jwt.blacklist_cache_prefix');
        if (is_string($customPrefix) && $customPrefix !== '') {
            $this->cachePrefix = $customPrefix;
        }
    }

    /**
     * {@inheritdoc}
     */
    public function add(TokenInterface $token, ?int $ttl = null): bool
    {
        $jti = $token->getId();

        if (empty($jti)) {
            // 如果令牌没有 jti，则无法有效地将其加入黑名单，可以选择抛出异常或返回 false
            // throw new JwtException('Cannot add token to blacklist: missing jti (JWT ID) claim.');
            return false; // 或者记录一个警告
        }

        $cacheKey = $this->generateCacheKey($jti);

        // 使用配置的 grace period 或传入的 ttl
        $effectiveTtl = $ttl ?? $this->defaultGracePeriod;
        // 存储的值可以是简单的 true，或者是令牌的过期时间，以便进行更复杂的检查（如果需要）
        // 这里我们存储一个标记值，例如当前时间戳或令牌的过期时间，以备将来扩展。
        // 对于简单的存在性检查，true 也可以。我们存储令牌的过期时间戳。
        $valueToStore = $token->getExpirationTime() ? $token->getExpirationTime()->getTimestamp() : time() + $effectiveTtl;
        return $this->cache->set($cacheKey, $valueToStore, $effectiveTtl);
    }

    /**
     * {@inheritdoc}
     */
    public function has(TokenInterface $token): bool
    {
        $jti = $token->getId();
        if (empty($jti)) {
            // 没有 jti 的令牌无法在黑名单中准确查找
            return false;
        }

        $cacheKey = $this->generateCacheKey($jti);
        return $this->cache->has($cacheKey);
    }

    /**
     * {@inheritdoc}
     */
    public function remove(TokenInterface $token): bool
    {
        $jti = $token->getId();
        if (empty($jti)) {
            return false;
        }

        $cacheKey = $this->generateCacheKey($jti);
        return $this->cache->delete($cacheKey);
    }

    /**
     * {@inheritdoc}
     * 清空黑名单。
     * 警告：PSR-16 (SimpleCache) 的 clear() 方法通常会清空整个缓存实例，
     * 而不仅仅是此前缀的条目。此操作可能影响共享同一缓存实例的其他数据。
     * 如果需要更精细的控制，应考虑使用支持标签或前缀删除的缓存驱动，并调整此实现。
     */
    public function clear(): bool
    {
        // 由于 PSR-16 clear() 的行为，我们不能安全地只清除带此前缀的条目。
        // 一种选择是抛出异常，或记录严重警告。
        // 另一种选择是，如果应用保证此缓存实例专用于黑名单，则可以调用 clear()。
        // 目前，我们选择不实现一个可能导致数据丢失的 clear，或者让用户自己承担风险。
        // 更好的做法是如果确实需要此功能，应使用支持按前缀或标签删除的缓存。
        // 为了符合接口，我们返回 false 或抛出异常，表示操作未按预期完成（安全地）。
        // 或者，如果配置文件中有一个明确的选项允许这种“危险”的清除，可以根据该选项操作。
        // logger()->warning('Blacklist clear() called, which may clear the entire cache instance. This operation is not recommended for shared caches.');
        // return $this->cache->clear(); // 直接调用，风险自负

        // 暂时返回 false 并记录，表示此方法没有安全实现以避免清除整个缓存
        // $logger = $this->config->get(StdoutLoggerInterface::class);
        // $logger->warning('Blacklist clear() method was called, but it is not implemented to avoid clearing the entire cache instance due to PSR-16 limitations. Returning false.');
        // 实际生产中，应通过日志组件记录。
        // 为了演示，这里我们返回 false，表明该操作未安全执行。
        // 如果你的缓存驱动有特殊方法可以按前缀删除，可以在这里实现。
        // 对于通用的 PSR-16，没有安全的方式只清除特定前缀的键。
        // throw new \LogicException('Clearing the blacklist by prefix is not safely supported by PSR-16. Implement driver-specific logic or accept clearing the entire cache store.');
        return false; // 表示操作未按预期安全执行
    }


    /**
     * {@inheritdoc}
     */
    public function setDefaultGracePeriod(int $ttl): self
    {
        $this->defaultGracePeriod = $ttl > 0 ? $ttl : 0;
        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getDefaultGracePeriod(): int
    {
        return $this->defaultGracePeriod;
    }

    /**
     * 根据令牌的唯一标识符 (jti) 生成缓存键。
     *
     * @param string $jti 令牌的 jti 声明
     * @return string
     */
    protected function generateCacheKey(string $jti): string
    {
        return $this->cachePrefix . $jti;
    }
}