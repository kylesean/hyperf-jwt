<?php

declare(strict_types=1);

namespace FriendsOfHyperf\Jwt\Blacklist;

use FriendsOfHyperf\Jwt\Contract\BlacklistStorageInterface;
use Hyperf\Contract\CacheInterface;

class HyperfCacheStorage implements BlacklistStorageInterface
{
    protected CacheInterface $cache;

    /**
     * 黑名单项在缓存中的键前缀.
     */
    protected string $prefix = 'jwt_blacklist:'; // 默认前缀

    /**
     * @param CacheInterface $cache Hyperf 缓存实例
     * @param string|null $prefix 可选的自定义键前缀
     */
    public function __construct(CacheInterface $cache, ?string $prefix = null)
    {
        $this->cache = $cache;
        if ($prefix !== null) {
            $this->prefix = $prefix;
        }
    }

    /**
     * @param string $jti
     * @param int $ttl
     * @return void
     */
    public function add(string $jti, int $ttl): void
    {
        $key = $this->getCacheKey($jti);
        if ($ttl > 0) {
            $this->cache->set($key, true, $ttl);
        } else {
            // 如果 ttl <= 0，根据 PSR-16，条目必须被删除或不得存储
            // 调用 delete 以确保它不存在，即使 set(key, val, 0) 应该也有同样效果
            $this->cache->delete($key);
        }
    }

    public function has(string $jti): bool
    {
        $key = $this->getCacheKey($jti);
        // CacheInterface::has() 会检查键是否存在且未过期
        return $this->cache->has($key);
    }

    /**
     * 获取 JTI 在缓存中实际的键名 (包含前缀).
     */
    protected function getCacheKey(string $jti): string
    {
        return $this->prefix . $jti;
    }
}