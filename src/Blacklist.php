<?php

declare(strict_types=1);

namespace Kylesean\Jwt;

use Kylesean\Jwt\Cache\CacheFactory;
use Kylesean\Jwt\Contract\BlacklistInterface;
use Kylesean\Jwt\Contract\TokenInterface;
use Kylesean\Jwt\Exception\JwtException;
use Hyperf\Contract\ConfigInterface;
use Psr\SimpleCache\CacheInterface;

class Blacklist implements BlacklistInterface
{
    protected CacheInterface $cache;

    protected string $cachePrefix = 'jwt_blacklist_';

    protected int $gracePeriod;

    public function __construct(CacheFactory $cacheFactory, ConfigInterface $config)
    {
        $this->cache = $cacheFactory->get();
        $this->gracePeriod = (int) $config->get('jwt.blacklist_grace_period', 3600);
        $this->cachePrefix = (string) $config->get('jwt.blacklist_cache_prefix', 'jwt_blacklist_');
    }

    /**
     * {@inheritdoc}
     */
    public function add(TokenInterface $token, ?int $ttl = null): bool
    {
        if (!$jti = $token->getId()) {
            return false;
        }

        // 如果已经存在，说明已经被其他进程拉黑，不重复操作
        if ($this->has($token)) {
            return true;
        }

        $ttl = $ttl ?? $this->gracePeriod;
        return $this->cache->set($this->getCacheKey($jti), true, $ttl);
    }

    /**
     * {@inheritdoc}
     */
    public function has(TokenInterface $token): bool
    {
        if (!$jti = $token->getId()) {
            return false;
        }

        return $this->cache->has($this->getCacheKey($jti));
    }

    /**
     * {@inheritdoc}
     */
    public function remove(TokenInterface $token): bool
    {
        if (!$jti = $token->getId()) {
            return false;
        }

        return $this->cache->delete($this->getCacheKey($jti));
    }

    /**
     * {@inheritdoc}
     *
     * PSR-16 要求 clear() 返回 bool。
     * 由于黑名单基于前缀且通常共享缓存池，全量清理可能导致误删其他业务数据。
     * 返回 false 表示该操作不受当前实现支持。
     */
    public function clear(): bool
    {
        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function setDefaultGracePeriod(int $ttl): self
    {
        $this->gracePeriod = max(0, $ttl);
        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getDefaultGracePeriod(): int
    {
        return $this->gracePeriod;
    }

    /**
     * 生成混淆后的缓存键。
     * 使用 SHA256 哈希以防止特殊字符干扰并增强安全性。
     */
    protected function getCacheKey(string $jti): string
    {
        return $this->cachePrefix . hash('sha256', $jti);
    }
}