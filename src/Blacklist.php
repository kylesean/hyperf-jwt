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

        $ttl = $ttl ?? $this->gracePeriod;

        // 存储令牌的过期时间作为标记值
        $exp = $token->getExpirationTime();
        $val = $exp ? $exp->getTimestamp() : time() + $ttl;

        return $this->cache->set($this->getCacheKey($jti), $val, $ttl);
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
     * 由于 PSR-16 的限制，clear 会清除整个缓存实例而不仅仅是此前缀的条目。
     * 为安全起见，默认返回 false。
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
     * 生成混淆后的缓存键
     */
    protected function getCacheKey(string $jti): string
    {
        return $this->cachePrefix . $jti;
    }
}