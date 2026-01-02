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

        // 存储标记值（只需知道它在黑名单中即可）
        $val = true;

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
     *
     * 由于 PSR-16 的限制，clear 会清除整个缓存实例而不仅仅是此前缀的条目。
     * 为安全起见，抛出明确异常而非静默失败。
     *
     * @throws JwtException 始终抛出异常，说明该操作不受支持
     */
    public function clear(): bool
    {
        throw new JwtException(
            'Clearing all blacklist entries is not supported. ' .
            'Individual entries will expire based on their TTL.'
        );
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