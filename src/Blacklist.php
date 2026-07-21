<?php

declare(strict_types=1);

namespace Kylesean\Jwt;

use Hyperf\Contract\ConfigInterface;
use Kylesean\Jwt\Cache\CacheFactory;
use Kylesean\Jwt\Contract\BlacklistInterface;
use Kylesean\Jwt\Contract\TokenInterface;
use Kylesean\Jwt\Exception\JwtException;
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
    public function add(TokenInterface $token, ?int $ttl = null, int $concurrencyGracePeriod = 0): bool
    {
        if (!$jti = $token->getId()) {
            return false;
        }

        // If the token has been blacklisted, return true
        if ($this->has($token)) {
            return true;
        }

        $ttl = $ttl ?? $this->gracePeriod;

        // If concurrencyGracePeriod is set, store the absolute timestamp of invalidation
        $valueToStore = $concurrencyGracePeriod > 0 ? time() + $concurrencyGracePeriod : 0;

        return $this->cache->set($this->getCacheKey($jti), $valueToStore, $ttl);
    }

    /**
     * {@inheritdoc}
     */
    public function has(TokenInterface $token): bool
    {
        if (!$jti = $token->getId()) {
            return false;
        }

        $value = $this->cache->get($this->getCacheKey($jti));
        if ($value === null) {
            return false;
        }

        // If stored value is true (legacy support), 0, or '0', it is immediately invalid
        if ($value === true || $value === 0 || $value === '0') {
            return true;
        }

        // If stored value is a future invalidation timestamp, check if it has passed
        if (is_numeric($value)) {
            return time() > (int) $value;
        }

        return true;
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
     * @throws JwtException Clearing the entire JWT blacklist is unsupported to prevent unintentional cache evictions.
     */
    public function clear(): bool
    {
        throw new JwtException('Clearing the entire JWT blacklist is unsupported to prevent unintentional cache evictions.');
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

    protected function getCacheKey(string $jti): string
    {
        return $this->cachePrefix . hash('sha256', $jti);
    }
}
