<?php

declare(strict_types=1);

namespace Kylesean\Jwt\Tests\Support;

use Kylesean\Jwt\Cache\CacheFactory;
use Psr\SimpleCache\CacheInterface;

/**
 * CacheFactory stub that always returns the given in-memory cache driver.
 */
class InMemoryCacheFactory extends CacheFactory
{
    public function __construct(private CacheInterface $cache)
    {
    }

    public function get(?string $cacheDriverName = null): CacheInterface
    {
        return $this->cache;
    }
}
