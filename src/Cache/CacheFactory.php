<?php

declare(strict_types=1);

namespace Kylesean\Jwt\Cache;

use Hyperf\Cache\CacheManager;
use Hyperf\Contract\ConfigInterface;
use Kylesean\Jwt\Exception\JwtException;
use Psr\Container\ContainerInterface;
use Psr\SimpleCache\CacheInterface;

class CacheFactory
{
    protected ContainerInterface $container;
    protected ConfigInterface $config;

    public function __construct(ContainerInterface $container, ConfigInterface $config)
    {
        $this->container = $container;
        $this->config = $config;
    }

    /**
     * Get cache driver instance.
     *
     * @param string|null $cacheDriverName cache driver name, if null, read from jwt.php config
     * @return CacheInterface
     * @throws JwtException if CacheManager is not available or cache driver does not exist
     */
    public function get(?string $cacheDriverName = null): CacheInterface
    {
        $driverName = $cacheDriverName ?? $this->config->get('jwt.blacklist_cache_driver', 'default');

        if (!$this->container->has(CacheManager::class)) {
            throw new JwtException('Hyperf CacheManager is not available. Please ensure hyperf/cache component is installed and configured.');
        }
        $cacheManager = $this->container->get(CacheManager::class);

        try {
            // CacheManager::getDriver() returns an instance that implements CacheInterface (PSR-16)
            return $cacheManager->getDriver($driverName);
        } catch (\Throwable $e) {
            throw new JwtException(sprintf('Failed to get cache driver "%s": %s', $driverName, $e->getMessage()), (int)$e->getCode(), $e);
        }
    }
}
