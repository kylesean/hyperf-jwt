<?php

declare(strict_types=1);

namespace FriendsOfHyperf\Jwt\Cache;

use Hyperf\Contract\ConfigInterface;
use Psr\Container\ContainerInterface;
use Psr\SimpleCache\CacheInterface;
use Hyperf\Cache\CacheManager;

// Hyperf 核心的缓存管理器
use FriendsOfHyperf\Jwt\Exception\JwtException;

// 引入我们定义的异常基类



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
     * 获取配置的 PSR-16 缓存驱动实例。
     *
     * @param string|null $cacheDriverName 缓存驱动的名称。如果为 null，则从 jwt.php 配置中读取。
     * @return CacheInterface
     * @throws JwtException 如果无法获取 CacheManager 或指定的缓存驱动不存在。
     */
    public function get(?string $cacheDriverName = null): CacheInterface
    {
        $driverName = $cacheDriverName ?? $this->config->get('jwt.blacklist_cache_driver', 'default');

        if (!$this->container->has(CacheManager::class)) {
            throw new JwtException('Hyperf CacheManager is not available. Please ensure hyperf/cache component is installed and configured.');
        }
        $cacheManager = $this->container->get(CacheManager::class);

        try {
            // CacheManager::getDriver() 会返回一个实现了 CacheInterface (PSR-16) 的实例
            return $cacheManager->getDriver($driverName);
        } catch (\Throwable $e) {
            // 捕获底层的异常，例如驱动配置错误
            throw new JwtException(sprintf('Failed to get cache driver "%s": %s', $driverName, $e->getMessage()), (int)$e->getCode(), $e);
        }
    }
}