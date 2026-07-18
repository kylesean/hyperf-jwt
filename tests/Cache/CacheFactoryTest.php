<?php

declare(strict_types=1);

namespace Kylesean\Jwt\Tests\Cache;

use Hyperf\Cache\CacheManager;
use Hyperf\Cache\Driver\DriverInterface;
use Hyperf\Contract\ConfigInterface;
use Kylesean\Jwt\Cache\CacheFactory;
use Kylesean\Jwt\Exception\JwtException;
use Mockery;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;

#[CoversClass(CacheFactory::class)]
class CacheFactoryTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    protected Mockery\MockInterface|ContainerInterface $mockContainer;
    protected Mockery\MockInterface|ConfigInterface $mockConfig;
    protected CacheFactory $cacheFactory;

    protected function setUp(): void
    {
        parent::setUp();
        $this->mockContainer = Mockery::mock(ContainerInterface::class);
        $this->mockConfig = Mockery::mock(ConfigInterface::class);
        $this->cacheFactory = new CacheFactory($this->mockContainer, $this->mockConfig);
    }

    public function testGetCacheDriverWithExplicitDriverName(): void
    {
        $driverName = 'redis';
        $mockCache = Mockery::mock(DriverInterface::class);
        $mockCacheManager = Mockery::mock(CacheManager::class);

        $this->mockContainer->shouldReceive('has')
            ->with(CacheManager::class)
            ->once()
            ->andReturn(true);

        $this->mockContainer->shouldReceive('get')
            ->with(CacheManager::class)
            ->once()
            ->andReturn($mockCacheManager);

        $mockCacheManager->shouldReceive('getDriver')
            ->with($driverName)
            ->once()
            ->andReturn($mockCache);

        $result = $this->cacheFactory->get($driverName);
        $this->assertSame($mockCache, $result);
    }

    public function testGetCacheDriverWithDefaultDriverFromConfig(): void
    {
        $defaultDriverName = 'default';
        $mockCache = Mockery::mock(DriverInterface::class);
        $mockCacheManager = Mockery::mock(CacheManager::class);

        $this->mockConfig->shouldReceive('get')
            ->with('jwt.blacklist_cache_driver', 'default')
            ->once()
            ->andReturn($defaultDriverName);

        $this->mockContainer->shouldReceive('has')
            ->with(CacheManager::class)
            ->once()
            ->andReturn(true);

        $this->mockContainer->shouldReceive('get')
            ->with(CacheManager::class)
            ->once()
            ->andReturn($mockCacheManager);

        $mockCacheManager->shouldReceive('getDriver')
            ->with($defaultDriverName)
            ->once()
            ->andReturn($mockCache);

        $result = $this->cacheFactory->get();
        $this->assertSame($mockCache, $result);
    }

    public function testGetThrowsExceptionWhenCacheManagerNotAvailable(): void
    {
        $this->expectException(JwtException::class);
        $this->expectExceptionMessage('Hyperf CacheManager is not available.');

        $this->mockContainer->shouldReceive('has')
            ->with(CacheManager::class)
            ->once()
            ->andReturn(false);

        $this->cacheFactory->get('redis');
    }

    public function testGetThrowsExceptionWhenGetDriverFails(): void
    {
        $this->expectException(JwtException::class);
        $this->expectExceptionMessage('Failed to get cache driver "invalid_driver"');

        $mockCacheManager = Mockery::mock(CacheManager::class);

        $this->mockContainer->shouldReceive('has')
            ->with(CacheManager::class)
            ->once()
            ->andReturn(true);

        $this->mockContainer->shouldReceive('get')
            ->with(CacheManager::class)
            ->once()
            ->andReturn($mockCacheManager);

        $mockCacheManager->shouldReceive('getDriver')
            ->with('invalid_driver')
            ->once()
            ->andThrow(new \InvalidArgumentException('Driver not found'));

        $this->cacheFactory->get('invalid_driver');
    }
}
