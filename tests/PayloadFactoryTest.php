<?php

declare(strict_types=1);

namespace FriendsOfHyperf\Jwt\Tests;

use DateTimeImmutable;
use FriendsOfHyperf\Jwt\PayloadFactory;
use Hyperf\Contract\ConfigInterface;
use Mockery;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 * @coversNothing
 */
class PayloadFactoryTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    protected Mockery\MockInterface|ConfigInterface $mockConfig;

    protected function setUp(): void
    {
        parent::setUp();
        $this->mockConfig = Mockery::mock(ConfigInterface::class);
    }

    // 辅助方法，用于创建 PayloadFactory 实例并预设 Config mock
    private function createPayloadFactory(array $configGetReturns = []): PayloadFactory
    {
        // 设置 ConfigInterface::get 的默认返回行为
        // 如果 $configGetReturns 中没有指定某个键，则让它返回第二个参数（默认值）
        $this->mockConfig->shouldReceive('get')
            ->with(Mockery::any(), Mockery::any()) // 匹配任何键和任何默认值
            ->andReturnUsing(function ($key, $default) use ($configGetReturns) {
                return $configGetReturns[$key] ?? $default; // 如果在测试中指定了返回值，则用它
            })
            ->byDefault(); // 允许在具体测试中覆盖

        return new PayloadFactory($this->mockConfig);
    }

    public function testConstructorInitializesPropertiesFromConfigWithDefaults(): void
    {
        // 测试当配置中没有jwt.* 相关项时，是否使用了硬编码的默认值
        // createPayloadFactory([]) 会使得所有 config->get 调用都返回其第二个参数(默认值)
        $factory = $this->createPayloadFactory([
            // 模拟 ConfigInterface::get('jwt.ttl', 60) 返回 60 (第二个参数)
            // 模拟 ConfigInterface::get('jwt.nbf_offset_seconds', 0) 返回 0 (第二个参数)
            // ...等等
        ]);

        $this->assertEquals(60, $factory->getTtl());
        $this->assertEquals(0, $factory->getNbfOffsetSeconds());
        $this->assertEquals('Hyperf App', $factory->getIssuer()); // 这是 PayloadFactory 构造函数中的默认值
        $this->assertEquals('Hyperf App', $factory->getAudience()); // 同上
    }

    public function testConstructorInitializesPropertiesFromConfigWithProvidedValues(): void
    {
        $factory = $this->createPayloadFactory([
            'jwt.ttl' => 120,
            'jwt.nbf_offset_seconds' => 10,
            'jwt.issuer' => 'my-custom-issuer',
            'jwt.audience' => ['aud1', 'aud2'],
        ]);

        $this->assertEquals(120, $factory->getTtl());
        $this->assertEquals(10, $factory->getNbfOffsetSeconds());
        $this->assertEquals('my-custom-issuer', $factory->getIssuer());
        $this->assertEquals(['aud1', 'aud2'], $factory->getAudience());
    }

    public function testSetAndGetTtl(): void
    {
        $factory = $this->createPayloadFactory(); // 使用默认配置构造
        $factory->setTtl(90);
        $this->assertEquals(90, $factory->getTtl());

        $factory->setTtl(0); // 测试边界，应至少为1
        $this->assertEquals(1, $factory->getTtl());

        $factory->setTtl(-10); // 测试负数，应至少为1
        $this->assertEquals(1, $factory->getTtl());
    }

    public function testSetAndGetNbfOffsetSeconds(): void
    {
        $factory = $this->createPayloadFactory();
        $factory->setNbfOffsetSeconds(30);
        $this->assertEquals(30, $factory->getNbfOffsetSeconds());

        $factory->setNbfOffsetSeconds(-5); // 允许负数，虽然实际意义不大
        $this->assertEquals(-5, $factory->getNbfOffsetSeconds());
    }

    public function testSetAndGetIssuer(): void
    {
        $factory = $this->createPayloadFactory();
        $factory->setIssuer('new-issuer');
        $this->assertEquals('new-issuer', $factory->getIssuer());
    }

    public function testSetAndGetAudience(): void
    {
        $factory = $this->createPayloadFactory();
        $factory->setAudience('single-aud');
        $this->assertEquals('single-aud', $factory->getAudience());

        $factory->setAudience(['aud-array1', 'aud-array2']);
        $this->assertEquals(['aud-array1', 'aud-array2'], $factory->getAudience());
    }

    public function testGetCurrentTime(): void
    {
        $factory = $this->createPayloadFactory();
        $this->assertInstanceOf(DateTimeImmutable::class, $factory->getCurrentTime());
        // 可以断言时间大致准确，但会有几毫秒误差
        $this->assertEqualsWithDelta(time(), $factory->getCurrentTime()->getTimestamp(), 1.0);
    }

    public function testGenerateJti(): void
    {
        $factory = $this->createPayloadFactory();
        $jti1 = $factory->generateJti();
        $jti2 = $factory->generateJti();

        $this->assertIsString($jti1);
        $this->assertNotEmpty($jti1);
        $this->assertEquals(32, strlen($jti1)); // bin2hex(random_bytes(16)) 结果是32位十六进制字符
        $this->assertNotEquals($jti1, $jti2);
    }

    public function testGetClaimsToRefreshDefault(): void
    {
        // 测试当配置中没有 'jwt.claims_to_refresh' 时，返回默认值
        $factory = $this->createPayloadFactory([
            'jwt.claims_to_refresh' => null, // 模拟配置中没有此项或为null
        ]);
        $this->assertEquals(['iat', 'exp', 'nbf', 'jti'], $factory->getClaimsToRefresh());
    }

    public function testGetClaimsToRefreshWithUserConfig(): void
    {
        $factory = $this->createPayloadFactory([
            'jwt.claims_to_refresh' => ['custom_claim1', 'iat'], // 用户配置，iat是重复的
        ]);
        $expected = ['iat', 'exp', 'nbf', 'jti', 'custom_claim1'];
        $actual = $factory->getClaimsToRefresh();
        // 由于 array_unique 和 array_merge 的顺序问题，我们比较元素是否存在即可
        sort($expected);
        sort($actual);
        $this->assertEquals($expected, $actual);
    }

    public function testGetClaimsToRefreshWithEmptyUserConfig(): void
    {
        $factory = $this->createPayloadFactory([
            'jwt.claims_to_refresh' => [], // 用户配置为空数组
        ]);
        // 即使配置为空，默认的 'iat', 'exp', 'nbf', 'jti' 应该还在
        $this->assertEquals(['iat', 'exp', 'nbf', 'jti'], $factory->getClaimsToRefresh());
    }
}