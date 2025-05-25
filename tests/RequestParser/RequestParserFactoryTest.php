<?php

declare(strict_types=1);

namespace FriendsOfHyperf\Jwt\Tests\RequestParser;

use FriendsOfHyperf\Jwt\Contract\RequestParser\RequestParserInterface;
use FriendsOfHyperf\Jwt\RequestParser\AuthorizationHeader;
use FriendsOfHyperf\Jwt\RequestParser\Cookie;
use FriendsOfHyperf\Jwt\RequestParser\InputSource;
use FriendsOfHyperf\Jwt\RequestParser\QueryString;
use FriendsOfHyperf\Jwt\RequestParser\RequestParserFactory;
use Hyperf\Contract\ConfigInterface;
use Mockery;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface; // DI 容器接口

/**
 * @internal
 * @coversNothing
 */
class RequestParserFactoryTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    protected Mockery\MockInterface|ContainerInterface $mockContainer;
    protected Mockery\MockInterface|ConfigInterface $mockConfig;

    protected function setUp(): void
    {
        parent::setUp();
        $this->mockContainer = Mockery::mock(ContainerInterface::class);
        $this->mockConfig = Mockery::mock(ConfigInterface::class);
    }

    // 辅助方法：创建一个 RequestParserFactory 实例
    protected function createFactory(array $tokenParsersConfigFromTest = null): RequestParserFactory
    {
        // 如果 $tokenParsersConfigFromTest 为 null，表示我们想测试 Factory 使用其内部默认值的情况。
        // 此时，我们模拟 ConfigInterface::get('jwt.token_parsers', $defaultValue) 的行为是：
        // 配置项 'jwt.token_parsers' 未找到，因此它应该返回传递给它的 $defaultValue。
        // 而在 Factory 的构造函数中，这个 $defaultValue 就是 $this->defaultParserConfigs。

        // 如果 $tokenParsersConfigFromTest 不为 null，表示我们想测试用户提供了具体配置的情况。
        // 此时，ConfigInterface::get('jwt.token_parsers', ...) 应该返回这个 $tokenParsersConfigFromTest。

        $this->mockConfig->shouldReceive('get')
            ->with('jwt.token_parsers', Mockery::on(function ($defaultValueArgument) {
                // 这个 Mockery::on 用于确保第二个参数 (默认值) 被正确传递给了 get 方法
                // 并且在我们的测试中，这个默认值参数就是 Factory 内部的 $this->defaultParserConfigs
                return is_array($defaultValueArgument); // 简单检查它是个数组
            }))
            ->andReturnUsing(function (string $key, $defaultValuePassedToGet) use ($tokenParsersConfigFromTest) {
                if ($tokenParsersConfigFromTest !== null) {
                    // 如果测试用例提供了具体的配置，则返回它
                    return $tokenParsersConfigFromTest;
                }
                // 否则，模拟配置项未找到，返回传递给 get() 的默认值
                // （在 Factory 中，这个默认值是 $this->defaultParserConfigs）
                return $defaultValuePassedToGet;
            })
            ->byDefault(); // byDefault 允许后续的 shouldReceive 在特定测试中覆盖

        return new RequestParserFactory($this->mockContainer, $this->mockConfig);
    }


    public function testGetParserChainWithDefaultConfiguration(): void
    {
        $factory = $this->createFactory(null); // 使用默认配置

        // 模拟容器的 make 方法行为
        $this->mockContainer->shouldReceive('make')->with(AuthorizationHeader::class, [])->andReturn(new AuthorizationHeader());
        $this->mockContainer->shouldReceive('make')->with(QueryString::class, [])->andReturn(new QueryString());
        $this->mockContainer->shouldReceive('make')->with(InputSource::class, [])->andReturn(new InputSource());
        $this->mockContainer->shouldReceive('make')->with(Cookie::class, [])->andReturn(new Cookie());

        $chain = $factory->getParserChain();

        $this->assertCount(4, $chain);
        $this->assertInstanceOf(AuthorizationHeader::class, $chain[0]);
        $this->assertInstanceOf(QueryString::class, $chain[1]);
        $this->assertInstanceOf(InputSource::class, $chain[2]);
        $this->assertInstanceOf(Cookie::class, $chain[3]);
    }

    public function testGetParserChainWithUserConfigurationStrings(): void
    {
        $userConfig = [
            QueryString::class,
            AuthorizationHeader::class,
        ];
        $factory = $this->createFactory($userConfig);

        $this->mockContainer->shouldReceive('make')->with(QueryString::class, [])->ordered()->andReturn(new QueryString());
        $this->mockContainer->shouldReceive('make')->with(AuthorizationHeader::class, [])->ordered()->andReturn(new AuthorizationHeader());

        $chain = $factory->getParserChain();

        $this->assertCount(2, $chain);
        $this->assertInstanceOf(QueryString::class, $chain[0]);
        $this->assertInstanceOf(AuthorizationHeader::class, $chain[1]);
    }

    public function testGetParserChainWithUserConfigurationArraysWithOptions(): void
    {
        $userConfig = [
            ['class' => QueryString::class, 'options' => ['paramName' => 'custom_token']],
            [AuthorizationHeader::class, ['prefix' => 'JWT', 'headerName' => 'X-Token-Auth']],
        ];
        $factory = $this->createFactory($userConfig);

        // 模拟容器的 make 方法，并验证传递给它的选项
        $this->mockContainer->shouldReceive('make')
            ->with(QueryString::class, ['paramName' => 'custom_token'])
            ->ordered()
            ->andReturn(new QueryString('custom_token'));

        $this->mockContainer->shouldReceive('make')
            ->with(AuthorizationHeader::class, ['prefix' => 'JWT', 'headerName' => 'X-Token-Auth'])
            ->ordered()
            ->andReturn(new AuthorizationHeader('JWT', 'X-Token-Auth'));

        $chain = $factory->getParserChain();

        $this->assertCount(2, $chain);
        $this->assertInstanceOf(QueryString::class, $chain[0]);
        $this->assertEquals('custom_token', $chain[0]->getParamName());
        $this->assertInstanceOf(AuthorizationHeader::class, $chain[1]);
        $this->assertEquals('JWT', $chain[1]->getPrefix());
        $this->assertEquals('X-Token-Auth', $chain[1]->getHeaderName());
    }

    public function testGetParserChainWithMixedConfiguration(): void
    {
        $userConfig = [
            QueryString::class, // 字符串
            ['class' => AuthorizationHeader::class, 'options' => ['prefix' => 'BearerToken']], // 数组带选项
            new Cookie('my_app_cookie_name'), // 预实例化对象
        ];
        $factory = $this->createFactory($userConfig);

        $this->mockContainer->shouldReceive('make')->with(QueryString::class, [])->andReturn(new QueryString());
        $this->mockContainer->shouldReceive('make')->with(AuthorizationHeader::class, ['prefix' => 'BearerToken'])->andReturn(new AuthorizationHeader('BearerToken'));
        // 对于预实例化对象，createParser 会直接返回，不调用 container->make

        $chain = $factory->getParserChain();

        $this->assertCount(3, $chain);
        $this->assertInstanceOf(QueryString::class, $chain[0]);
        $this->assertInstanceOf(AuthorizationHeader::class, $chain[1]);
        $this->assertEquals('BearerToken', $chain[1]->getPrefix());
        $this->assertInstanceOf(Cookie::class, $chain[2]);
        $this->assertEquals('my_app_cookie_name', $chain[2]->getCookieName());
    }

    public function testGetParserChainSkipsInvalidConfigurationItems(): void
    {
        $userConfig = [
            'NonExistentParserClass', // 无效类名
            ['class' => stdClass::class], // 无效类（未实现接口）
            QueryString::class, // 有效
            [], // 空数组配置
            ['options_only' => ['foo' => 'bar']], // 无 class 键
        ];
        $factory = $this->createFactory($userConfig);

        // 只期望 QueryString::class 被成功创建
        $this->mockContainer->shouldReceive('make')->with(QueryString::class, [])->andReturn(new QueryString());
        // 对于无效配置，不应该调用 container->make

        $chain = $factory->getParserChain();
        $this->assertCount(1, $chain); // 只应该有一个有效的解析器
        $this->assertInstanceOf(QueryString::class, $chain[0]);
    }

    public function testCreateParserWithStringClass(): void
    {
        $factory = $this->createFactory();
        $parserMock = Mockery::mock(RequestParserInterface::class);
        $this->mockContainer->shouldReceive('make')->with(QueryString::class, [])->andReturn($parserMock);

        $parser = $factory->createParser(QueryString::class);
        $this->assertSame($parserMock, $parser);
    }

    public function testCreateParserWithArrayConfigTupleStyle(): void
    {
        $factory = $this->createFactory();
        $parserMock = Mockery::mock(RequestParserInterface::class);
        $options = ['paramName' => 'jwt'];
        $this->mockContainer->shouldReceive('make')->with(QueryString::class, $options)->andReturn($parserMock);

        $parser = $factory->createParser([QueryString::class, $options]);
        $this->assertSame($parserMock, $parser);
    }

    public function testCreateParserWithArrayConfigMapStyle(): void
    {
        $factory = $this->createFactory();
        $parserMock = Mockery::mock(RequestParserInterface::class);
        $options = ['prefix' => 'APIKey'];
        $this->mockContainer->shouldReceive('make')->with(AuthorizationHeader::class, $options)->andReturn($parserMock);

        $parser = $factory->createParser(['class' => AuthorizationHeader::class, 'options' => $options]);
        $this->assertSame($parserMock, $parser);
    }

    public function testCreateParserWithPreInstantiatedObject(): void
    {
        $factory = $this->createFactory();
        $preInstantiatedParser = new Cookie(); // 直接实例化

        $parser = $factory->createParser($preInstantiatedParser);
        $this->assertSame($preInstantiatedParser, $parser);
        // 这种情况下不应调用 container->make
        $this->mockContainer->shouldNotHaveReceived('make');
    }

    public function testCreateParserReturnsNullForInvalidConfig(): void
    {
        $factory = $this->createFactory();
        $this->assertNull($factory->createParser('NonExistentClass'));
        $this->assertNull($factory->createParser(['class' => \stdClass::class])); // stdClass不实现接口
        $this->assertNull($factory->createParser([])); // 空数组
        $this->assertNull($factory->createParser(['invalid_key' => QueryString::class])); // 错误格式
        $this->expectException(\TypeError::class);
        $this->assertNull($factory->createParser(123)); // 无效类型
    }

    public function testSetParsersConfigClearsCache(): void
    {
        $factory = $this->createFactory([QueryString::class]);
        $this->mockContainer->shouldReceive('make')->with(QueryString::class, [])->andReturn(new QueryString());

        $chain1 = $factory->getParserChain(); // 第一次调用，会缓存
        $this->assertCount(1, $chain1);

        // 修改配置
        $this->mockConfig->shouldReceive('get') // 确保 config mock 被更新的调用捕获
        ->with('jwt.token_parsers', Mockery::any())
            ->andReturn([AuthorizationHeader::class]); // 新的配置

        // 模拟容器对新配置的 make 调用
        $this->mockContainer->shouldReceive('make')->with(AuthorizationHeader::class, [])->andReturn(new AuthorizationHeader());


        $factory->setParsersConfig([AuthorizationHeader::class]); // 调用 setParsersConfig

        $chain2 = $factory->getParserChain(); // 第二次调用，应该使用新配置并重新生成
        $this->assertCount(1, $chain2);
        $this->assertInstanceOf(AuthorizationHeader::class, $chain2[0]);
    }
}