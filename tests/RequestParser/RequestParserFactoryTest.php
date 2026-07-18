<?php

declare(strict_types=1);

namespace Kylesean\Jwt\Tests\RequestParser;

use Kylesean\Jwt\Contract\RequestParser\RequestParserInterface;
use Kylesean\Jwt\RequestParser\AuthorizationHeader;
use Kylesean\Jwt\RequestParser\Cookie;
use Kylesean\Jwt\RequestParser\InputSource;
use Kylesean\Jwt\RequestParser\QueryString;
use Kylesean\Jwt\RequestParser\RequestParserFactory;
use Hyperf\Contract\ConfigInterface;
use Mockery;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;
use stdClass;

#[CoversClass(RequestParserFactory::class)]
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

    // Helper method: Create a RequestParserFactory instance
    protected function createFactory(?array $tokenParsersConfigFromTest = null): RequestParserFactory
    {
        // If $tokenParsersConfigFromTest is null, we test Factory using its internal defaults.
        // We simulate ConfigInterface::get('jwt.token_parsers', $defaultValue) behavior:
        // Config key 'jwt.token_parsers' is not found, so it returns the passed $defaultValue.
        // In the Factory constructor, this $defaultValue is $this->defaultParserConfigs.

        // If $tokenParsersConfigFromTest is not null, we test when the user provides specific config.
        // In this case, ConfigInterface::get('jwt.token_parsers', ...) returns $tokenParsersConfigFromTest.

        $this->mockConfig->shouldReceive('get')
            ->with('jwt.token_parsers', Mockery::on(function ($defaultValueArgument) {
                // This Mockery::on ensures the second argument (default value) is passed correctly to get()
                // In our tests, this default parameter is the internal $this->defaultParserConfigs
                return is_array($defaultValueArgument); // Simple check for array
            }))
            ->andReturnUsing(function (string $key, $defaultValuePassedToGet) use ($tokenParsersConfigFromTest) {
                if ($tokenParsersConfigFromTest !== null) {
                    // If test case provides specific config, return it
                    return $tokenParsersConfigFromTest;
                }
                // Otherwise simulate config key not found, returning default passed to get()
                // (In Factory, this default is $this->defaultParserConfigs)
                return $defaultValuePassedToGet;
            })
            ->byDefault(); // byDefault allows subsequent shouldReceive to override in specific tests

        return new RequestParserFactory($this->mockContainer, $this->mockConfig);
    }


    public function testGetParserChainWithDefaultConfiguration(): void
    {
        $factory = $this->createFactory(null); // Use default config

        // Mock container make method behavior
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

        // Mock container make method and verify options passed to it
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
            QueryString::class, // String
            ['class' => AuthorizationHeader::class, 'options' => ['prefix' => 'BearerToken']], // Array with options
            new Cookie('my_app_cookie_name'), // Pre-instantiated object
        ];
        $factory = $this->createFactory($userConfig);

        $this->mockContainer->shouldReceive('make')->with(QueryString::class, [])->andReturn(new QueryString());
        $this->mockContainer->shouldReceive('make')->with(AuthorizationHeader::class, ['prefix' => 'BearerToken'])->andReturn(new AuthorizationHeader('BearerToken'));
        // For pre-instantiated objects, createParser returns directly without calling container->make

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
            'NonExistentParserClass', // Invalid class name
            ['class' => stdClass::class], // Invalid class (interface not implemented)
            QueryString::class, // Valid
            [], // Empty array config
            ['options_only' => ['foo' => 'bar']], // Missing 'class' key
        ];
        $factory = $this->createFactory($userConfig);

        // Expect only QueryString::class to be successfully created
        $this->mockContainer->shouldReceive('make')->with(QueryString::class, [])->andReturn(new QueryString());
        // For invalid config, container->make should not be called

        $chain = $factory->getParserChain();
        $this->assertCount(1, $chain); // Should only have 1 valid parser
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
        $preInstantiatedParser = new Cookie(); // Direct instantiation

        $parser = $factory->createParser($preInstantiatedParser);
        $this->assertSame($preInstantiatedParser, $parser);
        // In this case container->make should not be called
        $this->mockContainer->shouldNotHaveReceived('make');
    }

    public function testCreateParserReturnsNullForInvalidConfig(): void
    {
        $factory = $this->createFactory();
        $this->assertNull($factory->createParser('NonExistentClass'));
        $this->assertNull($factory->createParser(['class' => \stdClass::class])); // stdClass does not implement interface
        $this->assertNull($factory->createParser([])); // Empty array
        $this->assertNull($factory->createParser(['invalid_key' => QueryString::class])); // Invalid format
        $this->expectException(\TypeError::class);
        $this->assertNull($factory->createParser(123)); // Invalid type
    }

    public function testSetParsersConfigClearsCache(): void
    {
        $factory = $this->createFactory([QueryString::class]);
        $this->mockContainer->shouldReceive('make')->with(QueryString::class, [])->andReturn(new QueryString());

        $chain1 = $factory->getParserChain(); // First call, will cache
        $this->assertCount(1, $chain1);

        // Modify config
        $this->mockConfig->shouldReceive('get') // Ensure config mock captures updated calls
            ->with('jwt.token_parsers', Mockery::any())
            ->andReturn([AuthorizationHeader::class]); // New config

        // Mock container make call for new config
        $this->mockContainer->shouldReceive('make')->with(AuthorizationHeader::class, [])->andReturn(new AuthorizationHeader());


        $factory->setParsersConfig([AuthorizationHeader::class]); // Call setParsersConfig

        $chain2 = $factory->getParserChain(); // Second call, should use new config and regenerate
        $this->assertCount(1, $chain2);
        $this->assertInstanceOf(AuthorizationHeader::class, $chain2[0]);
    }
}