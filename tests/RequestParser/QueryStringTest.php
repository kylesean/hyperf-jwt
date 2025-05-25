<?php

declare(strict_types=1);

namespace FriendsOfHyperf\Jwt\Tests\RequestParser;

use FriendsOfHyperf\Jwt\RequestParser\QueryString;
use Mockery;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

/**
 * @internal
 * @coversNothing
 */
class QueryStringTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    protected function createRequestWithQueryParams(array $params): ServerRequestInterface
    {
        $request = Mockery::mock(ServerRequestInterface::class);
        $request->shouldReceive('getQueryParams')->andReturn($params)->byDefault();
        return $request;
    }

    public function testParseWithValidTokenInQuery(): void
    {
        $parser = new QueryString(); // 默认参数名 "token"
        $request = $this->createRequestWithQueryParams(['token' => 'my_jwt_from_query']);
        $this->assertEquals('my_jwt_from_query', $parser->parse($request));
    }

    public function testParseWithValidTokenAndCustomParamName(): void
    {
        $parser = new QueryString('jwt_param');
        $request = $this->createRequestWithQueryParams(['jwt_param' => 'my_other_token']);
        $this->assertEquals('my_other_token', $parser->parse($request));
    }

    public function testParseMissingTokenParam(): void
    {
        $parser = new QueryString();
        $request = $this->createRequestWithQueryParams(['another_param' => 'some_value']);
        $this->assertNull($parser->parse($request));
    }

    public function testParseEmptyTokenParamValue(): void
    {
        $parser = new QueryString();
        $request = $this->createRequestWithQueryParams(['token' => '']);
        $this->assertNull($parser->parse($request));

        $requestSpaced = $this->createRequestWithQueryParams(['token' => '  ']);
        $this->assertNull($parser->parse($requestSpaced)); // trim会处理掉空格
    }

    public function testParseWithTokenInQueryAmongOtherParams(): void
    {
        $parser = new QueryString('api_key');
        $request = $this->createRequestWithQueryParams(['foo' => 'bar', 'api_key' => 'my_api_token', 'baz' => 'qux']);
        $this->assertEquals('my_api_token', $parser->parse($request));
    }

    public function testGetParamName(): void
    {
        $parser = new QueryString('custom_query_param');
        $this->assertEquals('custom_query_param', $parser->getParamName());
    }
}