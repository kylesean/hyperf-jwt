<?php

declare(strict_types=1);

namespace FriendsOfHyperf\Jwt\Tests\RequestParser;

use FriendsOfHyperf\Jwt\RequestParser\InputSource;
use Mockery;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use stdClass; // 用于模拟对象类型的 parsedBody

/**
 * @internal
 * @coversNothing
 */
class InputSourceTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    protected function createRequestWithParsedBody(mixed $body): ServerRequestInterface
    {
        $request = Mockery::mock(ServerRequestInterface::class);
        $request->shouldReceive('getParsedBody')->andReturn($body)->byDefault();
        return $request;
    }

    public function testParseWithValidTokenInArrayBody(): void
    {
        $parser = new InputSource(); // 默认参数名 "token"
        $request = $this->createRequestWithParsedBody(['token' => 'my_jwt_from_input_array']);
        $this->assertEquals('my_jwt_from_input_array', $parser->parse($request));
    }

    public function testParseWithValidTokenInObjectBody(): void
    {
        $parser = new InputSource();
        $body = new stdClass();
        $body->token = 'my_jwt_from_input_object';
        $request = $this->createRequestWithParsedBody($body);
        $this->assertEquals('my_jwt_from_input_object', $parser->parse($request));
    }

    public function testParseWithValidTokenAndCustomParamName(): void
    {
        $parser = new InputSource('jwt_field');
        $request = $this->createRequestWithParsedBody(['jwt_field' => 'my_other_input_token']);
        $this->assertEquals('my_other_input_token', $parser->parse($request));
    }

    public function testParseMissingTokenParamInBody(): void
    {
        $parser = new InputSource();
        $request = $this->createRequestWithParsedBody(['another_field' => 'some_value']);
        $this->assertNull($parser->parse($request));

        $requestObject = $this->createRequestWithParsedBody(new stdClass());
        $this->assertNull($parser->parse($requestObject));
    }

    public function testParseEmptyTokenParamValueInBody(): void
    {
        $parser = new InputSource();
        $request = $this->createRequestWithParsedBody(['token' => '']);
        $this->assertNull($parser->parse($request));

        $bodyObject = new stdClass();
        $bodyObject->token = '   ';
        $requestObject = $this->createRequestWithParsedBody($bodyObject);
        $this->assertNull($parser->parse($requestObject));
    }

    public function testParseWithNonArrayOrObjectBody(): void
    {
        $parser = new InputSource();
        $request = $this->createRequestWithParsedBody(null); // 例如 getParsedBody 返回 null
        $this->assertNull($parser->parse($request));

        $requestStringBody = $this->createRequestWithParsedBody("just a string");
        $this->assertNull($parser->parse($requestStringBody));
    }

    public function testGetParamName(): void
    {
        $parser = new InputSource('custom_input_field');
        $this->assertEquals('custom_input_field', $parser->getParamName());
    }
}