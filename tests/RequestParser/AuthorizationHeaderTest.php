<?php

declare(strict_types=1);

namespace FriendsOfHyperf\Jwt\Tests\RequestParser;

use FriendsOfHyperf\Jwt\RequestParser\AuthorizationHeader;
use Mockery;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

/**
 * @internal
 * @coversNothing
 */
class AuthorizationHeaderTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    protected function createRequestWithHeader(string $headerName, ?string $headerValue): ServerRequestInterface
    {
        $request = Mockery::mock(ServerRequestInterface::class);
        if ($headerValue === null) {
            // getHeaderLine 期望在头部不存在时返回空字符串
            $request->shouldReceive('getHeaderLine')->with($headerName)->andReturn('')->byDefault();
        } else {
            $request->shouldReceive('getHeaderLine')->with($headerName)->andReturn($headerValue)->byDefault();
        }
        return $request;
    }

    public function testParseWithValidBearerToken(): void
    {
        $parser = new AuthorizationHeader(); // 使用默认前缀 "Bearer" 和头部名 "Authorization"
        $request = $this->createRequestWithHeader('Authorization', 'Bearer my_jwt_token');
        $this->assertEquals('my_jwt_token', $parser->parse($request));
    }

    public function testParseWithValidCustomPrefixAndHeader(): void
    {
        $parser = new AuthorizationHeader('TokenPrefix', 'X-Auth-Token');
        $request = $this->createRequestWithHeader('X-Auth-Token', 'TokenPrefix my_other_token');
        $this->assertEquals('my_other_token', $parser->parse($request));
    }

    public function testParseMissingHeader(): void
    {
        $parser = new AuthorizationHeader();
        $request = $this->createRequestWithHeader('Authorization', null); // 模拟头部不存在
        $this->assertNull($parser->parse($request));
    }

    public function testParseEmptyHeaderValue(): void
    {
        $parser = new AuthorizationHeader();
        $request = $this->createRequestWithHeader('Authorization', '');
        $this->assertNull($parser->parse($request));
    }

    public function testParseHeaderWithIncorrectPrefix(): void
    {
        $parser = new AuthorizationHeader();
        $request = $this->createRequestWithHeader('Authorization', 'Basic some_other_string');
        $this->assertNull($parser->parse($request));
    }

    public function testParseHeaderWithPrefixButNoToken(): void
    {
        $parser = new AuthorizationHeader();
        $request = $this->createRequestWithHeader('Authorization', 'Bearer '); // 前缀后为空格，但没有token
        $this->assertNull($parser->parse($request)); // 我们的实现会提取空字符串，然后判断为空返回null

        $requestNoSpace = $this->createRequestWithHeader('Authorization', 'Bearer'); // 只有前缀
        $this->assertNull($parser->parse($requestNoSpace));
    }

    public function testParseHeaderWithPrefixAndTokenButNoSpace(): void
    {
        // 当前 AuthorizationHeader 的实现要求前缀后有空格 "Bearer <token>"
        $parser = new AuthorizationHeader();
        $request = $this->createRequestWithHeader('Authorization', 'Bearermy_jwt_token');
        $this->assertNull($parser->parse($request));
    }

    public function testGetters(): void
    {
        $parser = new AuthorizationHeader('TestBearer', 'X-My-Header');
        $this->assertEquals('TestBearer', $parser->getPrefix());
        $this->assertEquals('X-My-Header', $parser->getHeaderName());
    }
}