<?php

declare(strict_types=1);

namespace Kylesean\Jwt\Tests\RequestParser;

use Kylesean\Jwt\RequestParser\AuthorizationHeader;
use Mockery;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

#[CoversClass(AuthorizationHeader::class)]
class AuthorizationHeaderTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    protected function createRequestWithHeader(string $headerName, ?string $headerValue): ServerRequestInterface
    {
        $request = Mockery::mock(ServerRequestInterface::class);
        if ($headerValue === null) {
            // getHeaderLine expects to return an empty string when the header does not exist
            $request->shouldReceive('getHeaderLine')->with($headerName)->andReturn('')->byDefault();
        } else {
            $request->shouldReceive('getHeaderLine')->with($headerName)->andReturn($headerValue)->byDefault();
        }
        return $request;
    }

    public function testParseWithValidBearerToken(): void
    {
        $parser = new AuthorizationHeader(); // Uses default prefix "Bearer" and header name "Authorization"
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
        $request = $this->createRequestWithHeader('Authorization', null); // Simulate missing header
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
        $request = $this->createRequestWithHeader('Authorization', 'Bearer '); // Trailing space after prefix, but no token
        $this->assertNull($parser->parse($request)); // Our implementation extracts an empty string, then returns null for empty value

        $requestNoSpace = $this->createRequestWithHeader('Authorization', 'Bearer'); // Prefix only
        $this->assertNull($parser->parse($requestNoSpace));
    }

    public function testParseHeaderWithPrefixAndTokenButNoSpace(): void
    {
        // Current AuthorizationHeader implementation requires space after prefix "Bearer <token>"
        $parser = new AuthorizationHeader();
        $request = $this->createRequestWithHeader('Authorization', 'Bearer_my_jwt_token');
        $this->assertNull($parser->parse($request));
    }

    public function testGetters(): void
    {
        $parser = new AuthorizationHeader('TestBearer', 'X-My-Header');
        $this->assertEquals('TestBearer', $parser->getPrefix());
        $this->assertEquals('X-My-Header', $parser->getHeaderName());
    }
}