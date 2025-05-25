<?php

declare(strict_types=1);

namespace FriendsOfHyperf\Jwt\Tests\RequestParser;

use FriendsOfHyperf\Jwt\RequestParser\Cookie;
use Mockery;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

/**
 * @internal
 * @coversNothing
 */
class CookieTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    protected function createRequestWithCookies(array $cookies): ServerRequestInterface
    {
        $request = Mockery::mock(ServerRequestInterface::class);
        $request->shouldReceive('getCookieParams')->andReturn($cookies)->byDefault();
        return $request;
    }

    public function testParseWithValidTokenInCookie(): void
    {
        $parser = new Cookie(); // 默认 Cookie 名 "token"
        $request = $this->createRequestWithCookies(['token' => 'my_jwt_from_cookie']);
        $this->assertEquals('my_jwt_from_cookie', $parser->parse($request));
    }

    public function testParseWithValidTokenAndCustomCookieName(): void
    {
        $parser = new Cookie('jwt_cookie_name');
        $request = $this->createRequestWithCookies(['jwt_cookie_name' => 'my_other_cookie_token']);
        $this->assertEquals('my_other_cookie_token', $parser->parse($request));
    }

    public function testParseMissingTokenCookie(): void
    {
        $parser = new Cookie();
        $request = $this->createRequestWithCookies(['another_cookie' => 'some_value']);
        $this->assertNull($parser->parse($request));
    }

    public function testParseEmptyTokenCookieValue(): void
    {
        $parser = new Cookie();
        $request = $this->createRequestWithCookies(['token' => '']);
        $this->assertNull($parser->parse($request));

        $requestSpaced = $this->createRequestWithCookies(['token' => '   ']);
        $this->assertNull($parser->parse($requestSpaced));
    }

    public function testGetCookieName(): void
    {
        $parser = new Cookie('custom_cookie_name');
        $this->assertEquals('custom_cookie_name', $parser->getCookieName());
    }
}