<?php

declare(strict_types=1);

namespace Kylesean\Jwt\RequestParser;

use Kylesean\Jwt\Contract\RequestParser\RequestParserInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Parse JWT from HTTP cookies.
 */
class Cookie implements RequestParserInterface
{
    protected string $cookieName;

    public function __construct(string $cookieName = 'token')
    {
        $this->cookieName = $cookieName;
    }

    public function parse(ServerRequestInterface $request): ?string
    {
        $cookies = $request->getCookieParams();
        if (isset($cookies[$this->cookieName])) {
            $token = $cookies[$this->cookieName];
            if (is_string($token) && !empty(trim($token))) {
                return trim($token);
            }
        }
        return null;
    }

    public function getCookieName(): string
    {
        return $this->cookieName;
    }
}