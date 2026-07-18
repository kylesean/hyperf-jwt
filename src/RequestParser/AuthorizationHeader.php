<?php

declare(strict_types=1);

namespace Kylesean\Jwt\RequestParser;

use Kylesean\Jwt\Contract\RequestParser\RequestParserInterface;
use Hyperf\Stringable\Str;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Parse JWT from Authorization header (e.g., "Bearer <token>").
 */
class AuthorizationHeader implements RequestParserInterface
{
    protected string $prefix;
    protected string $headerName;

    public function __construct(string $prefix = 'Bearer', string $headerName = 'Authorization')
    {
        $this->prefix = trim($prefix);
        $this->headerName = $headerName;
    }

    public function parse(ServerRequestInterface $request): ?string
    {
        $headerValue = $request->getHeaderLine($this->headerName);
        if (empty($headerValue)) {
            return null;
        }

        $prefixWithSpace = $this->prefix . ' ';
        if (!Str::startsWith($headerValue, $prefixWithSpace)) {
            return null;
        }

        $token = Str::substr($headerValue, Str::length($prefixWithSpace));
        return !empty($token) ? $token : null;
    }

    public function getHeaderName(): string
    {
        return $this->headerName;
    }

    public function getPrefix(): string
    {
        return $this->prefix;
    }
}