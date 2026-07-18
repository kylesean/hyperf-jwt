<?php

declare(strict_types=1);

namespace Kylesean\Jwt\RequestParser;

use Kylesean\Jwt\Contract\RequestParser\RequestParserInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Parse JWT from request body (POST data or JSON).
 */
class InputSource implements RequestParserInterface
{
    protected string $paramName;

    public function __construct(string $paramName = 'token')
    {
        $this->paramName = $paramName;
    }

    public function parse(ServerRequestInterface $request): ?string
    {
        $parsedBody = $request->getParsedBody();

        if (is_array($parsedBody) && isset($parsedBody[$this->paramName])) {
            $token = $parsedBody[$this->paramName];
            if (is_string($token) && !empty(trim($token))) {
                return trim($token);
            }
        } elseif (is_object($parsedBody) && property_exists($parsedBody, $this->paramName)) {
            $token = $parsedBody->{$this->paramName};
            if (is_string($token) && !empty(trim($token))) {
                return trim($token);
            }
        }

        return null;
    }

    public function getParamName(): string
    {
        return $this->paramName;
    }
}