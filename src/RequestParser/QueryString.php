<?php

declare(strict_types=1);

namespace Kylesean\Jwt\RequestParser;

use Kylesean\Jwt\Contract\RequestParser\RequestParserInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Parses JWT from URL query parameters.
 */
class QueryString implements RequestParserInterface
{
    protected string $paramName;

    public function __construct(string $paramName = 'token')
    {
        $this->paramName = $paramName;
    }

    public function parse(ServerRequestInterface $request): ?string
    {
        $queryParams = $request->getQueryParams();
        if (isset($queryParams[$this->paramName]) && !empty(trim((string) $queryParams[$this->paramName]))) {
            return trim((string) $queryParams[$this->paramName]);
        }
        return null;
    }

    public function getParamName(): string
    {
        return $this->paramName;
    }
}