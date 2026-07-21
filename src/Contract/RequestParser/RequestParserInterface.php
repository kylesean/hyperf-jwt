<?php

declare(strict_types=1);

namespace Kylesean\Jwt\Contract\RequestParser;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Interface RequestParserInterface.
 *
 * Defines the method for attempting to parse the JWT string from a PSR-7 ServerRequestInterface object.
 */
interface RequestParserInterface
{
    /**
     * Attempt to parse JWT from the given PSR-7 request object.
     *
     * @param ServerRequestInterface $request PSR-7 server request object
     * @return string|null Returns the token string if successfully parsed, otherwise returns null
     */
    public function parse(ServerRequestInterface $request): ?string;
}
