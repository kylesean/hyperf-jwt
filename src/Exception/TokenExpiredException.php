<?php

declare(strict_types=1);

namespace Kylesean\Jwt\Exception;

/**
 * Class TokenExpiredException.
 *
 * Throws when the 'exp' (Expiration Time) claim of the JWT token indicates that the token has expired.
 */
class TokenExpiredException extends JwtException
{
    /**
     * Default exception message.
     * @var string
     */
    protected $message = 'Token has expired.';
}