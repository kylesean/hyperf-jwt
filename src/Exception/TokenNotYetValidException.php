<?php

declare(strict_types=1);

namespace Kylesean\Jwt\Exception;

/**
 * Class TokenNotYetValidException.
 *
 * Throws when the 'nbf' (Not Before) claim of the JWT token indicates that the token is not yet valid.
 * The current time is earlier than the earliest time the token is allowed to be used.
 */
class TokenNotYetValidException extends JwtException
{
    /**
     * Default exception message.
     * @var string
     */
    protected $message = 'Token is not yet valid.';
}