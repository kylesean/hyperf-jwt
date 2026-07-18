<?php

declare(strict_types=1);

namespace Kylesean\Jwt\Exception;

/**
 * Class TokenInvalidException.
 *
 * Throws when the JWT token is considered invalid.
 * This may be due to several reasons, such as:
 * - The token format is incorrect
 * - Signature verification failed (usually handled by the underlying library, but may be further checked at this level)
 * - A required claim is missing
 * - The value of a claim does not meet expectations
 * - The token has been blacklisted (if we also handle the exception thrown by the blacklist check here)
 */
class TokenInvalidException extends JwtException
{
    /**
     * Default exception message.
     * @var string
     */
    protected $message = 'Token is invalid.';

    // You can add a constructor to allow custom messages or pass more contextual information if needed
    // public function __construct($message = "", $code = 0, \Throwable $previous = null)
    // {
    //     parent::__construct($message ?: $this->message, $code, $previous);
    // }
}