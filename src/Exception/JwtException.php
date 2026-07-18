<?php

declare(strict_types=1);

namespace Kylesean\Jwt\Exception;

use RuntimeException;

/**
 * Class JwtException.
 *
 * Base class for all JWT-related exceptions.
 */
class JwtException extends RuntimeException
{
    // You can add some common properties or methods here if all sub-exceptions need them.
    // For example, an error code.
}