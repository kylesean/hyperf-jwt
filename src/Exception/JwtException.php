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
    /**
     * @param array<string, mixed> $context
     */
    public function __construct(
        string $message = '',
        int $code = 0,
        ?\Throwable $previous = null,
        protected array $context = []
    ) {
        parent::__construct($message, $code, $previous);
    }

    /**
     * Get contextual metadata associated with the exception.
     *
     * @return array<string, mixed>
     */
    public function getContext(): array
    {
        return $this->context;
    }
}
