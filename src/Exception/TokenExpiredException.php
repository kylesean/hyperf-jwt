<?php

declare(strict_types=1);

namespace Kylesean\Jwt\Exception;

use DateTimeInterface;
use Throwable;

/**
 * Class TokenExpiredException.
 *
 * Thrown when the 'exp' (Expiration Time) claim of the JWT token indicates that the token has expired.
 */
class TokenExpiredException extends JwtException
{
    /**
     * Default exception message.
     * @var string
     */
    protected $message = 'Token has expired.';

    /**
     * @param array<string, mixed> $context
     */
    public function __construct(
        string $message = 'Token has expired.',
        protected ?DateTimeInterface $expiredAt = null,
        int $code = 0,
        ?Throwable $previous = null,
        array $context = []
    ) {
        if ($expiredAt !== null) {
            $context['expired_at'] = $expiredAt->format(DateTimeInterface::ATOM);
        }

        parent::__construct($message, $code, $previous, $context);
    }

    /**
     * Get the expiration date time.
     */
    public function getExpiredAt(): ?DateTimeInterface
    {
        return $this->expiredAt;
    }
}
