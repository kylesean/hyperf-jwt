<?php

declare(strict_types=1);

namespace Kylesean\Jwt\Exception;

use DateTimeInterface;
use Throwable;

/**
 * Class TokenNotYetValidException.
 *
 * Thrown when the 'nbf' (Not Before) claim of the JWT token indicates that the token is not yet valid.
 * The current time is earlier than the earliest time the token is allowed to be used.
 */
class TokenNotYetValidException extends JwtException
{
    /**
     * Default exception message.
     * @var string
     */
    protected $message = 'Token is not yet valid.';

    /**
     * @param array<string, mixed> $context
     */
    public function __construct(
        string $message = 'Token is not yet valid.',
        protected ?DateTimeInterface $notBefore = null,
        int $code = 0,
        ?Throwable $previous = null,
        array $context = []
    ) {
        if ($notBefore !== null) {
            $context['not_before'] = $notBefore->format(DateTimeInterface::ATOM);
        }

        parent::__construct($message, $code, $previous, $context);
    }

    /**
     * Get the not-before date time.
     */
    public function getNotBefore(): ?DateTimeInterface
    {
        return $this->notBefore;
    }
}
