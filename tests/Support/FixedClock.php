<?php

declare(strict_types=1);

namespace Kylesean\Jwt\Tests\Support;

use DateTimeImmutable;
use Psr\Clock\ClockInterface;

/**
 * Deterministic PSR-20 clock whose current time can be advanced by tests.
 */
class FixedClock implements ClockInterface
{
    public function __construct(private DateTimeImmutable $now)
    {
    }

    public function now(): DateTimeImmutable
    {
        return $this->now;
    }

    public function setTo(DateTimeImmutable $now): void
    {
        $this->now = $now;
    }
}
