<?php

declare(strict_types=1);

namespace Kylesean\Jwt\Tests\Support;

use Hyperf\Contract\ConfigInterface;

/**
 * Minimal array-backed ConfigInterface for integration tests.
 * Keys are flat dot-notation strings, e.g. 'jwt.ttl' or 'jwt.required_claims.iss'.
 */
class InMemoryConfig implements ConfigInterface
{
    /**
     * @param array<string, mixed> $items
     */
    public function __construct(private array $items = [])
    {
    }

    public function get(string $key, mixed $default = null): mixed
    {
        return array_key_exists($key, $this->items) ? $this->items[$key] : $default;
    }

    public function has(string $keys): bool
    {
        return array_key_exists($keys, $this->items);
    }

    public function set(string $key, mixed $value): void
    {
        $this->items[$key] = $value;
    }
}
