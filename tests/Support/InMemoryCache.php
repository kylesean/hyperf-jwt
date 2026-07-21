<?php

declare(strict_types=1);

namespace Kylesean\Jwt\Tests\Support;

use DateInterval;
use DateTimeImmutable;
use Psr\SimpleCache\CacheInterface;

/**
 * Minimal array-backed PSR-16 cache for integration tests.
 * The public $store exposes raw entries as [value, expiresAt|null]
 * so tests can assert on stored values and TTLs.
 */
class InMemoryCache implements CacheInterface
{
    /** @var array<string, array{0: mixed, 1: int|null}> */
    public array $store = [];

    public function get(string $key, mixed $default = null): mixed
    {
        if (!array_key_exists($key, $this->store)) {
            return $default;
        }
        [$value, $expiresAt] = $this->store[$key];
        if ($expiresAt !== null && time() > $expiresAt) {
            unset($this->store[$key]);

            return $default;
        }

        return $value;
    }

    public function set(string $key, mixed $value, null|int|DateInterval $ttl = null): bool
    {
        if ($ttl instanceof DateInterval) {
            $seconds = (new DateTimeImmutable())->add($ttl)->getTimestamp() - time();
        } else {
            $seconds = $ttl;
        }
        $this->store[$key] = [$value, $seconds === null ? null : time() + $seconds];

        return true;
    }

    public function delete(string $key): bool
    {
        unset($this->store[$key]);

        return true;
    }

    public function clear(): bool
    {
        $this->store = [];

        return true;
    }

    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        $result = [];
        foreach ($keys as $key) {
            $result[$key] = $this->get($key, $default);
        }

        return $result;
    }

    public function setMultiple(iterable $values, null|int|DateInterval $ttl = null): bool
    {
        foreach ($values as $key => $value) {
            $this->set((string) $key, $value, $ttl);
        }

        return true;
    }

    public function deleteMultiple(iterable $keys): bool
    {
        foreach ($keys as $key) {
            $this->delete($key);
        }

        return true;
    }

    public function has(string $key): bool
    {
        return $this->get($key) !== null;
    }
}
