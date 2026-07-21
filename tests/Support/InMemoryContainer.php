<?php

declare(strict_types=1);

namespace Kylesean\Jwt\Tests\Support;

use Hyperf\Contract\ContainerInterface;
use Kylesean\Jwt\Token;
use RuntimeException;

/**
 * Minimal container for integration tests. It only knows how to make()
 * Token instances (which is all Manager needs) and has no bound services.
 */
class InMemoryContainer implements ContainerInterface
{
    public function get(string $id): mixed
    {
        throw new RuntimeException("No binding for {$id}");
    }

    public function has(string $id): bool
    {
        return false;
    }

    public function make(string $name, array $parameters = [])
    {
        if ($name === Token::class) {
            return new Token($parameters['lcobucciToken']);
        }

        throw new RuntimeException("Cannot make {$name}");
    }

    public function set(string $name, $entry): void
    {
    }

    public function unbind(string $name): void
    {
    }

    public function define(string $name, $definition): void
    {
    }
}
