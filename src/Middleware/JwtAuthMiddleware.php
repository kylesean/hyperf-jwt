<?php

declare(strict_types=1);

namespace Kylesean\Jwt\Middleware;

use Hyperf\Context\Context;
use Hyperf\Contract\ConfigInterface;
use Kylesean\Jwt\Contract\ManagerInterface;
use Kylesean\Jwt\Contract\TokenInterface;
use Kylesean\Jwt\Exception\TokenInvalidException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * JWT Auth Middleware.
 *
 * From request, parse JWT Token and store it in Hyperf Context and Request Attribute,
 * making it convenient to obtain authentication information in Controller and other components.
 */
class JwtAuthMiddleware implements MiddlewareInterface
{
    /**
     * Hyperf Context storage key name.
     */
    public const CONTEXT_KEY = 'jwt.token';

    /**
     * PSR-7 Request Attribute storage key name.
     */
    public const ATTRIBUTE_KEY = 'jwt.token';

    public function __construct(
        protected ManagerInterface $manager,
        protected ConfigInterface $config
    ) {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $token = $this->manager->parseTokenFromRequest($request);

        if (!$token) {
            $required = $this->config->get('jwt.middleware.auth_required', true);
            if ($required) {
                throw new TokenInvalidException('Token not provided.');
            }

            return $handler->handle($request);
        }

        // Store in Hyperf Coroutine Context (recommended, coroutine-safe)
        Context::set(self::CONTEXT_KEY, $token);

        // Also store in Request Attribute (PSR-7 compatible)
        $request = $request->withAttribute(self::ATTRIBUTE_KEY, $token);

        return $handler->handle($request);
    }

    /**
     * Static helper method: Get the current request's Token from Context.
     *
     * Usage example:
     * ```php
     * $token = JwtAuthMiddleware::getToken();
     * $userId = $token?->getSubject();
     * ```
     *
     * @return TokenInterface|null The current request's Token, or null if not authenticated
     */
    public static function getToken(): ?TokenInterface
    {
        return Context::get(self::CONTEXT_KEY);
    }

    /**
     * Static helper method: Get the current authenticated user's subject identifier (usually user ID).
     *
     * @return string|null User subject identifier, or null if not authenticated
     */
    public static function getSubject(): ?string
    {
        return self::getToken()?->getSubject();
    }

    /**
     * Static helper method: Get the value of the specified claim from the Token.
     *
     * @param string $name Claim name
     * @return mixed|null Claim value, or null if not authenticated or claim does not exist
     */
    public static function getClaim(string $name): mixed
    {
        return self::getToken()?->getClaim($name);
    }
}
