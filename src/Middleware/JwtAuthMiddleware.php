<?php

declare(strict_types=1);

namespace Kylesean\Jwt\Middleware;

use Hyperf\Context\Context;
use Kylesean\Jwt\Contract\ManagerInterface;
use Kylesean\Jwt\Contract\TokenInterface;
use Kylesean\Jwt\Exception\TokenInvalidException;
use Hyperf\HttpServer\Contract\ResponseInterface as HttpResponse;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * JWT 认证中间件。
 *
 * 从请求中解析 JWT Token 并存储到 Hyperf Context 和 Request Attribute 中，
 * 方便后续在 Controller 和其他组件中获取认证信息。
 */
class JwtAuthMiddleware implements MiddlewareInterface
{
    /**
     * Hyperf Context 存储键名。
     */
    public const CONTEXT_KEY = 'jwt.token';

    /**
     * PSR-7 Request Attribute 存储键名。
     */
    public const ATTRIBUTE_KEY = 'jwt.token';

    public function __construct(
        protected ManagerInterface $manager,
        protected HttpResponse $response,
        protected \Hyperf\Contract\ConfigInterface $config
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

        // 存储到 Hyperf 协程上下文（推荐方式，协程安全）
        Context::set(self::CONTEXT_KEY, $token);

        // 同时存入 Request Attribute（PSR-7 兼容方式）
        $request = $request->withAttribute(self::ATTRIBUTE_KEY, $token);

        return $handler->handle($request);
    }

    /**
     * 静态辅助方法：从 Context 获取当前请求的 Token。
     *
     * 使用示例：
     * ```php
     * $token = JwtAuthMiddleware::getToken();
     * $userId = $token?->getSubject();
     * ```
     *
     * @return TokenInterface|null 当前请求的 Token，如果未认证则返回 null
     */
    public static function getToken(): ?TokenInterface
    {
        return Context::get(self::CONTEXT_KEY);
    }

    /**
     * 静态辅助方法：获取当前认证用户的主体标识（通常是用户 ID）。
     *
     * @return string|null 用户主体标识，如果未认证则返回 null
     */
    public static function getSubject(): ?string
    {
        return self::getToken()?->getSubject();
    }

    /**
     * 静态辅助方法：获取 Token 中指定的声明值。
     *
     * @param string $name 声明名称
     * @return mixed|null 声明值，如果未认证或声明不存在则返回 null
     */
    public static function getClaim(string $name): mixed
    {
        return self::getToken()?->getClaim($name);
    }
}
