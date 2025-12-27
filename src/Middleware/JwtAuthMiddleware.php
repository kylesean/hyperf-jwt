<?php

declare(strict_types=1);

namespace FriendsOfHyperf\Jwt\Middleware;

use FriendsOfHyperf\Jwt\Contract\ManagerInterface;
use FriendsOfHyperf\Jwt\Exception\TokenInvalidException;
use Hyperf\HttpServer\Contract\ResponseInterface as HttpResponse;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

class JwtAuthMiddleware implements MiddlewareInterface
{
    public function __construct(
        protected ManagerInterface $manager,
        protected HttpResponse $response
    ) {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $token = $this->manager->parseTokenFromRequest($request);

        if (!$token) {
            throw new TokenInvalidException('Token not provided.');
        }

        // 可以将解析出的 token 存入请求上下文，方便后续在 Controller 中获取
        // Hyperf 惯例是使用 Context
        // \Hyperf\Context\Context::set('jwt.token', $token);

        return $handler->handle($request);
    }
}
