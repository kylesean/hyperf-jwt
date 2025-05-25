<?php

declare(strict_types=1);

namespace FriendsOfHyperf\Jwt\Contract\RequestParser;

use Psr\Http\Message\ServerRequestInterface; // PSR-7 服务器请求接口

/**
 * Interface RequestParserInterface.
 *
 * 定义了从 PSR-7 ServerRequestInterface 对象中尝试解析 JWT 字符串的方法。
 */
interface RequestParserInterface
{
    /**
     * 尝试从给定的 PSR-7 请求对象中解析 JWT。
     *
     * @param ServerRequestInterface $request PSR-7 服务器请求对象
     * @return string|null 如果成功解析到令牌则返回令牌字符串，否则返回 null
     */
    public function parse(ServerRequestInterface $request): ?string;
}