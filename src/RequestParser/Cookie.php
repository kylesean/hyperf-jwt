<?php

declare(strict_types=1);

namespace FriendsOfHyperf\Jwt\RequestParser;

use FriendsOfHyperf\Jwt\Contract\RequestParser\RequestParserInterface;
use Psr\Http\Message\ServerRequestInterface;

class Cookie implements RequestParserInterface
{
    /**
     * 在 Cookie 中要查找的名称。
     * @var string
     */
    protected string $cookieName;

    /**
     * 构造函数。
     *
     * @param string $cookieName Cookie 的名称，例如 "token"
     */
    public function __construct(string $cookieName = 'token')
    {
        $this->cookieName = $cookieName;
    }

    /**
     * 尝试从 Cookie 中解析 JWT。
     *
     * @param ServerRequestInterface $request PSR-7 服务器请求对象
     * @return string|null 如果成功解析到令牌则返回令牌字符串，否则返回 null
     */
    public function parse(ServerRequestInterface $request): ?string
    {
        // 1. 获取所有 Cookie 参数
        // PSR-7 的 getCookieParams() 方法返回一个关联数组，包含了请求中的 Cookie。
        $cookies = $request->getCookieParams();

        // 2. 检查是否存在指定的 Cookie 名称，并且其值不为空
        if (isset($cookies[$this->cookieName])) {
            $token = $cookies[$this->cookieName];
            // Cookie 值通常是字符串
            if (is_string($token) && !empty(trim($token))) {
                return trim($token);
            }
        }

        return null;
    }

    /**
     * 获取配置的 Cookie 名称。
     */
    public function getCookieName(): string
    {
        return $this->cookieName;
    }
}