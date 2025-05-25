<?php

declare(strict_types=1);

namespace FriendsOfHyperf\Jwt\RequestParser;

use FriendsOfHyperf\Jwt\Contract\RequestParser\RequestParserInterface;
use Psr\Http\Message\ServerRequestInterface;
use function Hyperf\Support\str_contains; // 使用 Hyperf 的辅助函数
use function Hyperf\Support\Str; // 使用 Hyperf 的字符串辅助类

class AuthorizationHeader implements RequestParserInterface
{
    /**
     * 期望的头部值前缀。
     * 例如 "Bearer"。注意，前缀后面通常会有一个空格。
     * @var string
     */
    protected string $prefix;

    /**
     * 要检查的 HTTP 头部名称。
     * @var string
     */
    protected string $headerName;

    /**
     * 构造函数。
     *
     * @param string $prefix 令牌在头部值中的前缀，例如 "Bearer"
     * @param string $headerName HTTP 头部的名称，例如 "Authorization"
     */
    public function __construct(string $prefix = 'Bearer', string $headerName = 'Authorization')
    {
        $this->prefix = trim($prefix); // 去除前后空格
        $this->headerName = $headerName;
    }

    /**
     * 尝试从 Authorization 头部解析 JWT。
     *
     * @param ServerRequestInterface $request PSR-7 服务器请求对象
     * @return string|null 如果成功解析到令牌则返回令牌字符串，否则返回 null
     */
    public function parse(ServerRequestInterface $request): ?string
    {
        // 1. 获取指定的头部行
        // PSR-7 推荐使用 getHeaderLine 来获取单个头部的值（如果是多行，会合并）
        $headerValue = $request->getHeaderLine($this->headerName);

        // 2. 检查头部是否存在且不为空
        if (empty($headerValue)) {
            return null;
        }

        // 3. 检查前缀
        // 我们需要确保前缀后面有一个空格，例如 "Bearer <token>"
        $prefixWithSpace = $this->prefix . ' ';
        if (!Str::startsWith($headerValue, $prefixWithSpace)) {
            // 如果前缀不区分大小写，可以使用 strtolower 比较
            // if (!Str::startsWith(strtolower($headerValue), strtolower($prefixWithSpace))) {
            //    return null;
            // }
            // 或者，如果允许没有空格的前缀（不推荐）
            // if (!Str::startsWith($headerValue, $this->prefix)) {
            //    return null;
            // }
            return null;
        }

        // 4. 提取令牌部分
        // 从前缀（包括空格）之后的部分开始提取
        $token = Str::substr($headerValue, Str::length($prefixWithSpace));

        // 5. 返回提取到的令牌（如果非空）
        return !empty($token) ? $token : null;
    }

    /**
     * 获取配置的头部名称。
     */
    public function getHeaderName(): string
    {
        return $this->headerName;
    }

    /**
     * 获取配置的头部值前缀。
     */
    public function getPrefix(): string
    {
        return $this->prefix;
    }
}