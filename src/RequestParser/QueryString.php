<?php

declare(strict_types=1);

namespace FriendsOfHyperf\Jwt\RequestParser;

use FriendsOfHyperf\Jwt\Contract\RequestParser\RequestParserInterface;
use Psr\Http\Message\ServerRequestInterface;

class QueryString implements RequestParserInterface
{
    /**
     * 在 URL 查询参数中要查找的参数名称。
     * @var string
     */
    protected string $paramName;

    /**
     * 构造函数。
     *
     * @param string $paramName URL 查询参数的名称，例如 "token"
     */
    public function __construct(string $paramName = 'token')
    {
        $this->paramName = $paramName;
    }

    /**
     * 尝试从 URL 查询参数中解析 JWT。
     *
     * @param ServerRequestInterface $request PSR-7 服务器请求对象
     * @return string|null 如果成功解析到令牌则返回令牌字符串，否则返回 null
     */
    public function parse(ServerRequestInterface $request): ?string
    {
        // 1. 获取所有查询参数
        $queryParams = $request->getQueryParams();

        // 2. 检查是否存在指定的参数名，并且其值不为空
        if (isset($queryParams[$this->paramName]) && !empty(trim((string) $queryParams[$this->paramName]))) {
            return trim((string) $queryParams[$this->paramName]);
        }

        return null;
    }

    /**
     * 获取配置的查询参数名称。
     */
    public function getParamName(): string
    {
        return $this->paramName;
    }
}