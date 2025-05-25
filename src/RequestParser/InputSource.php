<?php

declare(strict_types=1);

namespace FriendsOfHyperf\Jwt\RequestParser;

use FriendsOfHyperf\Jwt\Contract\RequestParser\RequestParserInterface;
use Psr\Http\Message\ServerRequestInterface;

class InputSource implements RequestParserInterface
{
    /**
     * 在请求体中要查找的参数名称。
     * @var string
     */
    protected string $paramName;

    /**
     * 构造函数。
     *
     * @param string $paramName 请求体参数的名称，例如 "token"
     */
    public function __construct(string $paramName = 'token')
    {
        $this->paramName = $paramName;
    }

    /**
     * 尝试从请求体（已解析的 POST 或 JSON 数据）中解析 JWT。
     *
     * @param ServerRequestInterface $request PSR-7 服务器请求对象
     * @return string|null 如果成功解析到令牌则返回令牌字符串，否则返回 null
     */
    public function parse(ServerRequestInterface $request): ?string
    {
        // 1. 获取已解析的请求体内容
        // PSR-7 的 getParsedBody() 方法会根据 Content-Type 返回解析后的数据。
        // - 对于 application/x-www-form-urlencoded，通常是键值对数组。
        // - 对于 application/json，通常是PHP数组或对象 (取决于JSON解析中间件的行为)。
        // - 如果 Content-Type 不被识别或请求体为空，可能返回 null 或空数组。
        $parsedBody = $request->getParsedBody();

        // 2. 检查 $parsedBody 是否为数组或对象，以及是否包含指定的参数
        if (is_array($parsedBody) && isset($parsedBody[$this->paramName])) {
            $token = $parsedBody[$this->paramName];
            if (is_string($token) && !empty(trim($token))) {
                return trim($token);
            }
        } elseif (is_object($parsedBody) && property_exists($parsedBody, $this->paramName)) {
            $token = $parsedBody->{$this->paramName};
            if (is_string($token) && !empty(trim($token))) {
                return trim($token);
            }
        }

        return null;
    }

    /**
     * 获取配置的请求体参数名称。
     */
    public function getParamName(): string
    {
        return $this->paramName;
    }
}