<?php

declare(strict_types=1);

namespace FriendsOfHyperf\Jwt\Exception;

/**
 * Class TokenInvalidException.
 *
 * 当 JWT 令牌被视为无效时抛出。
 * 这可能是由于多种原因，例如：
 * - 令牌格式不正确
 * - 签名验证失败（通常由底层库处理，但也可能在此层面进一步检查）
 * - 必需的声明缺失
 * - 声明的值不符合预期
 * - 令牌已被列入黑名单（如果我们在此处也处理黑名单检查的抛出）
 */
class TokenInvalidException extends JwtException
{
    /**
     * 默认的异常消息。
     * @var string
     */
    protected $message = 'Token is invalid.'; // 令牌无效

    // 你可以根据需要添加构造函数来允许自定义消息或传递更多上下文信息
    // public function __construct($message = "", $code = 0, \Throwable $previous = null)
    // {
    //     parent::__construct($message ?: $this->message, $code, $previous);
    // }
}