<?php

declare(strict_types=1);

namespace FriendsOfHyperf\Jwt\Exception;

/**
 * Class TokenNotYetValidException.
 *
 * 当 JWT 令牌的 'nbf' (Not Before) 声明指示令牌尚未生效时抛出。
 * 当前时间早于令牌允许使用的最早时间。
 */
class TokenNotYetValidException extends JwtException
{
    /**
     * 默认的异常消息。
     * @var string
     */
    protected $message = 'Token is not yet valid.'; // 令牌尚未生效
}