<?php

declare(strict_types=1);

namespace FriendsOfHyperf\Jwt\Exception;

/**
 * Class TokenExpiredException.
 *
 * 当 JWT 令牌的 'exp' (Expiration Time) 声明指示令牌已过期时抛出。
 */
class TokenExpiredException extends JwtException
{
    /**
     * 默认的异常消息。
     * @var string
     */
    protected $message = 'Token has expired.'; // 令牌已过期
}