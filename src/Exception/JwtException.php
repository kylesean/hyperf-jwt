<?php

declare(strict_types=1);

namespace FriendsOfHyperf\Jwt\Exception;

use RuntimeException; // 或者 \Exception，取决于你希望的异常层级

/**
 * Class JwtException.
 *
 * 所有 JWT 相关异常的基类。
 */
class JwtException extends RuntimeException
{
    // 你可以在这里添加一些通用的属性或方法，如果所有子异常都需要的话。
    // 例如，一个错误码。
}