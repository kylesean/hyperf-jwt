# Hyperf JWT Package

English | [中文文档](README.zh-CN.md)

A high-performance, lightweight JWT (JSON Web Token) package designed for [Hyperf](https://github.com/hyperf/hyperf) coroutine framework, powered by [lcobucci/jwt](https://github.com/lcobucci/jwt) v5.

---

## Features

- **Coroutine Friendly**: Native integration with Hyperf DI container and Swoole/Swow coroutine concurrency environments.
- **Multiple Algorithms**: Full support for HMAC (HS256, HS384, HS512), RSA (RS256, etc.), and ECDSA (ES256, etc.) signing algorithms.
- **Blacklist & Concurrency Grace Period**: Redis/Cache-backed token blacklisting with an innovative **Concurrency Grace Period** mechanism for coroutine applications.
- **Flexible Request Parsing**: Extract tokens from Authorization Header (Bearer), URL Query Parameters, POST Body, or Cookies in customizable order.
- **Seamless Authentication Middleware**: Out-of-the-box `JwtAuthMiddleware` with coroutine context isolation and convenient static helpers.

---

## Installation

Install via Composer:

```bash
composer require kylesean/hyperf-jwt
```

Publish the configuration file:

```bash
php bin/hyperf.php vendor:publish kylesean/hyperf-jwt
```

Generate a secure secret key:

```bash
php bin/hyperf.php jwt:gen-key --algo=hs256 --update-env
```

---

## Quick Start

### 1. Token Issuance & Parsing

```php
use Kylesean\Jwt\Contract\ManagerInterface;
use Hyperf\Context\ApplicationContext;

$manager = ApplicationContext::getContainer()->get(ManagerInterface::class);

// 1. Issue a Token with custom claims and subject
$token = $manager->issueToken([
    'user_id' => 123,
    'role' => 'admin'
], 'user_123');

$tokenString = $token->toString();

// 2. Parse and validate a Token string
$parsedToken = $manager->parse($tokenString);
$userId = $parsedToken->getClaim('user_id'); // 123
$subject = $parsedToken->getSubject();       // 'user_123'
```

---

### 2. Token Refreshing

The `ManagerInterface::refreshToken()` method allows clients to swap an expiring token for a fresh token within the configured refresh window (`refresh_ttl`), automatically blacklisting the old token.

```php
use Kylesean\Jwt\Exception\TokenExpiredException;
use Kylesean\Jwt\Exception\TokenInvalidException;

try {
    // Refresh the old token and get a new Token instance
    // Param 1: Old token string
    // Param 2: forceForever (Whether to permanently blacklist the old token)
    // Param 3: resetClaims (Whether to reset custom claims on the new token, default false)
    $newToken = $manager->refreshToken($oldTokenString);

    echo $newToken->toString();
} catch (TokenExpiredException $e) {
    // Old token has exceeded the refresh TTL window
} catch (TokenInvalidException $e) {
    // Old token is invalid, tampered with, or already blacklisted
}
```

---

### 3. Token Invalidation & Blacklist Grace Period

#### Manual Invalidation (Logout)
```php
// Add the given token to the blacklist immediately
$manager->invalidate($token);
```

#### Coroutine Concurrency Grace Period
In high-concurrency coroutine environments (e.g. 5 parallel HTTP requests sent by a Single Page App simultaneously), if one request refreshes the token and invalidates the old one immediately, the remaining 4 concurrent requests carrying the old token might trigger 401 Unauthorized errors.

Configure the concurrency grace period in `config/autoload/jwt.php`:

```php
'blacklist_concurrency_grace_period' => 30, // 30 seconds grace period
```

During this 30-second window, the replaced old token remains accepted as valid, preventing race-condition failures.

---

### 4. Authentication Middleware

Register `JwtAuthMiddleware` in your routes or controller annotations:

```php
use Kylesean\Jwt\Middleware\JwtAuthMiddleware;
use Hyperf\HttpServer\Router\Router;

Router::addGroup('/api', function () {
    Router::get('/user/profile', [UserController::class, 'profile']);
}, ['middleware' => [JwtAuthMiddleware::class]]);
```

Access authenticated identity inside controllers:

```php
use Kylesean\Jwt\Middleware\JwtAuthMiddleware;

class UserController
{
    public function profile()
    {
        // Retrieve current authenticated Token / Subject from Coroutine Context
        $subject = JwtAuthMiddleware::getSubject();
        $role = JwtAuthMiddleware::getClaim('role');

        return [
            'user' => $subject,
            'role' => $role
        ];
    }
}
```

---

## License

[MIT license](LICENSE)
