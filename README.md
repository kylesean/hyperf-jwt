# Hyperf JWT


为 [Hyperf](https://hyperf.io/) 框架设计的 JWT (JSON Web Token) 认证包，提供了 Token 签发、解析、验证、刷新、黑名单等功能。

## 安装

```bash
composer require friendsofhyperf/jwt
```

## 配置密钥和算法
```bash
php bin/hyperf.php vendor:publish friendsofhyperf/jwt

php bin/hyperf.php jwt:gen-key --algo=HS256

```
## 其他配置

参考 `config/autoload/jwt.php` 中的注释，调整以下配置

- `ttl`：Token 有效期 (分钟)。
- `refresh_ttl`：Token 过期后可刷新的宽限期 (分钟)。
- `blacklist_enabled`：是否启用黑名单。
- `blacklist_cache_driver`：黑名单使用的缓存驱动。
- `token_parsers`：从请求中提取 Token 的解析器链。
- `issuer (iss)` 和 `audience (aud)` 声明。
- `required_claims`：验证时必须存在的声明。
- `leeway`：时钟偏差容忍度 (秒)。

## 签发 Token

```php
$customClaims = [
    'user_id' => 123,
    'username' => 'test_user',
    // 其他自定义数据...
];
$subject = 123; 
$tokenObject = $this->jwtManager->issueToken($customClaims, $subject);
$tokenString = $tokenObject->toString(); 

```
## 解析和验证 Token

```php

use FriendsOfHyperf\Jwt\Contract\ManagerInterface;
use FriendsOfHyperf\Jwt\Exception\TokenExpiredException;
use FriendsOfHyperf\Jwt\Exception\TokenInvalidException;
use FriendsOfHyperf\Jwt\Exception\TokenNotYetValidException;
use FriendsOfHyperf\Jwt\Exception\JwtException;
use Psr\Http\Message\ServerRequestInterface;

// ...
try {
    $tokenObject = $this->jwtManager->parseTokenFromRequest($request); 
    // $tokenObject = $this->jwtManager->parse($tokenString);
    if ($tokenObject) {
        $userId = $tokenObject->getClaim('user_id');
        $jti = $tokenObject->getId(); // 获取 jti
    } else {
        // Token 未找到或无效
    }
} catch (TokenExpiredException $e) {
    // Token 已过期
} catch (TokenInvalidException $e) {
    // Token 无效 (例如，签名错误、声明缺失、已在黑名单)
} catch (TokenNotYetValidException $e) {
    // Token 尚未生效
} catch (JwtException $e) {
    // 其他 JWT 相关错误
}
```

## 刷新 Token
```php
// $oldTokenString 是客户端传递过来的旧 Token 字符串
try {
    $newTokenObject = $this->jwtManager->refreshToken($oldTokenString);
    $newTokenString = $newTokenObject->toString();
    // 将新的 Token 返回给客户端，客户端需要替换旧的 Token
} catch (TokenExpiredException $e) {
    // 旧 Token 已彻底过期，无法刷新
} catch (TokenInvalidException $e) {
    // 旧 Token 无效 (例如已在黑名单)
} catch (JwtException $e) {
    // 刷新过程中发生其他错误
}
// refreshToken 方法会自动将旧 Token 加入黑名单
```
## 使 Token 失效（加入黑名单）
```php

try {
    $tokenObject = $this->jwtManager->parse($tokenString); 
    if ($tokenObject) {
        $this->jwtManager->invalidate($tokenObject);
        // Token 已成功加入黑名单
    }
} catch (JwtException $e) {
  
}
```
## 自定义 PayloadFactory
精细地控制签发 Token 时的默认载荷，或者根据不同场景添加不同的默认声明
```php
// config/dependencies.php
return [
    \FriendsOfHyperf\Jwt\Contract\PayloadFactoryInterface::class => \App\Service\MyCustomPayloadFactory::class,
];```
```
## License
[MIT](LICENSE)