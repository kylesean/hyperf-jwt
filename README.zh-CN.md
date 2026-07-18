# Hyperf JWT 扩展包

[English](README.md) | 中文文档

基于 [lcobucci/jwt](https://github.com/lcobucci/jwt) v5 打造的高性能、轻量级 JWT 扩展包，专为 [Hyperf](https://github.com/hyperf/hyperf) 协程框架设计。

---

## 特性

- **专为协程设计**：原生适配 Hyperf DI 与 Swoole / Swow 协程并发环境。
- **灵活的算法支持**：支持 HMAC (HS256, HS384, HS512)、RSA (RS256 等) 及 ECDSA (ES256 等) 签名。
- **黑名单与并发宽限期**：支持基于 Redis / Cache 的黑名单，独创高并发下的**协程刷新宽限期（Concurrency Grace Period）**机制。
- **多管道 Token 解析**：支持从 Header (Bearer)、URL Query String、POST Body 及 Cookie 中按优先级提取 Token。
- **无缝中间件认证**：内置 `JwtAuthMiddleware`，集成 Context 请求上下文隔离与便捷静态助手。

---

## 安装

通过 Composer 安装：

```bash
composer require kylesean/hyperf-jwt
```

发布配置文件：

```bash
php bin/hyperf.php vendor:publish kylesean/hyperf-jwt
```

运行命令生成安全秘钥：

```bash
php bin/hyperf.php jwt:gen-key --algo=hs256 --update-env
```

---

## 核心使用示例

### 1. Token 签发与解析

```php
use Kylesean\Jwt\Contract\ManagerInterface;
use Hyperf\Context\ApplicationContext;

$manager = ApplicationContext::getContainer()->get(ManagerInterface::class);

// 1. 签发 Token (附带用户自定义 Claims 和 Subject 标识)
$token = $manager->issueToken([
    'user_id' => 123,
    'role' => 'admin'
], 'user_123');

$tokenString = $token->toString();

// 2. 解析与校验 Token 字符串
$parsedToken = $manager->parse($tokenString);
$userId = $parsedToken->getClaim('user_id'); // 123
$subject = $parsedToken->getSubject();       // 'user_123'
```

---

### 2. Token 刷新 (Refresh Token)

`ManagerInterface::refreshToken()` 方法允许客户端在旧 Token 过期后的刷新窗口期（`refresh_ttl`）内更换新 Token，并将旧 Token 自动拉黑。

```php
use Kylesean\Jwt\Exception\TokenExpiredException;
use Kylesean\Jwt\Exception\TokenInvalidException;

try {
    // 刷新旧 Token，返回新 Token 实例
    // 参数 1: 旧 token 字符串
    // 参数 2: forceForever (是否永久拉黑旧 token)
    // 参数 3: resetClaims (是否重置旧 token 的自定义 claims，默认 false)
    $newToken = $manager->refreshToken($oldTokenString);

    echo $newToken->toString();
} catch (TokenExpiredException $e) {
    // 旧 Token 已超出刷新期（refresh_ttl）
} catch (TokenInvalidException $e) {
    // 旧 Token 签名无效或已经被拉黑
}
```

---

### 3. Token 手动销毁与黑名单 (Invalidate & Blacklist)

#### 登出并销毁 Token
```php
// 将当前 Token 加入黑名单
$manager->invalidate($token);
```

#### 高并发下的协程刷新宽限期 (Concurrency Grace Period)
在高并发场景下（如前端同时并发发出 5 个 API 请求），若其中一个请求触发了 Token 刷新并把旧 Token 加入黑名单，其余 4 个并发请求若携带旧 Token 到达服务器可能直接返回 401 错误。

在配置文件 `config/autoload/jwt.php` 中配置并发宽限期：

```php
'blacklist_concurrency_grace_period' => 30, // 宽限 30 秒
```

在此 30 秒宽限期内，被刷新替换的旧 Token 仍会被认定为有效，防止前端并发请求报错。

---

### 4. 路由中间件

在 `config/routes.php` 或控制器注解中使用内置认证中间件：

```php
use Kylesean\Jwt\Middleware\JwtAuthMiddleware;
use Hyperf\HttpServer\Router\Router;

Router::addGroup('/api', function () {
    Router::get('/user/profile', [UserController::class, 'profile']);
}, ['middleware' => [JwtAuthMiddleware::class]]);
```

在控制器中获取已认证的用户信息：

```php
use Kylesean\Jwt\Middleware\JwtAuthMiddleware;

class UserController
{
    public function profile()
    {
        // 从当前协程 Context 中获取已认证的 Token 或 Subject
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

## 协议

[MIT 许可证](LICENSE) 
