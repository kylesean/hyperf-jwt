# Hyperf JWT

[![Latest Stable Version](https://img.shields.io/packagist/v/kylesean/hyperf-jwt.svg)](https://packagist.org/packages/kylesean/hyperf-jwt)
[![License](https://img.shields.io/packagist/l/kylesean/hyperf-jwt.svg)](https://packagist.org/packages/kylesean/hyperf-jwt)

为 [Hyperf](https://hyperf.io/) 框架量身定制的 JWT (JSON Web Token) 专业认证扩展包。基于强大的 `lcobucci/jwt` v5.4+ 构建，提供高性能、强类型且符合 PSR 标准的认证方案。

## ✨ 特性

- **库版本对齐**：全面支持 `lcobucci/jwt` v5.4+ 的不可变 API。
- **架构解耦**：基于工厂模式和依赖注入，核心 `Manager` 高度解耦。
- **中间件支持**：内置标准的身份验证中间件。
- **异常桥接**：将复杂的验证失败精准转化为业务语义异常（过期、非法、尚未生效）。
- **多源解析**：支持从 Header、Query、Cookie 等多种途径提取令牌。
- **黑名单机制**：支持 Token 主动注销与刷新。

## 📦 安装

```bash
composer require kylesean/hyperf-jwt
```

## 🛠️ 配置

### 1. 发布配置文件
```bash
php bin/hyperf.php vendor:publish kylesean/hyperf-jwt
```

### 2. 生成密钥 (ECC 或 HMAC)
```bash
# 生成 HS256 密钥
php bin/hyperf.php jwt:gen-key --algo=HS256
```

请参考 `config/autoload/jwt.php` 完善 `issuer`, `audience`, `ttl` 等核心配置。

## 🚀 快速开始

### 签发 Token
```php
use Kylesean\Jwt\Contract\ManagerInterface;

public function login(ManagerInterface $manager)
{
    $customClaims = ['role' => 'admin'];
    $userId = 1;

    // 签发 Token (返回 TokenInterface 对象)
    $token = $manager->issueToken($customClaims, $userId);
    
    return [
        'access_token' => $token->toString(),
    ];
}
```

### 身份验证中间件
在路由或控制器上挂载 `Kylesean\Jwt\Middleware\JwtAuthMiddleware` 即可实现自动拦截。

```php
// config/routes.php
Router::addGroup('/admin', function () {
    Router::get('/profile', [App\Controller\UserController::class, 'profile']);
}, ['middleware' => [Kylesean\Jwt\Middleware\JwtAuthMiddleware::class]]);
```

## 🛡️ 异常处理

本插件会将验证失败的具体原因桥接到以下异常，建议在 `App\Exception\Handler` 中统一捕获：

| 异常类 | 含义 | 建议响应 |
| :--- | :--- | :--- |
| `TokenExpiredException` | 令牌已过期 | HTTP 401 (Code: 40101) |
| `TokenInvalidException` | 签名错误或被黑名单 | HTTP 401 (Code: 40102) |
| `TokenNotYetValidException` | 令牌尚未到生效时间 | HTTP 401 |
| `JwtException` | 其他 JWT 内部错误 | HTTP 500 |

## ⚙️ 高级用法

### 自定义载荷工厂 (PayloadFactory)
若需精细控制签发逻辑，可替换默认工厂：

```php
// config/dependencies.php
return [
    \Kylesean\Jwt\Contract\PayloadFactoryInterface::class => \App\Jwt\CustomPayloadFactory::class,
];
```

## ⚖️ 许可证

MIT License.
