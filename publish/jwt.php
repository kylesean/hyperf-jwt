<?php

declare(strict_types=1);

use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;

return [
    /*
    |--------------------------------------------------------------------------
    | JWT 密钥 (JWT Secret)
    |--------------------------------------------------------------------------
    |
    | 用于签名和验证 JWT 的密钥。
    | 对于 HMAC 算法 (HS256, HS384, HS512)，这是一个字符串。
    | 对于 RSA 或 ECDSA 算法 (RS256, ES256 等)，你需要设置 `keys.private` 和 `keys.public`。
    | 强烈建议通过 GenJwtKeyCommand (php bin/hyperf.php jwt:gen-key) 命令生成一个安全的密钥。
    | 或者设置为 `env('JWT_SECRET')` 从环境变量读取。
    |
    */
    'secret' => env('JWT_SECRET', null),

    /*
    |--------------------------------------------------------------------------
    | JWT 签名算法 (JWT Signing Algorithm)
    |--------------------------------------------------------------------------
    |
    | 用于签名 JWT 的算法。建议使用 HS256 (HmacSha256) 或更强的算法如 RS256。
    | 支持的算法依赖于 lcobucci/jwt 库。
    | 常见的 HMAC 算法: Lcobucci\JWT\Signer\Hmac\Sha256::class, Lcobucci\JWT\Signer\Hmac\Sha384::class, Lcobucci\JWT\Signer\Hmac\Sha512::class
    | 常见的 RSA 算法: Lcobucci\JWT\Signer\Rsa\Sha256::class, Lcobucci\JWT\Signer\Rsa\Sha384::class, Lcobucci\JWT\Signer\Rsa\Sha512::class
    | 常见的 ECDSA 算法: Lcobucci\JWT\Signer\Ecdsa\Sha256::class, Lcobucci\JWT\Signer\Ecdsa\Sha384::class, Lcobucci\JWT\Signer\Ecdsa\Sha512::class
    |
    */
    'algo' => Sha256::class, // 默认使用 HS256

    /*
    |--------------------------------------------------------------------------
    | RSA 和 ECDSA 密钥 (RSA and ECDSA Keys)
    |--------------------------------------------------------------------------
    |
    | 如果你使用 RSA (RS*) 或 ECDSA (ES*) 算法，你需要在这里配置公钥和私钥。
    | 私钥用于签名，公钥用于验证。
    | 密钥内容可以是密钥文件路径 (以 'file://' 开头) 或者密钥本身的内容。
    | 如果是密钥文件路径，请确保 Hyperf 应用有读取权限。
    | 如果使用密钥内容，可以直接将 PEM 格式的密钥字符串粘贴在此。
    | `passphrase` 是私钥的密码短语，如果没有密码则设置为 null。
    |
    */
    'keys' => [
        'public' => env('JWT_PUBLIC_KEY', null), // 公钥路径或内容
        'private' => env('JWT_PRIVATE_KEY', null), // 私钥路径或内容
        'passphrase' => env('JWT_PASSPHRASE', null), // 私钥密码
    ],

    /*
    |--------------------------------------------------------------------------
    | JWT 令牌有效期 (JWT Time To Live)
    |--------------------------------------------------------------------------
    |
    | 指定令牌的有效期，单位为分钟。
    | 例如，设置为 60 表示令牌将在签发后 60 分钟过期。
    |
    */
    'ttl' => env('JWT_TTL', 60), // 单位：分钟

    /*
    |--------------------------------------------------------------------------
    | 刷新令牌的有效期 (Refresh Time To Live)
    |--------------------------------------------------------------------------
    |
    | 指定在旧令牌过期后，可以用来获取新令牌的刷新窗口期，单位为分钟。
    | 例如，设置为 20160 (约两周) 表示在令牌过期后的两周内，仍然可以使用该令牌（如果未被加入黑名单）去刷新获取一个新的令牌。
    | 这个值必须大于 `ttl`。
    |
    */
    'refresh_ttl' => env('JWT_REFRESH_TTL', 20160), // 单位：分钟

    /*
    |--------------------------------------------------------------------------
    | 令牌签发者 (JWT Issuer Claim)
    |--------------------------------------------------------------------------
    |
    | 'iss' (Issuer) 声明，标识 JWT 的签发者。
    | 你可以设置为你的应用名称或 URL。
    | 如果设置为 null，则不会在 JWT 中添加此声明。
    |
    */
    'issuer' => env('JWT_ISSUER', 'your-app-name'),

    /*
    |--------------------------------------------------------------------------
    | 令牌受众 (JWT Audience Claim)
    |--------------------------------------------------------------------------
    |
    | 'aud' (Audience) 声明，标识 JWT 的接收者（或预期受众）。
    | 你可以设置为你的应用名称或 URL。
    | 如果设置为 null，则不会在 JWT 中添加此声明。
    |
    */
    'audience' => env('JWT_AUDIENCE', 'your-app-name'),

    /*
    |--------------------------------------------------------------------------
    | 声明刷新列表 (Claims to Refresh)
    |--------------------------------------------------------------------------
    |
    | 当刷新一个 JWT 时，此数组中列出的声明将会被重新生成，
    | 而不是从旧令牌中复制。默认情况下，'iat', 'exp', 'nbf', 'jti'
    | 总是会被刷新。你可以在这里添加其他你希望在刷新时重新评估的声明。
    |
    */
    'claims_to_refresh' => [
        // 'custom_app_flag', // 例如，如果这个标记需要在每次刷新时重新计算
    ],

    /*
    |--------------------------------------------------------------------------
    | 令牌主体标识符 (JWT Subject Identifier Claim Name)
    |--------------------------------------------------------------------------
    |
    | 'sub' (Subject) 声明通常用于存储用户ID或其他唯一标识符。
    | 这里定义了从用户模型或身份对象中获取此值的属性名。
    | 当我们后面开发 auth 包时，会用到这个配置从 User 对象获取用户ID。
    | 对于仅 JWT 功能，此配置在生成令牌时指定 'sub' 声明的值。
    | 另外 PayloadFactory 和 Manager 可能用此配置来处理 'sub' 声明。
    |
    */
    'subject_claim' => 'sub',

    /*
    |--------------------------------------------------------------------------
    | 是否需要 'iat', 'nbf', 'exp' 声明 (Required Claims)
    |--------------------------------------------------------------------------
    |
    | 指定在验证令牌时，哪些标准时间声明是必须存在的。
    | 'iat' (Issued At) - 签发时间
    | 'nbf' (Not Before) - 生效时间
    | 'exp' (Expiration Time) - 过期时间
    | 建议全部保留为 true 以增强安全性。
    |
    */
    'required_claims' => [
        'iss' => true, // 是否必须验证签发者
        'aud' => true, // 是否必须验证受众
        // 'sub' 的验证通常在应用层面进行，确保它存在且有效
        'iat' => true, // 是否必须验证签发时间
        'nbf' => true, // 是否必须验证生效时间
        'exp' => true, // 是否必须验证过期时间
    ],

    /*
    |--------------------------------------------------------------------------
    | 时钟偏差容忍度 (Clock Leeway)
    |--------------------------------------------------------------------------
    |
    | 在验证 'nbf' (Not Before) 和 'exp' (Expiration Time) 声明时，
    | 允许的时钟偏差秒数，以解决服务器之间可能存在的微小时钟不同步问题。
    | 例如，设置为 60 表示允许 60 秒的偏差。
    |
    */
    'leeway' => env('JWT_LEEWAY', 0), // 单位：秒

    /*
    |--------------------------------------------------------------------------
    | 黑名单功能 (Blacklist Enabled)
    |--------------------------------------------------------------------------
    |
    | 是否启用 JWT 黑名单功能。
    | 启用后，已登出的令牌或手动加入黑名单的令牌将被视为无效。
    | 这需要配置缓存驱动 (`blacklist_cache_driver`)。
    |
    */
    'blacklist_enabled' => env('JWT_BLACKLIST_ENABLED', true),

    /*
    |--------------------------------------------------------------------------
    | 黑名单缓存驱动 (Blacklist Cache Driver)
    |--------------------------------------------------------------------------
    |
    | 用于存储 JWT 黑名单的缓存驱动名称。
    | 这应该对应 Hyperf 缓存配置 (`config/autoload/cache.php`) 中的一个驱动。
    | 例如：'default', 'redis' 等。
    | 如果 `blacklist_enabled` 为 false，此配置无效。
    |
    */
    'blacklist_cache_driver' => env('JWT_BLACKLIST_CACHE_DRIVER', 'default'),

    /*
    |--------------------------------------------------------------------------
    | 黑名单令牌宽限期 (Blacklist Grace Period)
    |--------------------------------------------------------------------------
    |
    | 当一个令牌被加入黑名单后，它在缓存中保留的时间（秒）。
    | 通常可以设置为令牌的 `refresh_ttl` 加上一定的缓冲时间，以确保在刷新期内令牌都可被检测到。
    | 这个值应该足够长，以覆盖令牌可能被用来尝试刷新的时间窗口。
    | 默认设置为 refresh_ttl 对应的秒数。
    |
    */
    'blacklist_grace_period' => env('JWT_BLACKLIST_GRACE_PERIOD', (int) env('JWT_REFRESH_TTL', 20160) * 60),

    /*
    |--------------------------------------------------------------------------
    | 令牌解析器链 (Token Parsers Chain)
    |--------------------------------------------------------------------------
    |
    | 定义从请求中提取 JWT 的解析器顺序。
    | Manager 会按顺序尝试这些解析器，直到成功获取令牌。
    | 可用的解析器类型有：
    | - 'header': 从 Authorization 头部 (Bearer token) 获取
    | - 'query': 从 URL 查询参数获取 (默认参数名 token)
    | - 'cookie': 从 Cookie 获取 (默认 cookie 名 token)
    | - 'input': 从请求体 (JSON/Form Post) 获取 (默认参数名 token)
    |
    | 你可以自定义每个解析器的参数，例如：
    | \FriendsOfHyperf\Jwt\RequestParser\AuthorizationHeader::class => ['prefix' => 'bearer', 'name' => 'authorization'],
    | \FriendsOfHyperf\Jwt\RequestParser\QueryString::class => ['name' => 'jwt_token'],
    | \FriendsOfHyperf\Jwt\RequestParser\InputSource::class => ['name' => 'jwt_token'],
    | \FriendsOfHyperf\Jwt\RequestParser\Cookie::class => ['name' => 'jwt_token'],
    |
    */
    'token_parsers' => [
        \FriendsOfHyperf\Jwt\RequestParser\AuthorizationHeader::class,
        \FriendsOfHyperf\Jwt\RequestParser\QueryString::class,
        \FriendsOfHyperf\Jwt\RequestParser\InputSource::class,
        \FriendsOfHyperf\Jwt\RequestParser\Cookie::class,
    ],

    /*
    |--------------------------------------------------------------------------
    | lcobucci/jwt 配置 (lcobucci/jwt Configuration)
    |--------------------------------------------------------------------------
    |
    | 如果你需要更细致地控制 lcobucci/jwt 库的行为，可以在这里提供一个
    | Lcobucci\JWT\Configuration 对象的工厂闭包或依赖注入标识。
    | 如果为 null，包将根据上述 'algo', 'secret', 'keys' 等配置自动创建 Configuration。
    |
    | 例如，自定义 Configuration:
    | 'lcobucci_config_factory' => function (\Psr\Container\ContainerInterface $container) {
    |     $signer = $container->get(MyCustomSigner::class); // 获取自定义签名器
    |     $key = InMemory::plainText('your-secret-key'); // 或其他密钥类型
    |     return \Lcobucci\JWT\Configuration::forSymmetricSigner($signer, $key);
    | },
    |
    | 注意：如果提供了此工厂，则上述 'secret', 'algo', 'keys' 配置将被忽略，
    | 因为它们主要用于自动创建 Configuration。
    |
    */
    'lcobucci_config_factory' => null,

];