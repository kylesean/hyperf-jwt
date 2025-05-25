<?php

declare(strict_types=1);

namespace FriendsOfHyperf\Jwt;

use DateTimeImmutable;
use FriendsOfHyperf\Jwt\Contract\TokenInterface;
use Lcobucci\JWT\Token as LcobucciPlainToken; // 通常 lcobucci 解析后得到的是 Plain 对象
use Lcobucci\JWT\UnencryptedToken; // lcobucci/jwt v4/v5 的基类或接口

class Token implements TokenInterface
{
    protected UnencryptedToken $lcobucciToken; // 底层 lcobucci 令牌实例

    /**
     * 构造函数.
     *
     * @param UnencryptedToken $lcobucciToken 底层的 lcobucci/jwt 令牌对象
     */
    public function __construct(UnencryptedToken $lcobucciToken)
    {
        $this->lcobucciToken = $lcobucciToken;
    }

    /**
     * 获取原始的 lcobucci/jwt 令牌对象。
     */
    public function getLcobucciToken(): UnencryptedToken // 返回类型调整为 UnencryptedToken
    {
        return $this->lcobucciToken;
    }

    /**
     * 获取令牌的字符串表示形式。
     */
    public function toString(): string
    {
        return $this->lcobucciToken->toString();
    }

    /**
     * 获取令牌的唯一标识符 (jti - JWT ID)。
     */
    public function getId(): ?string
    {
        return $this->lcobucciToken->claims()->get('jti');
    }

    /**
     * 获取令牌的签发者 (iss - Issuer)。
     */
    public function getIssuer(): ?string
    {
        $issuer = $this->lcobucciToken->claims()->get('iss');
        // lcobucci/jwt v5 中，issuer 可能是一个 Stringable 对象
        return $issuer instanceof \Stringable ? (string) $issuer : $issuer;
    }

    /**
     * 获取令牌的受众 (aud - Audience)。
     * @return string[]
     */
    public function getAudience(): array
    {
        $audience = $this->lcobucciToken->claims()->get('aud', []);
        // 确保返回的是数组，即使只有一个受众字符串
        return is_array($audience) ? $audience : [$audience];
    }

    /**
     * 获取令牌的主题 (sub - Subject)。
     */
    public function getSubject(): ?string
    {
        $subject = $this->lcobucciToken->claims()->get('sub');
        // lcobucci/jwt v5 中，subject 可能是一个 Stringable 对象
        return $subject instanceof \Stringable ? (string) $subject : $subject;
    }

    /**
     * 获取令牌的签发时间 (iat - Issued At)。
     */
    public function getIssuedAt(): ?DateTimeImmutable
    {
        return $this->lcobucciToken->claims()->get('iat');
    }

    /**
     * 获取令牌的生效时间 (nbf - Not Before)。
     */
    public function getNotBefore(): ?DateTimeImmutable
    {
        return $this->lcobucciToken->claims()->get('nbf');
    }

    /**
     * 获取令牌的过期时间 (exp - Expiration Time)。
     */
    public function getExpirationTime(): ?DateTimeImmutable
    {
        return $this->lcobucciToken->claims()->get('exp');
    }

    /**
     * 获取令牌中指定名称的声明。
     * @param string $name 声明的名称
     * @return mixed|null 声明的值，如果不存在则返回 null
     */
    public function getClaim(string $name): mixed
    {
        return $this->lcobucciToken->claims()->get($name);
    }

    /**
     * 检查令牌是否包含指定的声明。
     */
    public function hasClaim(string $name): bool
    {
        return $this->lcobucciToken->claims()->has($name);
    }

    /**
     * 获取令牌中的所有声明。
     * @return array<string, mixed>
     */
    public function getAllClaims(): array
    {
        // lcobucci/jwt v4 返回 Claim 对象数组，v5 返回 DataSet 对象
        // 我们需要将它们转换为 key-value 数组
        $claimsArray = [];
        foreach ($this->lcobucciToken->claims()->all() as $name => $value) {
            $claimsArray[$name] = $value;
        }
        return $claimsArray;
    }

    /**
     * 允许将 Token 对象作为字符串直接使用。
     */
    public function __toString(): string
    {
        return $this->toString();
    }
}