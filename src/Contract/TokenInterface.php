<?php

declare(strict_types=1);

namespace FriendsOfHyperf\Jwt\Contract;

use DateTimeImmutable;
use Lcobucci\JWT\Token as LcobucciToken; // 引入底层库的 Token 类型

interface TokenInterface
{
    /**
     * 获取原始的 lcobucci/jwt 令牌对象。
     * 这允许在需要时访问底层库的全部功能。
     */
    public function getLcobucciToken(): LcobucciToken;

    /**
     * 获取令牌的字符串表示形式。
     */
    public function toString(): string;

    /**
     * 获取令牌的唯一标识符 (jti - JWT ID)。
     */
    public function getId(): ?string;

    /**
     * 获取令牌的签发者 (iss - Issuer)。
     */
    public function getIssuer(): ?string;

    /**
     * 获取令牌的受众 (aud - Audience)。
     * @return string[]
     */
    public function getAudience(): array;

    /**
     * 获取令牌的主题 (sub - Subject)。
     */
    public function getSubject(): ?string;

    /**
     * 获取令牌的签发时间 (iat - Issued At)。
     */
    public function getIssuedAt(): ?DateTimeImmutable;

    /**
     * 获取令牌的生效时间 (nbf - Not Before)。
     */
    public function getNotBefore(): ?DateTimeImmutable;

    /**
     * 获取令牌的过期时间 (exp - Expiration Time)。
     */
    public function getExpirationTime(): ?DateTimeImmutable;

    /**
     * 获取令牌中指定名称的声明。
     * @param string $name 声明的名称
     * @return mixed|null 声明的值，如果不存在则返回 null
     */
    public function getClaim(string $name): mixed;

    /**
     * 检查令牌是否包含指定的声明。
     */
    public function hasClaim(string $name): bool;

    /**
     * 获取令牌中的所有声明。
     * @return array<string, mixed>
     */
    public function getAllClaims(): array;
}