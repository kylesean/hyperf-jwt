<?php

declare(strict_types=1);

namespace FriendsOfHyperf\Jwt\Contract;

use DateTimeImmutable;

interface PayloadFactoryInterface
{
    /**
     * 设置令牌的有效期 (Time To Live)，单位为分钟。
     * 工厂需要知道 TTL 来计算 'exp' 声明。
     *
     * @return $this
     */
    public function setTtl(int $ttl): self;

    /**
     * 获取令牌的有效期（分钟）。
     */
    public function getTtl(): int;

    /**
     * 设置令牌的 'nbf' (Not Before) 相对于 'iat' (Issued At) 的偏移量（秒）。
     *
     * @return $this
     */
    public function setNbfOffsetSeconds(int $seconds): self;

    /**
     * 获取 'nbf' 偏移量（秒）。
     */
    public function getNbfOffsetSeconds(): int;

    /**
     * 设置令牌的签发者 (iss)。
     * @return $this
     */
    public function setIssuer(string $issuer): self;

    /**
     * 获取令牌的签发者。
     */
    public function getIssuer(): string;

    /**
     * 设置令牌的受众 (aud)。
     * @param string|string[] $audience
     * @return $this
     */
    public function setAudience(string|array $audience): self;

    /**
     * 获取令牌的受众。
     * @return string|string[]
     */
    public function getAudience(): string|array;

    /**
     * 获取当前时间，用于生成时间相关的声明。
     * 允许覆盖以方便测试。
     */
    public function getCurrentTime(): DateTimeImmutable;

    public function generateJti(): string;

    public function getClaimsToRefresh(): array;

    // public function processCustomClaims(array $customClaims, mixed $subject = null): array; // 可选的辅助方法
}