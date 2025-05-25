<?php

declare(strict_types=1);

namespace FriendsOfHyperf\Jwt\Contract;

use FriendsOfHyperf\Jwt\Contract\TokenInterface; // 我们的令牌接口

/**
 * Interface ValidatorInterface.
 *
 * 定义了验证 JWT 令牌有效性的方法。
 */
interface ValidatorInterface
{
    /**
     * 设置在验证时必须存在的声明。
     *
     * @param string[] $claims 例如 ['iss', 'sub', 'exp']
     * @return $this
     */
    public function setRequiredClaims(array $claims): self;

    /**
     * 获取必须存在的声明。
     *
     * @return string[]
     */
    public function getRequiredClaims(): array;

    /**
     * 设置验证时间声明 (exp, nbf, iat) 时允许的时钟偏差（秒）。
     *
     * @param int $leeway 时钟偏差秒数，默认为 0
     * @return $this
     */
    public function setLeeway(int $leeway): self;

    /**
     * 获取时钟偏差秒数。
     */
    public function getLeeway(): int;

    /**
     * 检查并验证令牌的结构和声明。
     * 如果令牌无效，则应抛出相应的异常。
     *
     * @param TokenInterface $token 要验证的令牌对象
     * @param bool $checkStandardClaims 是否检查标准时间声明 (exp, nbf, iat)
     * @param array<string, mixed> $expectedClaims 期望的声明及其值，例如 ['iss' => 'my-app', 'aud' => 'my-audience']
     * @throws \FriendsOfHyperf\Jwt\Exception\TokenExpiredException 如果令牌已过期
     * @throws \FriendsOfHyperf\Jwt\Exception\TokenInvalidException 如果令牌无效（例如，声明缺失或不匹配）
     * @throws \FriendsOfHyperf\Jwt\Exception\TokenNotYetValidException 如果令牌尚未生效
     * @return void
     */
    public function validate(TokenInterface $token, bool $checkStandardClaims = true, array $expectedClaims = []): void;

    /**
     * 检查令牌的标准时间声明 (exp, nbf, iat)。
     *
     * @param TokenInterface $token 要检查的令牌
     * @throws \FriendsOfHyperf\Jwt\Exception\TokenExpiredException
     * @throws \FriendsOfHyperf\Jwt\Exception\TokenNotYetValidException
     * @throws \FriendsOfHyperf\Jwt\Exception\TokenInvalidException 如果 'iat' 在 'nbf' 或 'exp' 之后
     * @return void
     */
    public function checkTimestamps(TokenInterface $token): void;

    /**
     * 检查令牌是否包含所有必需的声明，并且可选地检查声明的值。
     *
     * @param TokenInterface $token 要检查的令牌
     * @param array<string, mixed> $expectedClaimsToMatch 期望的声明及其值。如果值设为 true，则只检查声明是否存在。
     *                                        例如：['iss' => 'expected_issuer', 'sub' => true]
     *                                        表示 'iss' 必须是 'expected_issuer', 'sub' 必须存在但值不限。
     * @throws \FriendsOfHyperf\Jwt\Exception\TokenInvalidException 如果声明无效或缺失
     * @return void
     */
    public function checkClaims(TokenInterface $token, array $expectedClaimsToMatch = []): void;
}