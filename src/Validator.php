<?php

declare(strict_types=1);

namespace FriendsOfHyperf\Jwt;

use DateTimeImmutable;
use DateInterval;
use FriendsOfHyperf\Jwt\Contract\TokenInterface;
use FriendsOfHyperf\Jwt\Contract\ValidatorInterface;
use FriendsOfHyperf\Jwt\Exception\TokenExpiredException;
use FriendsOfHyperf\Jwt\Exception\TokenInvalidException;
use FriendsOfHyperf\Jwt\Exception\TokenNotYetValidException;

class Validator implements ValidatorInterface
{
    /**
     * 必需的声明列表。
     * @var string[]
     */
    protected array $requiredClaims = [];

    /**
     * 时钟偏差容忍度（秒）。
     * @var int
     */
    protected int $leeway = 0;

    /**
     * 获取当前时间。
     * 便于测试时模拟时间。
     */
    protected function getCurrentTime(): DateTimeImmutable
    {
        return new DateTimeImmutable();
    }

    /**
     * 设置在验证时必须存在的声明。
     *
     * @param string[] $claims 例如 ['iss', 'sub', 'exp']
     * @return $this
     */
    public function setRequiredClaims(array $claims): self
    {
        $this->requiredClaims = $claims;
        return $this;
    }

    /**
     * 获取必须存在的声明。
     *
     * @return string[]
     */
    public function getRequiredClaims(): array
    {
        return $this->requiredClaims;
    }

    /**
     * 设置验证时间声明 (exp, nbf, iat) 时允许的时钟偏差（秒）。
     *
     * @param int $leeway 时钟偏差秒数，默认为 0
     * @return $this
     */
    public function setLeeway(int $leeway): self
    {
        $this->leeway = $leeway > 0 ? $leeway : 0; // 确保 leeway 不为负
        return $this;
    }

    /**
     * 获取时钟偏差秒数。
     */
    public function getLeeway(): int
    {
        return $this->leeway;
    }

    /**
     * 检查并验证令牌的结构和声明。
     *
     * @param TokenInterface $token 要验证的令牌对象
     * @param bool $checkStandardClaims 是否检查标准时间声明 (exp, nbf, iat)
     * @param array<string, mixed> $expectedClaims 期望的声明及其值，例如 ['iss' => 'my-app', 'aud' => 'my-audience']
     * @throws TokenExpiredException 如果令牌已过期
     * @throws TokenInvalidException 如果令牌无效（例如，声明缺失或不匹配）
     * @throws TokenNotYetValidException 如果令牌尚未生效
     */
    public function validate(TokenInterface $token, bool $checkStandardClaims = true, array $expectedClaims = []): void
    {
        // 合并必需声明和期望声明进行检查
        // 期望声明的键名也会被认为是必需的（即使值为 true）
        $allExpectedClaims = $this->requiredClaims;
        foreach ($expectedClaims as $key => $value) {
            if (!in_array($key, $allExpectedClaims, true)) {
                $allExpectedClaims[] = $key;
            }
        }

        $this->checkClaims($token, $expectedClaims, $this->requiredClaims);

        if ($checkStandardClaims) {
            $this->checkTimestamps($token);
        }
    }

    /**
     * 检查令牌的标准时间声明 (exp, nbf, iat)。
     *
     * @throws TokenExpiredException
     * @throws TokenNotYetValidException
     * @throws TokenInvalidException 如果 'iat' 在 'nbf' 或 'exp' 之后或在未来
     */
    public function checkTimestamps(TokenInterface $token): void
    {
        $now = $this->getCurrentTime();
        $leewayInterval = new DateInterval("PT{$this->leeway}S");

        // 检查 'exp' (Expiration Time)
        if ($exp = $token->getExpirationTime()) {
            // 如果过期时间加上容差仍然早于当前时间，则令牌已过期
            if ($exp->add($leewayInterval) < $now) {
                throw new TokenExpiredException('Token has expired.');
            }
        } elseif (in_array('exp', $this->requiredClaims, true)) {
            // 如果 'exp' 是必需的但不存在
            throw new TokenInvalidException('Expiration Time (exp) claim is required but not present.');
        }

        // 检查 'nbf' (Not Before)
        if ($nbf = $token->getNotBefore()) {
            // 如果生效时间减去容差仍然晚于当前时间，则令牌尚未生效
            if ($nbf->sub($leewayInterval) > $now) {
                throw new TokenNotYetValidException('Token is not yet valid (Not Before).');
            }
        } elseif (in_array('nbf', $this->requiredClaims, true)) {
            // 如果 'nbf' 是必需的但不存在
            throw new TokenInvalidException('Not Before (nbf) claim is required but not present.');
        }

        // 检查 'iat' (Issued At)
        if ($iat = $token->getIssuedAt()) {
            // 签发时间加上容差不应晚于当前时间（即不应在未来签发）
            if ($iat->add($leewayInterval) > $now) {
                throw new TokenInvalidException('Issued At (iat) claim cannot be in the future.');
            }
            // 可选: 检查 iat 是否在 nbf 和 exp 之前（如果它们存在）
            // if ($nbf && $iat > $nbf) {
            //     throw new TokenInvalidException('Issued At (iat) claim cannot be after Not Before (nbf) claim.');
            // }
            // if ($exp && $iat > $exp) {
            //     throw new TokenInvalidException('Issued At (iat) claim cannot be after Expiration Time (exp) claim.');
            // }
        } elseif (in_array('iat', $this->requiredClaims, true)) {
            // 如果 'iat' 是必需的但不存在
            throw new TokenInvalidException('Issued At (iat) claim is required but not present.');
        }
    }

    /**
     * 检查令牌是否包含所有必需的声明，并且可选地检查声明的值。
     *
     * @param TokenInterface $token 要检查的令牌
     * @param array<string, mixed> $expectedClaimsToMatch 期望匹配其值的声明。
     *                                              例如：['iss' => 'expected_issuer']
     * @param string[] $requiredClaimKeys 仅要求存在的声明键名列表。
     * @throws TokenInvalidException 如果声明无效或缺失
     */
    public function checkClaims(TokenInterface $token, array $expectedClaimsToMatch = [], array $requiredClaimKeys = []): void
    {
        // 1. 检查所有在 $requiredClaimKeys 中声明的键是否存在
        foreach ($requiredClaimKeys as $claimName) {
            if (!$token->hasClaim($claimName)) {
                throw new TokenInvalidException(sprintf('Required claim "%s" is missing.', $claimName));
            }
        }

        // 2. 检查 $expectedClaimsToMatch 中的声明是否存在且值匹配
        foreach ($expectedClaimsToMatch as $claimName => $expectedValue) {
            if (!$token->hasClaim($claimName)) {
                throw new TokenInvalidException(sprintf('Expected claim "%s" is missing.', $claimName));
            }
            $actualValue = $token->getClaim($claimName);

            // 特殊处理 aud 声明，它可能是数组
            if ($claimName === 'aud') {
                $actualAudience = $token->getAudience(); // TokenInterface::getAudience() 应确保返回数组
                $expectedAudience = is_array($expectedValue) ? $expectedValue : [$expectedValue];
                // 检查 $expectedAudience 中的每一项是否都存在于 $actualAudience 中
                // 或者，更严格地，检查两个数组是否完全相等或 $actualAudience 是否包含所有 $expectedAudience
                // 这里我们采用宽松检查：只要预期受众中至少有一个匹配实际受众中的一个即可
                // 更严格的检查可能是: count(array_intersect($expectedAudience, $actualAudience)) > 0
                // 或者，如果配置中指定多个aud，token中也需要包含所有这些aud
                $match = false;
                foreach ($expectedAudience as $expectedAud) {
                    if (in_array((string)$expectedAud, $actualAudience, true)) {
                        $match = true;
                        break;
                    }
                }
                if (!$match) {
                    throw new TokenInvalidException(sprintf(
                        'Audience (aud) claim mismatch. Expected one of [%s] but got [%s].',
                        implode(', ', $expectedAudience),
                        implode(', ', $actualAudience)
                    ));
                }
            } elseif ($actualValue !== $expectedValue) {
                throw new TokenInvalidException(sprintf(
                    'Claim "%s" value mismatch. Expected "%s" but got "%s".',
                    $claimName,
                    is_scalar($expectedValue) ? (string) $expectedValue : gettype($expectedValue),
                    is_scalar($actualValue) ? (string) $actualValue : gettype($actualValue)
                ));
            }
        }
    }
}