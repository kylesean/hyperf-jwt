<?php

declare(strict_types=1);

namespace Kylesean\Jwt\Contract;

use Kylesean\Jwt\Contract\TokenInterface;

/**
 * Interface ValidatorInterface.
 */
interface ValidatorInterface
{
    /**
     * Set the required claims for validation.
     *
     * @param string[] $claims 例如 ['iss', 'sub', 'exp']
     * @return $this
     */
    public function setRequiredClaims(array $claims): self;

    /**
     * Get the required claims.
     *
     * @return string[]
     */
    public function getRequiredClaims(): array;

    /**
     * Set the clock skew in seconds for validating time-related claims (exp, nbf, iat).
     *
     * @param int $leeway Clock skew in seconds, defaults to 0
     * @return $this
     */
    public function setLeeway(int $leeway): self;

    /**
     * Get the clock skew in seconds.
     */
    public function getLeeway(): int;

    /**
     * Check and validate the token's structure and claims.
     *
     * @param TokenInterface $token
     * @param bool $checkStandardClaims
     * @param array<string, mixed> $expectedClaims
     * @throws \Kylesean\Jwt\Exception\TokenExpiredException
     * @throws \Kylesean\Jwt\Exception\TokenInvalidException
     * @throws \Kylesean\Jwt\Exception\TokenNotYetValidException
     * @return void
     */
    public function validate(TokenInterface $token, bool $checkStandardClaims = true, array $expectedClaims = []): void;

    /**
     * Check the token's standard time-related claims (exp, nbf, iat).
     *
     * @param TokenInterface $token
     * @throws \Kylesean\Jwt\Exception\TokenExpiredException
     * @throws \Kylesean\Jwt\Exception\TokenNotYetValidException
     * @throws \Kylesean\Jwt\Exception\TokenInvalidException
     * @return void
     */
    public function checkTimestamps(TokenInterface $token): void;

    /**
     * Check if the token contains all required claims, and optionally check claim values.
     *
     * @param TokenInterface $token The token to check
     * @param array<string, mixed> $expectedClaimsToMatch The expected claims and their values. If the value is set to true, only check for the existence of the claim.
     *                                        For example: ['iss' => 'expected_issuer', 'sub' => true]
     *                                        Means 'iss' must be 'expected_issuer', and 'sub' must exist but its value is not limited.
     * @param string[] $requiredClaimKeys Array of claim keys that must exist in the token.
     * @throws \Kylesean\Jwt\Exception\TokenInvalidException If the claim is invalid or missing
     * @return void
     */
    public function checkClaims(TokenInterface $token, array $expectedClaimsToMatch = [], array $requiredClaimKeys = []): void;
}