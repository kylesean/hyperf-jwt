<?php

declare(strict_types=1);

namespace Kylesean\Jwt\Contract;

use DateTimeImmutable;

interface PayloadFactoryInterface
{
    /**
     * Set the token time-to-live (TTL) in minutes.
     * The factory needs to know the TTL to calculate the 'exp' claim.
     *
     * @param int $ttl Time-to-live in minutes
     * @return $this
     */
    public function setTtl(int $ttl): self;

    /**
     * Get the token time-to-live (TTL) in minutes.
     */
    public function getTtl(): int;

    /**
     * Get the token refresh time-to-live (Refresh TTL) in minutes.
     * Expired tokens can still be refreshed within this window.
     */
    public function getRefreshTtl(): int;

    /**
     * Set the 'nbf' (Not Before) offset in seconds relative to 'iat' (Issued At).
     * A positive value delays the validity start; a negative value makes the token
     * valid that many seconds before 'iat' (clock-skew tolerance).
     *
     * @return $this
     */
    public function setNbfOffsetSeconds(int $seconds): self;

    /**
     * Get the 'nbf' offset in seconds.
     */
    public function getNbfOffsetSeconds(): int;

    /**
     * Set the token issuer (iss).
     * @return $this
     */
    public function setIssuer(string $issuer): self;

    /**
     * Get the token issuer.
     */
    public function getIssuer(): string;

    /**
     * Set the token audience (aud).
     * @param string|string[] $audience
     * @return $this
     */
    public function setAudience(string|array $audience): self;

    /**
     * Get the token audience.
     * @return string|string[]
     */
    public function getAudience(): string|array;

    /**
     * Get the current time used for generating time-related claims.
     * Allows overriding for testing purposes.
     */
    public function getCurrentTime(): DateTimeImmutable;

    public function generateJti(): string;

    /**
     * Get the claims that should be refreshed when refreshing a token.
     *
     * @return string[]
     */
    public function getClaimsToRefresh(): array;

    // public function processCustomClaims(array $customClaims, mixed $subject = null): array; // Optional helper method
}
