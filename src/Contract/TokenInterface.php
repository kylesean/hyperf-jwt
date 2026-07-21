<?php

declare(strict_types=1);

namespace Kylesean\Jwt\Contract;

use DateTimeImmutable;
use Lcobucci\JWT\Token as LcobucciToken;

interface TokenInterface
{
    /**
     * Get the original lcobucci/jwt token object.
     * This allows access to the full functionality of the underlying library when needed.
     */
    public function getLcobucciToken(): LcobucciToken;

    /**
     * Get the string representation of the token.
     */
    public function toString(): string;

    /**
     * Get the token's unique identifier (jti - JWT ID).
     */
    public function getId(): ?string;

    /**
     * Get the token issuer (iss - Issuer).
     */
    public function getIssuer(): ?string;

    /**
     * Get the token audience (aud - Audience).
     * @return string[]
     */
    public function getAudience(): array;

    /**
     * Get the token subject (sub - Subject).
     */
    public function getSubject(): ?string;

    /**
     * Get the token's issued at time (iat - Issued At).
     */
    public function getIssuedAt(): ?DateTimeImmutable;

    /**
     * Get the token's not before time (nbf - Not Before).
     */
    public function getNotBefore(): ?DateTimeImmutable;

    /**
     * Get the token's expiration time (exp - Expiration Time).
     */
    public function getExpirationTime(): ?DateTimeImmutable;

    /**
     * Get the token claim by name.
     * @param string $name The name of the claim
     * @return mixed|null The value of the claim, or null if not found
     */
    public function getClaim(string $name): mixed;

    /**
     * Check if the token has the specified claim.
     */
    public function hasClaim(string $name): bool;

    /**
     * Get all claims from the token.
     * @return array<string, mixed>
     */
    public function getAllClaims(): array;
}
