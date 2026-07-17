<?php

declare(strict_types=1);

namespace Kylesean\Jwt;

use DateTimeImmutable;
use Kylesean\Jwt\Contract\TokenInterface;
use Lcobucci\JWT\Token as LcobucciPlainToken;
use Lcobucci\JWT\UnencryptedToken;
use Stringable;

readonly class Token implements TokenInterface
{
    public function __construct(
        protected UnencryptedToken $lcobucciToken
    ) {
    }

    public function getLcobucciToken(): UnencryptedToken
    {
        return $this->lcobucciToken;
    }

    public function toString(): string
    {
        return $this->lcobucciToken->toString();
    }

    public function getId(): ?string
    {
        return $this->lcobucciToken->claims()->get('jti');
    }

    public function getIssuer(): ?string
    {
        $issuer = $this->lcobucciToken->claims()->get('iss');
        return $issuer instanceof Stringable ? (string) $issuer : $issuer;
    }

    /**
     * @return string[]
     */
    public function getAudience(): array
    {
        $audience = $this->lcobucciToken->claims()->get('aud', []);
        return is_array($audience) ? $audience : [$audience];
    }

    public function getSubject(): ?string
    {
        $subject = $this->lcobucciToken->claims()->get('sub');
        return $subject instanceof Stringable ? (string) $subject : $subject;
    }

    public function getIssuedAt(): ?DateTimeImmutable
    {
        return $this->lcobucciToken->claims()->get('iat');
    }

    public function getNotBefore(): ?DateTimeImmutable
    {
        return $this->lcobucciToken->claims()->get('nbf');
    }

    public function getExpirationTime(): ?DateTimeImmutable
    {
        return $this->lcobucciToken->claims()->get('exp');
    }

    public function getClaim(string $name): mixed
    {
        return $this->lcobucciToken->claims()->get($name);
    }

    public function hasClaim(string $name): bool
    {
        return $this->lcobucciToken->claims()->has($name);
    }

    /**
     * @return array<string, mixed>
     */
    public function getAllClaims(): array
    {
        $claimsArray = [];
        foreach ($this->lcobucciToken->claims()->all() as $name => $value) {
            $claimsArray[$name] = $value;
        }
        return $claimsArray;
    }

    public function __toString(): string
    {
        return $this->toString();
    }
}