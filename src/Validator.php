<?php

declare(strict_types=1);

namespace Kylesean\Jwt;

use DateTimeImmutable;
use DateInterval;
use Kylesean\Jwt\Contract\TokenInterface;
use Kylesean\Jwt\Contract\ValidatorInterface;
use Kylesean\Jwt\Exception\TokenExpiredException;
use Kylesean\Jwt\Exception\TokenInvalidException;
use Kylesean\Jwt\Exception\TokenNotYetValidException;
use Psr\Clock\ClockInterface;

class Validator implements ValidatorInterface
{
    /** @var string[] */
    protected array $requiredClaims = [];

    /** Clock skew tolerance in seconds */
    protected int $leeway = 0;

    protected ?ClockInterface $clock = null;

    public function setClock(?ClockInterface $clock): self
    {
        $this->clock = $clock;
        return $this;
    }

    protected function getCurrentTime(): DateTimeImmutable
    {
        return $this->clock?->now() ?? new DateTimeImmutable();
    }

    /**
     * {@inheritdoc}
     */
    public function setRequiredClaims(array $claims): self
    {
        $this->requiredClaims = $claims;
        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getRequiredClaims(): array
    {
        return $this->requiredClaims;
    }

    /**
     * {@inheritdoc}
     */
    public function setLeeway(int $leeway): self
    {
        $this->leeway = $leeway > 0 ? $leeway : 0;
        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getLeeway(): int
    {
        return $this->leeway;
    }

    /**
     * {@inheritdoc}
     */
    public function validate(TokenInterface $token, bool $checkStandardClaims = true, array $expectedClaims = []): void
    {
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
     * {@inheritdoc}
     */
    public function checkTimestamps(TokenInterface $token): void
    {
        $now = $this->getCurrentTime();
        $leewayInterval = new DateInterval("PT{$this->leeway}S");

        if ($exp = $token->getExpirationTime()) {
            if ($exp->add($leewayInterval) < $now) {
                throw new TokenExpiredException('Token has expired.', $exp);
            }
        } elseif (in_array('exp', $this->requiredClaims, true)) {
            throw new TokenInvalidException('Expiration Time (exp) claim is required but not present.');
        }

        if ($nbf = $token->getNotBefore()) {
            if ($nbf->sub($leewayInterval) > $now) {
                throw new TokenNotYetValidException('Token is not yet valid (Not Before).', $nbf);
            }
        } elseif (in_array('nbf', $this->requiredClaims, true)) {
            throw new TokenInvalidException('Not Before (nbf) claim is required but not present.');
        }

        if ($iat = $token->getIssuedAt()) {
            if ($iat->sub($leewayInterval) > $now) {
                throw new TokenInvalidException('Issued At (iat) claim cannot be in the future.');
            }
        } elseif (in_array('iat', $this->requiredClaims, true)) {
            throw new TokenInvalidException('Issued At (iat) claim is required but not present.');
        }
    }

    /**
     * {@inheritdoc}
     */
    public function checkClaims(TokenInterface $token, array $expectedClaimsToMatch = [], array $requiredClaimKeys = []): void
    {
        foreach ($requiredClaimKeys as $claimName) {
            if (!$token->hasClaim($claimName)) {
                throw new TokenInvalidException(sprintf('Required claim "%s" is missing.', $claimName));
            }
        }

        foreach ($expectedClaimsToMatch as $claimName => $expectedValue) {
            if (!$token->hasClaim($claimName)) {
                throw new TokenInvalidException(sprintf('Expected claim "%s" is missing.', $claimName));
            }
            $actualValue = $token->getClaim($claimName);

            if ($claimName === 'aud') {
                $actualAudience = $token->getAudience();
                $expectedAudience = is_array($expectedValue) ? $expectedValue : [$expectedValue];
                $match = false;
                foreach ($expectedAudience as $expectedAud) {
                    if (in_array((string) $expectedAud, $actualAudience, true)) {
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