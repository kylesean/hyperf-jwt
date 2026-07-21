<?php

declare(strict_types=1);

namespace Kylesean\Jwt;

use DateTimeImmutable;
use Hyperf\Contract\ConfigInterface;
use Kylesean\Jwt\Contract\PayloadFactoryInterface;
use Psr\Clock\ClockInterface;

class PayloadFactory implements PayloadFactoryInterface
{
    /**
     * Default token time-to-live in minutes.
     */
    public const DEFAULT_TTL_MINUTES = 60;

    /**
     * Default refresh window time-to-live in minutes (approximately 2 weeks).
     * 20160 minutes = 14 days = 2 weeks
     */
    public const DEFAULT_REFRESH_TTL_MINUTES = 20160;

    /**
     * Default claims that should be regenerated on token refresh.
     */
    public const DEFAULT_CLAIMS_TO_REFRESH = ['iat', 'exp', 'nbf', 'jti'];

    /**
     * Maximum allowed TTL in minutes (1 year).
     */
    public const MAX_TTL_MINUTES = 525600;

    /**
     * Maximum allowed refresh TTL in minutes (2 years).
     */
    public const MAX_REFRESH_TTL_MINUTES = 1051200;

    protected ConfigInterface $config;
    protected ?ClockInterface $clock;
    protected int $ttl;
    protected int $refreshTtl;
    protected int $nbfOffsetSeconds;
    protected string $issuer;
    /** @var string|string[] */
    protected string|array $audience;

    /** @var string[] Claims to regenerate on token refresh */
    protected array $claimsToRefresh = self::DEFAULT_CLAIMS_TO_REFRESH;

    public function __construct(ConfigInterface $config, ?ClockInterface $clock = null)
    {
        $this->config = $config;
        $this->clock = $clock;
        $this->setTtl((int) $this->config->get('jwt.ttl', self::DEFAULT_TTL_MINUTES));
        $this->setRefreshTtl((int) $this->config->get('jwt.refresh_ttl', self::DEFAULT_REFRESH_TTL_MINUTES));
        $this->setNbfOffsetSeconds((int) $this->config->get('jwt.nbf_offset_seconds', 0));
        $this->setIssuer((string) $this->config->get('jwt.issuer', 'Hyperf App'));
        $audience = $this->config->get('jwt.audience', 'Hyperf App');
        $this->setAudience(is_array($audience) ? $audience : (string) $audience);
    }

    public function setTtl(int $ttl): self
    {
        if ($ttl < 1) {
            $ttl = 1;
        } elseif ($ttl > self::MAX_TTL_MINUTES) {
            $ttl = self::MAX_TTL_MINUTES;
        }
        $this->ttl = $ttl;

        return $this;
    }

    public function getTtl(): int
    {
        return $this->ttl;
    }

    public function setRefreshTtl(int $refreshTtl): self
    {
        if ($refreshTtl < 1) {
            $refreshTtl = 1;
        } elseif ($refreshTtl > self::MAX_REFRESH_TTL_MINUTES) {
            $refreshTtl = self::MAX_REFRESH_TTL_MINUTES;
        }
        $this->refreshTtl = $refreshTtl;

        return $this;
    }

    public function getRefreshTtl(): int
    {
        return $this->refreshTtl;
    }

    public function setNbfOffsetSeconds(int $seconds): self
    {
        $this->nbfOffsetSeconds = $seconds;

        return $this;
    }

    public function getNbfOffsetSeconds(): int
    {
        return $this->nbfOffsetSeconds;
    }

    public function setIssuer(string $issuer): self
    {
        $this->issuer = $issuer;

        return $this;
    }

    public function getIssuer(): string
    {
        return $this->issuer;
    }

    public function setAudience(string|array $audience): self
    {
        $this->audience = $audience;

        return $this;
    }

    public function getAudience(): string|array
    {
        return $this->audience;
    }

    public function getCurrentTime(): DateTimeImmutable
    {
        return $this->clock?->now() ?? new DateTimeImmutable();
    }

    public function setClock(?ClockInterface $clock): self
    {
        $this->clock = $clock;

        return $this;
    }

    /**
     * @return string[]
     */
    public function getClaimsToRefresh(): array
    {
        $userClaimsToRefresh = $this->config->get('jwt.claims_to_refresh', []);

        return array_unique(array_merge($this->claimsToRefresh, is_array($userClaimsToRefresh) ? $userClaimsToRefresh : []));
    }

    /**
     * Generate a cryptographically secure unique JTI (JWT ID).
     *
     * @throws \RuntimeException If a secure random source is not available
     */
    public function generateJti(): string
    {
        try {
            return bin2hex(random_bytes(16));
        } catch (\Exception $e) {
            // JTI is security-critical and must be cryptographically secure.
            // Do NOT use weak fallbacks like uniqid() or microtime().
            throw new \RuntimeException(
                'Failed to generate a cryptographically secure JTI. ' .
                'Ensure your PHP installation has access to a secure random source. ' .
                'Original error: ' . $e->getMessage(),
                0,
                $e
            );
        }
    }
}
