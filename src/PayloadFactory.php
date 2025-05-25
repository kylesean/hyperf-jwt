<?php

declare(strict_types=1);

namespace FriendsOfHyperf\Jwt;

use DateTimeImmutable;
use DateInterval;
use FriendsOfHyperf\Jwt\Contract\PayloadFactoryInterface;
use Hyperf\Contract\ConfigInterface; // 用于获取配置

class PayloadFactory implements PayloadFactoryInterface
{
    protected ConfigInterface $config;
    protected int $ttl; // 分钟
    protected int $nbfOffsetSeconds; // 秒
    protected string $issuer;
    protected string|array $audience;


    /**
     * 需要刷新的声明列表。
     * 当刷新令牌时，这些声明会被 PayloadFactory 重新生成，而不是从旧令牌复制。
     * @var string[]
     */
    protected array $claimsToRefresh = ['iat', 'exp', 'nbf', 'jti'];

    public function __construct(ConfigInterface $config)
    {
        $this->config = $config;
        // 在构造函数中直接初始化这些属性
        $this->setTtl((int) $this->config->get('jwt.ttl', 60));
        $this->setNbfOffsetSeconds((int) $this->config->get('jwt.nbf_offset_seconds', 0));
        $this->setIssuer((string) $this->config->get('jwt.issuer', 'Hyperf App'));
        $this->setAudience($this->config->get('jwt.audience', 'Hyperf App'));
    }

    public function setTtl(int $ttl): self
    {
        $this->ttl = $ttl > 0 ? $ttl : 1;
        return $this;
    }

    public function getTtl(): int
    {
        return $this->ttl;
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
        return new DateTimeImmutable();
    }

    /**
     * 获取在刷新令牌时需要重新生成的声明列表。
     */
    public function getClaimsToRefresh(): array
    {
        $userClaimsToRefresh = $this->config->get('jwt.claims_to_refresh', []);
        return array_unique(array_merge($this->claimsToRefresh, is_array($userClaimsToRefresh) ? $userClaimsToRefresh : []));
    }

    /**
     * 生成唯一的 JWT ID (jti)。
     */
    public function generateJti(): string
    {
        try {
            return bin2hex(random_bytes(16));
        } catch (\Exception $e) {
            return uniqid('', true) . sha1(microtime(true));
        }
    }
}