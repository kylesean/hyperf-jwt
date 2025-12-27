<?php

declare(strict_types=1);

namespace FriendsOfHyperf\Jwt;

use DateTimeImmutable;
use DateInterval;
use FriendsOfHyperf\Jwt\Contract\BlacklistInterface;
use FriendsOfHyperf\Jwt\Contract\ManagerInterface;
use FriendsOfHyperf\Jwt\Contract\RequestParser\RequestParserFactoryInterface;
use FriendsOfHyperf\Jwt\Contract\TokenInterface;
use FriendsOfHyperf\Jwt\Contract\ValidatorInterface;
use FriendsOfHyperf\Jwt\Exception\JwtException;
use FriendsOfHyperf\Jwt\Exception\TokenInvalidException;
use FriendsOfHyperf\Jwt\Exception\TokenExpiredException;
use FriendsOfHyperf\Jwt\Exception\TokenNotYetValidException;
use Hyperf\Contract\ConfigInterface;
use Hyperf\HttpServer\Contract\RequestInterface as HyperfRequestInterface;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Configuration as LcobucciConfiguration;
use Lcobucci\JWT\Encoding\CannotDecodeContent;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Token\InvalidTokenStructure;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use Psr\Http\Message\ServerRequestInterface;
use FriendsOfHyperf\Jwt\Contract\PayloadFactoryInterface;

class Manager implements ManagerInterface
{
    protected Signer $signer;
    protected int $ttl;
    protected int $refreshTtl;
    protected string $issuer;
    protected string|array $audience;
    protected string $subjectClaimName = 'sub';

    public function __construct(
        protected \Hyperf\Contract\ContainerInterface $container,
        protected ConfigInterface $hyperfConfig,
        protected LcobucciConfiguration $lcobucciConfig,
        protected ValidatorInterface $validator,
        protected BlacklistInterface $blacklist,
        protected RequestParserFactoryInterface $requestParserFactory,
        protected PayloadFactoryInterface $payloadFactory,
    ) {
        $this->signer = $this->lcobucciConfig->signer();
        $this->loadConfig();
        $this->configureValidator();
    }

    protected function loadConfig(): void
    {
        $this->ttl = (int) $this->hyperfConfig->get('jwt.ttl', 60);
        $this->refreshTtl = (int) $this->hyperfConfig->get('jwt.refresh_ttl', 20160);
        $this->issuer = (string) $this->hyperfConfig->get('jwt.issuer', 'Hyperf App');
        $this->audience = $this->hyperfConfig->get('jwt.audience', 'Hyperf App');
        $this->subjectClaimName = (string) $this->hyperfConfig->get('jwt.subject_claim', 'sub');
    }

    protected function configureValidator(): void
    {
        $requiredClaims = $this->hyperfConfig->get('jwt.required_claims', []);
        $filteredRequiredClaims = [];
        if (is_array($requiredClaims)) {
            foreach ($requiredClaims as $claim => $isRequired) {
                if ($isRequired && is_string($claim) && !in_array($claim, ['exp', 'nbf', 'iat', 'iss', 'aud'])) {
                    $filteredRequiredClaims[] = $claim;
                }
            }
        }
        $this->validator->setRequiredClaims($filteredRequiredClaims);
        $this->validator->setLeeway((int) $this->hyperfConfig->get('jwt.leeway', 0));
    }

    public function issueToken(array $customClaims = [], mixed $subject = null): TokenInterface
    {
        $builder = $this->lcobucciConfig->builder();
        $now = $this->payloadFactory->getCurrentTime();

        $builder = $builder
            ->issuedBy($this->payloadFactory->getIssuer())
            ->identifiedBy($this->payloadFactory->generateJti())
            ->issuedAt($now)
            ->expiresAt($now->add(new DateInterval('PT' . $this->payloadFactory->getTtl() . 'M')));

        if ($this->payloadFactory->getNbfOffsetSeconds() > 0) {
            $builder = $builder->canOnlyBeUsedAfter(
                $now->add(new DateInterval('PT' . $this->payloadFactory->getNbfOffsetSeconds() . 'S'))
            );
        }

        $audience = $this->payloadFactory->getAudience();
        if (!empty($audience)) {
            $builder = $builder->permittedFor(...(is_array($audience) ? $audience : [$audience]));
        }

        $subjectValue = $this->getSubjectValue($customClaims, $subject);
        if ($subjectValue !== null) {
            $builder = $builder->relatedTo((string) $subjectValue);
            unset($customClaims[$this->subjectClaimName]);
        }

        foreach ($customClaims as $claim => $value) {
            if (!in_array(strtolower($claim), ['iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti'])) {
                $builder = $builder->withClaim($claim, $value);
            }
        }

        try {
            $lcobucciToken = $builder->getToken($this->lcobucciConfig->signer(), $this->lcobucciConfig->signingKey());
            return $this->container->make(Token::class, ['lcobucciToken' => $lcobucciToken]);
        } catch (\Throwable $e) {
            throw new TokenInvalidException($e->getMessage(), (int) $e->getCode(), $e);
        }
    }

    protected function getSubjectValue(array $customClaims, mixed $subject): mixed
    {
        if (array_key_exists($this->subjectClaimName, $customClaims)) {
            return $customClaims[$this->subjectClaimName];
        }

        if ($subject !== null) {
            if (is_object($subject) && method_exists($subject, 'getJwtIdentifier')) {
                return $subject->getJwtIdentifier();
            }
            if (is_scalar($subject)) {
                return $subject;
            }
        }

        return null;
    }

    public function parse(string $jwtString): ?TokenInterface
    {
        try {
            /** @var UnencryptedToken $lcobucciToken */
            $lcobucciToken = $this->lcobucciConfig->parser()->parse($jwtString);
        } catch (\Throwable $e) {
            throw new TokenInvalidException('Could not decode token: ' . $e->getMessage(), (int) $e->getCode(), $e);
        }

        // 1. 签名校验 (这是所有后续操作的前提)
        try {
            $this->lcobucciConfig->validator()->assert($lcobucciToken, new SignedWith(
                $this->lcobucciConfig->signer(),
                $this->lcobucciConfig->verificationKey()
            ));
        } catch (RequiredConstraintsViolated $e) {
            throw new TokenInvalidException('Token signature validation failed.', (int) $e->getCode(), $e);
        }

        $ourToken = $this->container->make(Token::class, ['lcobucciToken' => $lcobucciToken]);

        // 2. 显式的时间校验 (取代脆弱的字符串匹配)
        $this->performManualTimeValidation($ourToken);

        // 3. 校验其他约束 (iss, aud 等)
        $otherConstraints = $this->getVerificationConstraints();
        try {
            $this->lcobucciConfig->validator()->assert($lcobucciToken, ...$otherConstraints);
        } catch (RequiredConstraintsViolated $e) {
            $this->handleValidationFailure($e);
        }

        if ($this->hyperfConfig->get('jwt.blacklist_enabled', true) && $this->blacklist->has($ourToken)) {
            throw new TokenInvalidException('Token has been blacklisted.');
        }

        $this->validator->validate($ourToken, true, []);

        return $ourToken;
    }

    /**
     * 执行显式的时间校验，避免解析错误消息字符串。
     */
    protected function performManualTimeValidation(TokenInterface $token): void
    {
        $now = $this->payloadFactory->getCurrentTime();
        $leeway = $this->validator->getLeeway();

        // 验证过期时间 (exp)
        $exp = $token->getExpirationTime();
        if ($exp && ($exp->getTimestamp() + $leeway) < $now->getTimestamp()) {
            throw new TokenExpiredException('The token is expired.');
        }

        // 验证生效时间 (nbf)
        $nbf = $token->getNotBefore();
        if ($nbf && ($nbf->getTimestamp() - $leeway) > $now->getTimestamp()) {
            throw new TokenNotYetValidException('The token is not yet valid.');
        }

        // 验证签发时间 (iat) - 确保不晚于当前时间太久
        $iat = $token->getIssuedAt();
        if ($iat && ($iat->getTimestamp() - $leeway) > $now->getTimestamp()) {
            throw new TokenInvalidException('The token was issued in the future.');
        }
    }

    protected function getVerificationConstraints(): array
    {
        $constraints = [];

        if ($this->hyperfConfig->get('jwt.required_claims.iss', false) && $this->issuer) {
            $constraints[] = new \Lcobucci\JWT\Validation\Constraint\IssuedBy($this->issuer);
        }

        $audiences = is_array($this->audience) ? $this->audience : [$this->audience];
        if ($this->hyperfConfig->get('jwt.required_claims.aud', false) && !empty($audiences) && count($audiences) === 1) {
            $constraints[] = new \Lcobucci\JWT\Validation\Constraint\PermittedFor($audiences[0]);
        }

        return $constraints;
    }

    protected function handleValidationFailure(RequiredConstraintsViolated $e): void
    {
        // 现在这里只处理非时间类的辅助校验失败（如 iss, aud 等）
        $firstMessage = $e->violations()[0]?->getMessage() ?? 'Token validation failed.';
        throw new TokenInvalidException($firstMessage, (int) $e->getCode(), $e);
    }

    public function parseTokenFromRequest(?ServerRequestInterface $request = null): ?TokenInterface
    {
        if (!$request && $this->container->has(HyperfRequestInterface::class)) {
            $request = $this->container->get(HyperfRequestInterface::class);
        } elseif (!$request) {
            return null;
        }

        $parserChain = $this->requestParserFactory->getParserChain();
        $jwtString = null;

        foreach ($parserChain as $parser) {
            $jwtString = $parser->parse($request);
            if ($jwtString !== null) {
                break;
            }
        }

        if ($jwtString === null) {
            return null;
        }

        return $this->parse($jwtString);
    }

    public function refreshToken(string $oldTokenString, bool $forceForever = false, bool $resetClaims = false): TokenInterface
    {
        if (!$this->hyperfConfig->get('jwt.blacklist_enabled', true)) {
            throw new JwtException('Token refresh is not available when blacklist is disabled.');
        }

        try {
            /** @var UnencryptedToken $lcobucciOldToken */
            $lcobucciOldToken = $this->lcobucciConfig->parser()->parse($oldTokenString);
        } catch (\Throwable $e) {
            throw new TokenInvalidException('Could not decode old token for refresh: ' . $e->getMessage(), (int) $e->getCode(), $e);
        }

        $constraints = [new SignedWith($this->lcobucciConfig->signer(), $this->lcobucciConfig->verificationKey())];
        try {
            $this->lcobucciConfig->validator()->assert($lcobucciOldToken, ...$constraints);
        } catch (RequiredConstraintsViolated $e) {
            throw new TokenInvalidException('Old token signature validation failed: ' . $e->getMessage(), (int) $e->getCode(), $e);
        }

        $oldToken = $this->container->make(Token::class, ['lcobucciToken' => $lcobucciOldToken]);

        if ($this->blacklist->has($oldToken)) {
            throw new TokenInvalidException('Token has been blacklisted and cannot be refreshed.');
        }

        $exp = $oldToken->getExpirationTime();
        if (!$exp) {
            throw new TokenInvalidException('Old token does not have an expiration time.');
        }

        $now = new DateTimeImmutable();
        $refreshWindowEnd = $exp->add(new DateInterval("PT{$this->refreshTtl}M"));

        if ($now > $refreshWindowEnd) {
            throw new TokenExpiredException('Token has expired and is outside the refresh window.');
        }

        $blacklistTtlSeconds = max(1, $refreshWindowEnd->getTimestamp() - $now->getTimestamp());
        $this->blacklist->add($oldToken, $blacklistTtlSeconds);

        $newPayload = [];
        if (!$resetClaims) {
            $allOldClaims = $oldToken->getAllClaims();
            $claimsToExclude = ['iat', 'exp', 'nbf', 'jti', 'iss', 'aud'];
            foreach ($allOldClaims as $key => $value) {
                if (!in_array($key, $claimsToExclude, true)) {
                    $newPayload[$key] = $value;
                }
            }
            if ($oldToken->getSubject() && !isset($newPayload[$this->subjectClaimName])) {
                $newPayload[$this->subjectClaimName] = $oldToken->getSubject();
            }
        }

        return $this->issueToken($newPayload);
    }

    public function invalidate(TokenInterface $token, bool $forceForever = false): self
    {
        if (!$this->hyperfConfig->get('jwt.blacklist_enabled', true)) {
            return $this;
        }

        try {
            $ttl = $forceForever ? ($this->refreshTtl * 60 * 24 * 365) : null;
            if (!$this->blacklist->add($token, $ttl)) {
                if (empty($token->getId())) {
                    throw new JwtException('Token does not have a jti claim and cannot be reliably blacklisted.');
                }
                throw new JwtException('Failed to add token to blacklist.');
            }
        } catch (\Throwable $e) {
            throw new JwtException('Error while invalidating token: ' . $e->getMessage(), (int) $e->getCode(), $e);
        }
        return $this;
    }

    public function getValidator(): ValidatorInterface
    {
        return $this->validator;
    }

    public function setValidator(ValidatorInterface $validator): self
    {
        $this->validator = $validator;
        $this->configureValidator();
        return $this;
    }

    public function getBlacklist(): BlacklistInterface
    {
        return $this->blacklist;
    }

    public function setBlacklist(BlacklistInterface $blacklist): self
    {
        $this->blacklist = $blacklist;
        return $this;
    }

    public function getPayloadFactory(): PayloadFactoryInterface
    {
        return $this->payloadFactory;
    }

    public function setPayloadFactory(PayloadFactoryInterface $payloadFactory): self
    {
        $this->payloadFactory = $payloadFactory;
        return $this;
    }

    public function getRequestParserFactory(): RequestParserFactoryInterface
    {
        return $this->requestParserFactory;
    }

    public function setRequestParserFactory(RequestParserFactoryInterface $requestParserFactory): self
    {
        $this->requestParserFactory = $requestParserFactory;
        return $this;
    }

    public function getLcobucciConfig(): LcobucciConfiguration
    {
        return $this->lcobucciConfig;
    }

    public function getSigner(): Signer
    {
        return $this->signer;
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

    public function getRefreshTtl(): int
    {
        return $this->refreshTtl;
    }

    protected function generateJti(): string
    {
        try {
            return bin2hex(random_bytes(16));
        } catch (\Exception $e) {
            return uniqid('', true) . sha1((string) microtime(true));
        }
    }

    public function getSubjectClaimKey(): string
    {
        return $this->subjectClaimName;
    }
}