<?php

declare(strict_types=1);

namespace Kylesean\Jwt;

use DateTimeImmutable;
use DateInterval;
use Kylesean\Jwt\Contract\BlacklistInterface;
use Kylesean\Jwt\Contract\ManagerInterface;
use Kylesean\Jwt\Contract\RequestParser\RequestParserFactoryInterface;
use Kylesean\Jwt\Contract\TokenInterface;
use Kylesean\Jwt\Contract\ValidatorInterface;
use Kylesean\Jwt\Exception\JwtException;
use Kylesean\Jwt\Exception\TokenInvalidException;
use Kylesean\Jwt\Exception\TokenExpiredException;
use Kylesean\Jwt\Exception\TokenNotYetValidException;
use Hyperf\Contract\ConfigInterface;
use Hyperf\HttpServer\Contract\RequestInterface as HyperfRequestInterface;
use Lcobucci\JWT\Configuration as LcobucciConfiguration;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ServerRequestInterface;
use Kylesean\Jwt\Contract\PayloadFactoryInterface;

class Manager implements ManagerInterface
{
    protected Signer $signer;
    protected string $subjectClaimName = 'sub';
    protected ClockInterface $clock;

    public function __construct(
        protected \Hyperf\Contract\ContainerInterface $container,
        protected ConfigInterface $hyperfConfig,
        protected LcobucciConfiguration $lcobucciConfig,
        protected ValidatorInterface $validator,
        protected BlacklistInterface $blacklist,
        protected RequestParserFactoryInterface $requestParserFactory,
        protected PayloadFactoryInterface $payloadFactory,
        ?ClockInterface $clock = null,
    ) {
        $this->signer = $this->lcobucciConfig->signer();
        $this->clock = $clock ?? new class implements ClockInterface {
            public function now(): DateTimeImmutable
            {
                return new DateTimeImmutable();
            }
        };
        $this->loadConfig();
        $this->configureValidator();
    }

    /**
     * Load configuration that is specific to Manager (not delegated to PayloadFactory).
     */
    protected function loadConfig(): void
    {
        // Most config is now delegated to PayloadFactory to avoid duplication
        // Only Manager-specific config is loaded here
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
        $this->validator->setClock($this->clock);
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

    /**
     * @param array<string, mixed> $customClaims
     */
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

        // 1. Signature validation (prerequisite for all subsequent operations)
        try {
            $this->lcobucciConfig->validator()->assert($lcobucciToken, new SignedWith(
                $this->lcobucciConfig->signer(),
                $this->lcobucciConfig->verificationKey()
            ));
        } catch (RequiredConstraintsViolated $e) {
            throw new TokenInvalidException('Token signature validation failed.', (int) $e->getCode(), $e);
        }

        $ourToken = $this->container->make(Token::class, ['lcobucciToken' => $lcobucciToken]);

        // 2. Strongly typed standard timestamp validation (exp, nbf, iat)
        $this->validator->checkTimestamps($ourToken);

        // 3. Blacklist check
        if ($this->hyperfConfig->get('jwt.blacklist_enabled', true) && $this->blacklist->has($ourToken)) {
            throw new TokenInvalidException('Token has been blacklisted.');
        }

        // 4. Expected claims validation (iss, aud, custom claims)
        $expectedClaims = [];
        if ($this->hyperfConfig->get('jwt.required_claims.iss', false)) {
            $expectedClaims['iss'] = $this->payloadFactory->getIssuer();
        }
        if ($this->hyperfConfig->get('jwt.required_claims.aud', false)) {
            $expectedClaims['aud'] = $this->payloadFactory->getAudience();
        }

        $this->validator->checkClaims($ourToken, $expectedClaims, $this->validator->getRequiredClaims());

        return $ourToken;
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

        $now = $this->clock->now();
        $refreshTtl = $this->payloadFactory->getRefreshTtl();
        $refreshWindowEnd = $exp->add(new DateInterval("PT{$refreshTtl}M"));

        if ($now > $refreshWindowEnd) {
            throw new TokenExpiredException('Token has expired and is outside the refresh window.');
        }

        $blacklistTtlSeconds = $forceForever 
            ? 31536000 
            : max(1, $refreshWindowEnd->getTimestamp() - $now->getTimestamp());
            
        $concurrencyGracePeriod = (int) $this->hyperfConfig->get('jwt.blacklist_concurrency_grace_period', 0);
        
        if (!$this->blacklist->add($oldToken, $blacklistTtlSeconds, $concurrencyGracePeriod)) {
            if (!$forceForever && empty($oldToken->getId())) {
                throw new TokenInvalidException('Old token does not have a jti claim and cannot be reliably blacklisted.');
            }
            throw new JwtException('Failed to add old token to blacklist.');
        }

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
            $ttl = $forceForever ? 31536000 : null; // 1 year
            if (!$this->blacklist->add($token, $ttl, 0)) {
                if (empty($token->getId())) {
                    throw new JwtException('Token does not have a jti claim and cannot be reliably blacklisted.');
                }
                throw new JwtException('Failed to add token to blacklist.');
            }
        } catch (JwtException $e) {
            throw $e; // Re-throw our own exceptions directly without wrapping
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
        $this->payloadFactory->setTtl($ttl);
        return $this;
    }

    public function getTtl(): int
    {
        return $this->payloadFactory->getTtl();
    }

    public function getRefreshTtl(): int
    {
        return $this->payloadFactory->getRefreshTtl();
    }



    public function getSubjectClaimKey(): string
    {
        return $this->subjectClaimName;
    }
}