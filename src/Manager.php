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

// Hyperf 当前请求接口
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Configuration as LcobucciConfiguration;
use Lcobucci\JWT\Encoding\CannotDecodeContent;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\InvalidTokenStructure;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;

// For iss, aud, iat, nbf, exp standard validation
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ServerRequestInterface;
use FriendsOfHyperf\Jwt\Contract\PayloadFactoryInterface;
use Lcobucci\JWT\Signer\CannotSignPayload;

class Manager implements ManagerInterface
{
    protected LcobucciConfiguration $lcobucciConfig;
    protected Signer $signer;
    protected ValidatorInterface $validator;
    protected BlacklistInterface $blacklist;
    protected RequestParserFactoryInterface $requestParserFactory;
    protected ContainerInterface $container;
    protected ConfigInterface $hyperfConfig; // Hyperf 的配置接口
    protected PayloadFactoryInterface $payloadFactory;
    protected int $ttl; // 令牌有效期（分钟）
    protected int $refreshTtl; // 令牌刷新期（分钟）
    protected string $issuer; // 签发者
    protected string|array $audience; // 受众
    protected string $subjectClaimName = 'sub'; // 主体声明的名称


    /**
     * 构造函数.
     *
     * @throws JwtException 如果配置无效或无法初始化签名器/密钥
     */
    public function __construct(
        ContainerInterface            $container,
        ConfigInterface               $hyperfConfig, // 注入 Hyperf 的 ConfigInterface
        ValidatorInterface            $validator,
        BlacklistInterface            $blacklist,
        RequestParserFactoryInterface $requestParserFactory,
        PayloadFactoryInterface       $payloadFactory,
    )
    {
        $this->container = $container;
        $this->hyperfConfig = $hyperfConfig;
        $this->validator = $validator;
        $this->blacklist = $blacklist;
        $this->requestParserFactory = $requestParserFactory;
        $this->payloadFactory = $payloadFactory;
        // $this->loadConfig(); // loadConfig 中的 ttl, nbf_offset, issuer, audience 等现在由 PayloadFactory 管理
        // 但是 Manager 可能仍然需要 refreshTtl 和 subjectClaimName 等，所以 loadConfig 还需要保留部分
        $this->loadConfig();
        $this->initLcobucciConfiguration();
        $this->configureValidator();
    }

    protected function loadManagerSpecificConfig(): void
    {
        $this->refreshTtl = (int)$this->hyperfConfig->get('jwt.refresh_ttl', 20160);
        $this->subjectClaimName = (string)$this->hyperfConfig->get('jwt.subject_claim', 'sub');
    }

    /**
     * 从 Hyperf 配置中加载 JWT 相关设置。
     */
    protected function loadConfig(): void
    {
        $this->ttl = (int)$this->hyperfConfig->get('jwt.ttl', 60);
        $this->refreshTtl = (int)$this->hyperfConfig->get('jwt.refresh_ttl', 20160);
        $this->issuer = (string)$this->hyperfConfig->get('jwt.issuer', 'Hyperf App');
        $this->audience = $this->hyperfConfig->get('jwt.audience', 'Hyperf App');
        $this->subjectClaimName = (string)$this->hyperfConfig->get('jwt.subject_claim', 'sub');
    }

    /**
     * 初始化 lcobucci/jwt 的 Configuration 对象。
     * @throws JwtException
     */
    protected function initLcobucciConfiguration(): void
    {
        // 检查是否有自定义的 lcobucci/jwt 配置工厂
        $customFactoryCallable = $this->hyperfConfig->get('jwt.lcobucci_config_factory');
        if ($customFactoryCallable) {
            if (is_callable($customFactoryCallable)) {
                $this->lcobucciConfig = call_user_func($customFactoryCallable, $this->container);
            } elseif (is_string($customFactoryCallable) && $this->container->has($customFactoryCallable)) {
                $this->lcobucciConfig = $this->container->get($customFactoryCallable);
            } else {
                throw new JwtException('Invalid jwt.lcobucci_config_factory configuration.');
            }
            $this->signer = $this->lcobucciConfig->signer(); // 从自定义配置中获取签名器
            return;
        }

        // 手动构建 LcobucciConfiguration
        $algoClass = $this->hyperfConfig->get('jwt.algo', \Lcobucci\JWT\Signer\Hmac\Sha256::class);
        if (!class_exists($algoClass) || !is_subclass_of($algoClass, Signer::class)) {
            throw new JwtException("Invalid JWT algorithm class: {$algoClass}");
        }
        $this->signer = $this->container->make($algoClass);

        if ($this->signer instanceof Signer\Hmac) { // HMAC 对称加密
            $secret = (string)$this->hyperfConfig->get('jwt.secret');
            if (empty($secret)) {
                throw new JwtException('JWT secret is not configured for HMAC algorithm.');
            }
            $key = InMemory::plainText($secret);
            $this->lcobucciConfig = LcobucciConfiguration::forSymmetricSigner($this->signer, $key);
        } elseif ($this->signer instanceof Signer\Rsa || $this->signer instanceof Signer\Ecdsa) { // RSA 或 ECDSA 非对称加密
            $privateKeyPathOrContent = (string)$this->hyperfConfig->get('jwt.keys.private');
            $publicKeyPathOrContent = (string)$this->hyperfConfig->get('jwt.keys.public');
            $passphraseConfigValue = $this->hyperfConfig->get('jwt.keys.passphrase'); // 可能是 null, 空字符串, 或实际密码

            if (empty($privateKeyPathOrContent) || empty($publicKeyPathOrContent)) {
                throw new JwtException('Private or public key is not configured for asymmetric algorithm.');
            }
            // 处理 passphrase: Lcobucci 需要 null 如果密钥未加密，或密码字符串如果密钥已加密。
            // 空字符串通常意味着未加密，所以我们将其转为 null。
            $privateKeyPassphrase = ($passphraseConfigValue === '' || $passphraseConfigValue === null) ? null : (string)$passphraseConfigValue;

            $privateKey = str_starts_with($privateKeyPathOrContent, 'file://')
                ? InMemory::file(substr($privateKeyPathOrContent, 7), (string)$privateKeyPassphrase)
                : InMemory::plainText($privateKeyPathOrContent, (string)$privateKeyPassphrase);
            $publicKey = str_starts_with($publicKeyPathOrContent, 'file://')
                ? InMemory::file(substr($publicKeyPathOrContent, 7))
                : InMemory::plainText($publicKeyPathOrContent);

            $this->lcobucciConfig = LcobucciConfiguration::forAsymmetricSigner($this->signer, $privateKey, $publicKey);
        } else {
            throw new JwtException("Unsupported JWT signer type: " . get_class($this->signer));
        }
    }

    /**
     * 根据配置设置验证器参数。
     */
    protected function configureValidator(): void
    {
        $requiredClaims = $this->hyperfConfig->get('jwt.required_claims', []);
        // 过滤掉非字符串的配置项，并确保时间声明不在其中，因为它们由 Lcobucci 处理
        $filteredRequiredClaims = [];
        if (is_array($requiredClaims)) {
            foreach ($requiredClaims as $claim => $isRequired) {
                if ($isRequired && is_string($claim) && !in_array($claim, ['exp', 'nbf', 'iat', 'iss', 'aud'])) {
                    $filteredRequiredClaims[] = $claim;
                }
            }
        }
        $this->validator->setRequiredClaims($filteredRequiredClaims);
        $this->validator->setLeeway((int)$this->hyperfConfig->get('jwt.leeway', 0));
    }


    /**
     * {@inheritdoc}
     */
    public function issueToken(array $customClaims = [], mixed $subject = null): TokenInterface
    {
        $builder = $this->lcobucciConfig->builder();
        // 1. 设置标准声明，从 PayloadFactory 获取值
        $now = $this->payloadFactory->getCurrentTime();
        $nbfTime = $now;
        if ($this->payloadFactory->getNbfOffsetSeconds() > 0) {
            $nbfTime = $now->add(new DateInterval("PT" . $this->payloadFactory->getNbfOffsetSeconds() . "S"));
        }
        $expTime = $now->add(new DateInterval("PT" . $this->payloadFactory->getTtl() . "M"));

        $builder = $builder
            ->issuedBy($this->payloadFactory->getIssuer())
            ->identifiedBy($this->payloadFactory->generateJti())
            ->issuedAt($now)
            ->canOnlyBeUsedAfter($nbfTime)
            ->expiresAt($expTime);

        // 设置 Audience (aud)
        $audience = $this->payloadFactory->getAudience();
        if (!empty($audience)) {
            $builder = $builder->permittedFor(...(is_array($audience) ? $audience : [$audience]));
        }

        // 2. 设置 Subject (sub)
        $subjectClaimName = (string)$this->hyperfConfig->get('jwt.subject_claim', 'sub');
        $subjectValueToSet = null;

        // 优先使用 $customClaims 中提供的 subject (如果键名匹配)
        if (array_key_exists($subjectClaimName, $customClaims)) {
            $subjectValueToSet = $customClaims[$subjectClaimName];
            unset($customClaims[$subjectClaimName]); // 从 customClaims 中移除，避免重复添加
        } elseif ($subject !== null) { // 否则，如果 $subject 参数提供了值
            if (is_object($subject) && method_exists($subject, 'getJwtIdentifier')) {
                $subjectValueToSet = $subject->getJwtIdentifier();
            } elseif (is_scalar($subject)) {
                $subjectValueToSet = $subject;
            }
        }

        if ($subjectValueToSet !== null) {
            $builder = $builder->relatedTo((string)$subjectValueToSet);
        }

        // 3. 设置剩余的自定义声明 (此时 $customClaims 中不应再包含标准声明的键)
        foreach ($customClaims as $claim => $value) {
            // 这里加一个检查，确保我们不会意外地用 withClaim 设置已知有专用方法的注册声明
            // (虽然理论上此时 $customClaims 已被清理)
            if (in_array(strtolower($claim), ['iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti'])) {
                // 可以选择记录一个警告，或者如果严格则抛出异常
                // logger()->warning("Attempted to set registered claim '{$claim}' using withClaim(). It should be set via its dedicated builder method or from PayloadFactory defaults.");
                // 为避免潜在冲突，可以选择跳过或确保不覆盖
                continue;
            }
            $builder = $builder->withClaim($claim, $value);
        }

        try {
            $lcobucciToken = $builder->getToken($this->lcobucciConfig->signer(), $this->lcobucciConfig->signingKey());
        } catch (CannotSignPayload|InvalidTokenStructure|RequiredConstraintsViolated|CannotDecodeContent $e) {
            throw new TokenInvalidException($e->getMessage(), (int)$e->getCode(), $e);
        } catch (\Throwable $e) {
            // 作为最后的保障，捕获任何其他可能发生的错误
            throw new JwtException(
                'An unexpected error occurred while creating the token: ' . $e->getMessage(),
                (int)$e->getCode(),
                $e
            );
        }
        return $this->container->make(Token::class, ['lcobucciToken' => $lcobucciToken]);
    }

    /**
     * {@inheritdoc}
     */
    public function parse(string $jwtString): ?TokenInterface
    {
        try {
            /** @var UnencryptedToken $lcobucciToken */
            $lcobucciToken = $this->lcobucciConfig->parser()->parse($jwtString);
        } catch (InvalidTokenStructure|CannotDecodeContent $e) {
            throw new TokenInvalidException('Could not decode token: ' . $e->getMessage(), (int)$e->getCode(), $e);
        }

        // 1. Lcobucci/jwt 级别验证 (签名, 标准时间声明, iss, aud)
        $constraints = [
            new SignedWith($this->lcobucciConfig->signer(), $this->lcobucciConfig->verificationKey()),
            new StrictValidAt(SystemClock::fromSystemTimezone(), new DateInterval('PT' . $this->validator->getLeeway() . 'S'))
        ];
        // 如果配置中要求验证 iss 和 aud
        if ($this->hyperfConfig->get('jwt.required_claims.iss', false) && $this->issuer) {
            $constraints[] = new \Lcobucci\JWT\Validation\Constraint\IssuedBy($this->issuer);
        }
        $audiences = is_array($this->audience) ? $this->audience : [$this->audience];
        if ($this->hyperfConfig->get('jwt.required_claims.aud', false) && !empty($audiences)) {
            foreach ($audiences as $aud) { // lcobucci constraint is for single audience.
                $constraints[] = new \Lcobucci\JWT\Validation\Constraint\PermittedFor($aud); // or use a custom one for array of audiences.
                // For simplicity, if multiple aud are configured, we might only check the first one here,
                // or expect the token to match one of them.
                // This part may need more sophisticated logic if multiple audiences must ALL be present.
                // A simple check: check if token's audience is one of the configured audiences.
                // Current lcobucci constraint `PermittedFor` checks if *at least one* of the token's `aud` claim values is equal to the constraint's value.
                // So if we add multiple PermittedFor constraints, it becomes an AND.
                // A better way would be a single constraint that checks if token.aud is a subset of configured.aud or vice-versa based on policy.
                // For now, we'll add one constraint if only one audience is configured.
                // If multiple, `ValidatorInterface::checkClaims` will handle our custom logic for audience array matching.
            }
            // If only one audience is configured, check for it.
            if (count($audiences) === 1) {
                $constraints[] = new \Lcobucci\JWT\Validation\Constraint\PermittedFor($audiences[0]);
            }
        }


        try {
            $this->lcobucciConfig->validator()->assert($lcobucciToken, ...$constraints);
        } catch (RequiredConstraintsViolated $e) {
            $firstViolation = $e->violations()[0] ?? null;
            $message = $firstViolation ? $firstViolation->getMessage() : 'Token validation failed (lcobucci).';

            // 检查具体是什么约束失败，转换为我们的异常
            // lcobucci/jwt 的 ValidAt 约束会抛出消息如 "The token is expired" 或 "The token cannot be used yet"
            if (str_contains(strtolower($message), 'expired')) {
                throw new TokenExpiredException($message, (int)$e->getCode(), $e);
            }
            if (str_contains(strtolower($message), 'cannot be used yet') || str_contains(strtolower($message), 'nbf')) {
                throw new TokenNotYetValidException($message, (int)$e->getCode(), $e);
            }
            // 其他如签名错误，iss, aud 错误
            throw new TokenInvalidException($message, (int)$e->getCode(), $e);
        }

        $ourToken = $this->container->make(Token::class, ['lcobucciToken' => $lcobucciToken]);

        // 2. 检查黑名单 (在我们的 Validator 之前，因为黑名单的优先级更高)
        if ($this->hyperfConfig->get('jwt.blacklist_enabled', true) && $this->blacklist->has($ourToken)) {
            throw new TokenInvalidException('Token has been blacklisted.');
        }

        // 3. 我们自定义的 Validator (主要用于非标准声明或更复杂的业务逻辑)
        // $expectedClaimsForValidator = []; // iss/aud are already checked by lcobucci if configured
        // $this->validator->validate($ourToken, false, $expectedClaimsForValidator); // `checkStandardClaims` is false as lcobucci did it.
        // However, our validator might have its own interpretation or check more.
        // Let's pass true and let validator re-check time claims if it wants, based on its own logic and required_claims config.
        $this->validator->validate($ourToken, true, $this->getValidationExpectedClaims());


        return $ourToken;
    }

    /**
     * 获取用于我们 Validator 的期望声明。
     */
    protected function getValidationExpectedClaims(): array
    {
        $claims = [];
        // Our validator can re-check iss/aud if they are in its required_claims,
        // but primary check is by lcobucci.
        // We mainly use this for other custom claims if needed.
        return $claims;
    }


    /**
     * {@inheritdoc}
     */
    public function parseTokenFromRequest(?ServerRequestInterface $request = null): ?TokenInterface
    {
        if (!$request && $this->container->has(HyperfRequestInterface::class)) {
            $request = $this->container->get(HyperfRequestInterface::class);
        } elseif (!$request) {
            // 如果连 HyperfRequestInterface 都没有，则无法获取请求
            // 可以选择抛出异常或返回 null
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
            return null; // 未能从请求中解析到令牌字符串
        }

        try {
            return $this->parse($jwtString);
        } catch (JwtException $e) {
            // 根据需要，可以选择在这里捕获并记录异常，或者直接让异常向上抛出
            // 例如，记录解析失败的尝试
            // $this->container->get(\Psr\Log\LoggerInterface::class)->debug('Failed to parse token from request: ' . $e->getMessage());
            return null; // 或者重新抛出 $e;
        }
    }


    public function refreshToken(string $oldTokenString, bool $forceForever = false, bool $resetClaims = false): TokenInterface
    {
        if (!$this->hyperfConfig->get('jwt.blacklist_enabled', true)) {
            throw new JwtException('Token refresh is not available when blacklist is disabled.');
        }

        // 1. 轻量级解析旧令牌，仅获取声明，不严格验证时间戳（但签名必须有效）
        try {
            /** @var UnencryptedToken $lcobucciOldToken */
            $lcobucciOldToken = $this->lcobucciConfig->parser()->parse($oldTokenString);
        } catch (InvalidTokenStructure|CannotDecodeContent $e) {
            throw new TokenInvalidException('Could not decode old token for refresh: ' . $e->getMessage(), (int)$e->getCode(), $e);
        }

        // 验证签名
        $constraints = [new SignedWith($this->lcobucciConfig->signer(), $this->lcobucciConfig->verificationKey())];
        try {
            $this->lcobucciConfig->validator()->assert($lcobucciOldToken, ...$constraints);
        } catch (RequiredConstraintsViolated $e) {
            throw new TokenInvalidException('Old token signature validation failed for refresh: ' . $e->getMessage(), (int)$e->getCode(), $e);
        }

        $oldToken = $this->container->make(Token::class, ['lcobucciToken' => $lcobucciOldToken]);

        // 2. 检查旧令牌是否已在黑名单中
        if ($this->blacklist->has($oldToken)) {
            throw new TokenInvalidException('Token has been blacklisted and cannot be refreshed.');
        }

        // 3. 检查令牌是否仍在刷新期内
        $exp = $oldToken->getExpirationTime();
        if (!$exp) {
            throw new TokenInvalidException('Old token does not have an expiration time and cannot be determined if it is refreshable.');
        }

        $now = new DateTimeImmutable();
        $refreshWindowEnd = $exp->add(new DateInterval("PT{$this->refreshTtl}M"));

        // 令牌可以未过期，也可以已过期但在刷新窗口内
        if ($now > $refreshWindowEnd) { // 已彻底超过刷新窗口
            throw new TokenExpiredException('Token has expired and is outside the refresh window.');
        }

        // 4. 将旧令牌加入黑名单 (后续步骤和之前类似)
        $blacklistTtlSeconds = max(1, $refreshWindowEnd->getTimestamp() - $now->getTimestamp());
        $this->blacklist->add($oldToken, $blacklistTtlSeconds);

        // 5. 准备新令牌的载荷 (后续步骤和之前类似)
        $newPayload = [];
        // ... (同之前的 resetClaims 逻辑) ...
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

    /**
     * {@inheritdoc} @deprecated token过期后虽然在刷新时间的窗口内但不支持刷新的实现
     */
//    public function refreshToken(TokenInterface $token, bool $forceForever = false, bool $resetClaims = false): TokenInterface
//    {
//        if (!$this->hyperfConfig->get('jwt.blacklist_enabled', true)) {
//            throw new JwtException('Token refresh is not available when blacklist is disabled.');
//        }
//
//        // 1. 检查旧令牌是否已在黑名单中 (如果启用了黑名单)
//        if ($this->blacklist->has($token)) {
//            throw new TokenInvalidException('Token has been blacklisted and cannot be refreshed.');
//        }
//
//        // 2. 检查令牌是否仍在刷新期内
//        // refreshTtl 定义为 "旧令牌过期后，可以用来获取新令牌的刷新窗口期"
//        $exp = $token->getExpirationTime();
//        if (!$exp) {
//            throw new TokenInvalidException('Token does not have an expiration time and cannot be determined if it is refreshable.');
//        }
//
//        $now = new DateTimeImmutable();
//        $refreshWindowEnd = $exp->add(new DateInterval("PT{$this->refreshTtl}M"));
//        // 令牌必须已过期，且当前时间在刷新窗口内
//        // 或者令牌未过期 (也允许刷新，通常刷新操作会使旧令牌立即失效)
//        $isExpired = $exp < $now;
//        $isInRefreshWindowAfterExpiry = $isExpired && ($now < $refreshWindowEnd);
//
//        if (!$isExpired && $now > $exp) { // Should not happen if $isExpired logic is correct. Defensive.
//            throw new TokenExpiredException('Token has expired and is outside the refresh window.');
//        }
//        if ($isExpired && !$isInRefreshWindowAfterExpiry) {
//            throw new TokenExpiredException('Token has expired and is outside the refresh window.');
//        }
//
//        // 3. 将旧令牌加入黑名单
//        // 计算旧令牌在黑名单中的存活时间，至少应该是到它的刷新窗口结束
//        $blacklistTtlSeconds = max(1, $refreshWindowEnd->getTimestamp() - $now->getTimestamp());
//        $this->blacklist->add($token, $blacklistTtlSeconds);
//
//
//        // 4. 准备新令牌的载荷
//        $newPayload = [];
//        if (!$resetClaims) {
//            $allOldClaims = $token->getAllClaims();
//            // 排除标准时间声明和jti，因为它们需要重新生成
//            $claimsToExclude = ['iat', 'exp', 'nbf', 'jti', 'iss', 'aud']; // iss, aud 也由 issueToken 处理
//            foreach ($allOldClaims as $key => $value) {
//                if (!in_array($key, $claimsToExclude, true)) {
//                    $newPayload[$key] = $value;
//                }
//            }
//        }
//        // 如果有特定的主题声明，且没有被重置，则保留
//        if (isset($newPayload[$this->subjectClaimName]) && $resetClaims) {
//            unset($newPayload[$this->subjectClaimName]); // 如果重置，则sub也可能需要重新设置
//        } else if ($token->getSubject() && !$resetClaims && !isset($newPayload[$this->subjectClaimName])) {
//            $newPayload[$this->subjectClaimName] = $token->getSubject();
//        }
//
//
//        // 5. 签发新令牌
//        return $this->issueToken($newPayload);
//    }


    /**
     * {@inheritdoc}
     */
    public function invalidate(TokenInterface $token, bool $forceForever = false): self
    {
        if (!$this->hyperfConfig->get('jwt.blacklist_enabled', true)) {
            // 如果黑名单未启用，则 invalidate 操作无效，可以抛出异常或静默失败
            // throw new JwtException('Cannot invalidate token: blacklist is disabled.');
            return $this; // 静默返回
        }

        try {
            // 使用默认的 grace period，或者如果 forceForever 为 true，可以考虑一个非常长的 TTL
            // 但 BlacklistInterface::add 的 $ttl 参数优先级更高
            $ttl = $forceForever ? ($this->refreshTtl * 60 * 24 * 365) : null; // e.g. 1 year for "forever"
            if (!$this->blacklist->add($token, $ttl)) {
                // 如果 jti 不存在等原因导致加入黑名单失败
                if (empty($token->getId())) {
                    throw new JwtException('Token does not have a jti claim and cannot be reliably blacklisted.');
                }
                // 其他原因
                throw new JwtException('Failed to add token to blacklist.');
            }
        } catch (\Throwable $e) {
            throw new JwtException('Error while invalidating token: ' . $e->getMessage(), (int)$e->getCode(), $e);
        }
        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getValidator(): ValidatorInterface
    {
        return $this->validator;
    }

    /**
     * {@inheritdoc}
     */
    public function setValidator(ValidatorInterface $validator): self
    {
        $this->validator = $validator;
        $this->configureValidator(); // 重新配置新的验证器
        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getBlacklist(): BlacklistInterface
    {
        return $this->blacklist;
    }

    /**
     * {@inheritdoc}
     */
    public function setBlacklist(BlacklistInterface $blacklist): self
    {
        $this->blacklist = $blacklist;
        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getRequestParserFactory(): RequestParserFactoryInterface
    {
        return $this->requestParserFactory;
    }

    /**
     * {@inheritdoc}
     */
    public function setRequestParserFactory(RequestParserFactoryInterface $requestParserFactory): self
    {
        $this->requestParserFactory = $requestParserFactory;
        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getLcobucciConfig(): LcobucciConfiguration
    {
        return $this->lcobucciConfig;
    }

    /**
     * {@inheritdoc}
     */
    public function getSigner(): Signer
    {
        return $this->signer;
    }

    /**
     * {@inheritdoc}
     */
    public function setTtl(int $ttl): self
    {
        $this->ttl = $ttl > 0 ? $ttl : 1; // TTL 至少为1分钟
        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getTtl(): int
    {
        return $this->ttl;
    }

    /**
     * {@inheritdoc}
     */
    public function getRefreshTtl(): int
    {
        return $this->refreshTtl;
    }

    /**
     * 生成唯一的 JWT ID (jti)。
     */
    protected function generateJti(): string
    {
        try {
            return bin2hex(random_bytes(16)); // 32个十六进制字符
        } catch (\Exception $e) {
            // 降级处理，如果 random_bytes 失败
            return uniqid('', true) . sha1(microtime(true));
        }
    }
}