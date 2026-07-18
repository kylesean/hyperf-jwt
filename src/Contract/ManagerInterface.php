<?php

declare(strict_types=1);

namespace Kylesean\Jwt\Contract;

use Kylesean\Jwt\Contract\RequestParser\RequestParserFactoryInterface;
use Kylesean\Jwt\Contract\TokenInterface;
use Lcobucci\JWT\Configuration as LcobucciConfiguration;
use Lcobucci\JWT\Signer;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Interface ManagerInterface.
 *
 * Core interface for the JWT manager, responsible for managing the token lifecycle.
 */
interface ManagerInterface
{
    /**
     * Create a new JWT token with the given payload.
     *
     * @param array<string, mixed> $customClaims Custom claims to include in the JWT
     * @param mixed $subject Optional subject claim value
     * @return TokenInterface The created token object
     * @throws \Kylesean\Jwt\Exception\JwtException If token creation fails
     */
    public function issueToken(array $customClaims = [], mixed $subject = null): TokenInterface;

    /**
     * Parse and validate a token from the given JWT string.
     *
     * @param string $jwtString The JWT string
     * @return TokenInterface|null The parsed and validated token object, or null if invalid depending on implementation
     * @throws \Kylesean\Jwt\Exception\TokenInvalidException If the token is invalid
     * @throws \Kylesean\Jwt\Exception\TokenExpiredException If the token is expired
     * @throws \Kylesean\Jwt\Exception\TokenNotYetValidException If the token is not yet valid
     */
    public function parse(string $jwtString): ?TokenInterface;

    /**
     * Attempt to parse and validate a token from the current HTTP request.
     * It uses the configured RequestParser chain to extract the token.
     *
     * @param ServerRequestInterface|null $request PSR-7 request object. If null, attempts to fetch current request from container.
     * @return TokenInterface|null The token object if successfully parsed and validated, null otherwise.
     */
    public function parseTokenFromRequest(?ServerRequestInterface $request = null): ?TokenInterface;

    /**
     * Refresh an existing (possibly expired, but within refresh period) JWT.
     *
     * @param string $oldTokenString The token string to refresh
     * @param bool $forceForever If true, forces adding the old token to the blacklist even if it lacks a jti claim.
     *                           This is typically used when immediately invalidating the old token upon refresh.
     * @param bool $resetClaims If true, the new token payload will be based on new defaults rather than copied from the old token.
     *                          Custom claims must still be passed via extra parameters or configuration.
     * @return TokenInterface The new JWT token object
     * @throws \Kylesean\Jwt\Exception\JwtException If refresh fails (e.g., old token is outside refresh window or completely invalid)
     * @throws \Kylesean\Jwt\Exception\TokenInvalidException If the old token cannot be blacklisted when required
     */
    public function refreshToken(string $oldTokenString, bool $forceForever = false, bool $resetClaims = false): TokenInterface;

    /**
     * Invalidate a JWT by adding it to the blacklist.
     *
     * @param TokenInterface $token The token to invalidate
     * @param bool $forceForever If true, attempts to blacklist based on fallback mechanisms even if token lacks a 'jti' claim,
     *                           or if the blacklist is configured for permanent storage.
     * @return $this
     * @throws \Kylesean\Jwt\Exception\JwtException If the token cannot be blacklisted
     */
    public function invalidate(TokenInterface $token, bool $forceForever = false): self;

    /**
     * Get the JWT validator instance.
     *
     * @return ValidatorInterface
     */
    public function getValidator(): ValidatorInterface;

    /**
     * Set the JWT validator instance.
     *
     * @param ValidatorInterface $validator
     * @return $this
     */
    public function setValidator(ValidatorInterface $validator): self;

    /**
     * Get the JWT blacklist instance.
     *
     * @return BlacklistInterface
     */
    public function getBlacklist(): BlacklistInterface;

    /**
     * Set the JWT blacklist instance.
     *
     * @param BlacklistInterface $blacklist
     * @return $this
     */
    public function setBlacklist(BlacklistInterface $blacklist): self;

    /**
     * Get the request parser factory instance.
     *
     * @return RequestParserFactoryInterface
     */
    public function getRequestParserFactory(): RequestParserFactoryInterface;

    /**
     * Set the request parser factory instance.
     *
     * @param RequestParserFactoryInterface $requestParserFactory
     * @return $this
     */
    public function setRequestParserFactory(RequestParserFactoryInterface $requestParserFactory): self;

    /**
     * Get the underlying lcobucci/jwt Configuration object.
     * This allows advanced users to access and manipulate JWT configuration directly.
     *
     * @return LcobucciConfiguration
     */
    public function getLcobucciConfig(): LcobucciConfiguration;

    /**
     * Get the payload factory instance.
     *
     * @return PayloadFactoryInterface
     */
    public function getPayloadFactory(): PayloadFactoryInterface;

    /**
     * Set the payload factory instance.
     *
     * @param PayloadFactoryInterface $payloadFactory
     * @return $this
     */
    public function setPayloadFactory(PayloadFactoryInterface $payloadFactory): self;

    /**
     * Get the signer used for generating and verifying tokens.
     *
     * @return Signer
     */
    public function getSigner(): Signer;

    /**
     * Set the token time-to-live (TTL) in minutes.
     *
     * @param int $ttl Time-to-live in minutes
     * @return $this
     */
    public function setTtl(int $ttl): self;

    /**
     * Get the token time-to-live (TTL) in minutes.
     *
     * @return int
     */
    public function getTtl(): int;

    /**
     * Get the token refresh time-to-live (Refresh TTL) in minutes.
     *
     * @return int
     */
    public function getRefreshTtl(): int;

    /**
     * Get the subject claim key name.
     *
     * @return string
     */
    public function getSubjectClaimKey(): string;
}