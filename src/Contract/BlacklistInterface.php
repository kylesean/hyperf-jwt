<?php

declare(strict_types=1);

namespace Kylesean\Jwt\Contract;

/**
 * Interface BlacklistInterface.
 *
 * Defines the contract for managing the JWT blacklist.
 * The blacklist is used to invalidate issued tokens.
 *
 * Note on concurrency: implementations built on PSR-16 caches perform
 * check-then-set, which is not atomic. Two coroutines refreshing the same
 * token simultaneously may both observe "not blacklisted" and both succeed.
 * The blacklist itself still ends up containing the token; callers that need
 * strict single-use refresh semantics must add their own distributed lock.
 */
interface BlacklistInterface
{
    /**
     * Add the given token to the blacklist.
     * Typically, the token's unique identifier (jti) and its expiration time (exp) are stored.
     *
     * @param TokenInterface $token The token to be blacklisted
     * @param int|null $ttl Optional time-to-live in seconds. If null, the default grace period is used.
     *                      This allows setting a specific blacklist TTL for an individual token.
     * @param int $concurrencyGracePeriod Coroutine concurrency grace period in seconds, during which the token remains valid
     * @return bool True on success, false on failure
     */
    public function add(TokenInterface $token, ?int $ttl = null, int $concurrencyGracePeriod = 0): bool;

    /**
     * Check whether the given token is in the blacklist.
     *
     * @param TokenInterface $token The token to check
     * @return bool True if the token is in the blacklist, false otherwise
     */
    public function has(TokenInterface $token): bool;

    /**
     * Remove the given token from the blacklist.
     * Note: Some cache drivers may not support deletion efficiently, or this operation
     * may not be necessary as blacklist entries usually have a TTL (Time-To-Live).
     *
     * @param TokenInterface $token The token to remove from the blacklist
     * @return bool True on success, false on failure
     */
    public function remove(TokenInterface $token): bool;

    /**
     * Clear all blacklist entries.
     * Warning: This will make all previously blacklisted tokens valid again (until they naturally expire).
     * Use this operation with caution.
     *
     * @return bool True on success, false on failure
     */
    public function clear(): bool;

    /**
     * Set the default grace period (in seconds) for entries in the blacklist.
     * This value typically corresponds to 'blacklist_grace_period' in configuration.
     *
     * @param int $ttl Time-to-live in seconds
     * @return $this
     */
    public function setDefaultGracePeriod(int $ttl): self;

    /**
     * Get the default grace period (in seconds) for entries in the blacklist.
     *
     * @return int The default grace period in seconds
     */
    public function getDefaultGracePeriod(): int;
}
