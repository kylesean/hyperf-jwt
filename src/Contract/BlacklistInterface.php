<?php

declare(strict_types=1);

namespace FriendsOfHyperf\Jwt\Contract;

use FriendsOfHyperf\Jwt\Contract\TokenInterface; // 我们的令牌接口

/**
 * Interface BlacklistInterface.
 *
 * 定义了管理 JWT 黑名单的契约。
 * 黑名单用于使已签发的令牌失效。
 */
interface BlacklistInterface
{
    /**
     * 将给定的 Token 添加到黑名单中。
     * 通常，令牌的唯一标识符 (jti) 和其过期时间 (exp) 会被存储。
     *
     * @param TokenInterface $token 要加入黑名单的令牌
     * @param int|null $ttl 可选的缓存存活时间（秒）。如果为 null，则使用默认的黑名单宽限期。
     *                      这允许为单个令牌设置特定的黑名单 TTL。
     * @return bool 操作是否成功
     */
    public function add(TokenInterface $token, ?int $ttl = null): bool;

    /**
     * 检查给定的 Token 是否已在黑名单中。
     *
     * @param TokenInterface $token 要检查的令牌
     * @return bool 如果令牌在黑名单中则返回 true，否则返回 false
     */
    public function has(TokenInterface $token): bool;

    /**
     * 从黑名单中移除给定的 Token。
     * 注意：某些缓存驱动可能不高效地支持删除操作，或者此操作可能不是必需的，
     * 因为黑名单条目通常有 TTL（存活时间）。
     *
     * @param TokenInterface $token 要从黑名单中移除的令牌
     * @return bool 操作是否成功
     */
    public function remove(TokenInterface $token): bool;

    /**
     * 清空所有黑名单条目。
     * 警告：这将使所有之前加入黑名单的令牌重新有效（直到它们自然过期）。
     * 此操作应谨慎使用。
     *
     * @return bool 操作是否成功
     */
    public function clear(): bool;

    /**
     * 设置黑名单中条目的默认存活时间（秒）。
     * 这个值通常对应于配置中的 'blacklist_grace_period'。
     *
     * @param int $ttl 存活时间（秒）
     * @return $this
     */
    public function setDefaultGracePeriod(int $ttl): self;

    /**
     * 获取黑名单中条目的默认存活时间（秒）。
     */
    public function getDefaultGracePeriod(): int;
}