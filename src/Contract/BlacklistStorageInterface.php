<?php

declare(strict_types=1);

namespace FriendsOfHyperf\Jwt\Contract;

interface BlacklistStorageInterface
{
    /**
     * 将 Token (的 JTI) 加入黑名单.
     *
     * @param string $jti 要加入黑名单的 Token JTI
     * @param int $ttl 黑名单条目的生存时间 (秒). 例如，可以设置为 Token 剩余的有效期.
     *                 如果存储后端支持，0 或负数可能表示永不过期 (需谨慎使用) 或立即过期.
     *                 对于像 Cache 这样的后端，通常 ttl > 0.
     */
    public function add(string $jti, int $ttl): void;

    /**
     * 检查 Token (的 JTI) 是否在黑名单中.
     *
     * @param string $jti 要检查的 Token JTI
     * @return bool 如果在黑名单中则返回 true, 否则返回 false
     */
    public function has(string $jti): bool;

    /**
     * (可选) 从黑名单中移除一个条目.
     * 如果存储驱动不支持精确移除或成本较高，可以不实现或抛出异常.
     *
     * @param string $jti 要移除的 Token JTI
     * @return bool 如果成功移除返回 true, 否则 false
     */
    // public function remove(string $jti): bool;

    /**
     * (可选) 清理所有已过期的黑名单条目.
     * 很多缓存驱动会自动处理过期，所以此方法可能不是必需的.
     * 如果实现，通常用于定期维护或测试.
     */
    // public function purge(): void;
}