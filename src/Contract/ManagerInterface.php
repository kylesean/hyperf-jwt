<?php

declare(strict_types=1);

namespace FriendsOfHyperf\Jwt\Contract;

use FriendsOfHyperf\Jwt\Contract\RequestParser\RequestParserFactoryInterface;
use FriendsOfHyperf\Jwt\Contract\TokenInterface;
use Lcobucci\JWT\Configuration as LcobucciConfiguration; // 底层库配置
use Lcobucci\JWT\Signer; // 底层库签名器
use Psr\Http\Message\ServerRequestInterface;

/**
 * Interface ManagerInterface.
 *
 * JWT 管理器的核心接口，负责令牌的生命周期管理。
 */
interface ManagerInterface
{
    /**
     * 根据给定的载荷 (payload) 创建一个新的 JWT 令牌。
     *
     * @param array<string, mixed> $customClaims 要包含在 JWT 中的自定义声明
     * @return TokenInterface 创建的令牌对象
     * @throws \FriendsOfHyperf\Jwt\Exception\JwtException 如果创建令牌失败
     */
    public function issueToken(array $customClaims = []): TokenInterface;

    /**
     * 从给定的 JWT 字符串解析并验证令牌。
     *
     * @param string $jwtString JWT 字符串
     * @return TokenInterface|null 解析并验证通过的令牌对象，如果无效则返回 null 或抛出异常（取决于实现）
     * @throws \FriendsOfHyperf\Jwt\Exception\TokenInvalidException 如果令牌无效
     * @throws \FriendsOfHyperf\Jwt\Exception\TokenExpiredException 如果令牌已过期
     * @throws \FriendsOfHyperf\Jwt\Exception\TokenNotYetValidException 如果令牌尚未生效
     */
    public function parse(string $jwtString): ?TokenInterface;

    /**
     * 尝试从当前的 HTTP 请求中解析并验证令牌。
     * 它会使用配置的 RequestParser 链来尝试提取令牌。
     *
     * @param ServerRequestInterface|null $request PSR-7 请求对象。如果为 null，则尝试从容器中获取当前请求。
     * @return TokenInterface|null 如果成功解析并验证令牌，则返回令牌对象；否则返回 null。
     */
    public function parseTokenFromRequest(?ServerRequestInterface $request = null): ?TokenInterface;

    /**
     * 刷新一个现有的（可能已过期的，但在刷新期内的）JWT。
     *
     * @param string $oldTokenString 要刷新的令牌
     * @param bool $forceForever 如果为 true，则强制将新令牌加入黑名单，即使原令牌未设置 jti。
     *                           这通常用于刷新后立即让旧令牌失效的场景。
     * @param bool $resetClaims 如果为 true，则新令牌的载荷将基于新的默认值，而不是从旧令牌复制。
     *                          自定义载荷仍需通过额外参数或配置传递。
     * @return TokenInterface 新的 JWT 令牌对象
     * @throws \FriendsOfHyperf\Jwt\Exception\JwtException 如果刷新失败（例如，原令牌不在刷新期内或已彻底失效）
     * @throws \FriendsOfHyperf\Jwt\Exception\TokenInvalidException 如果原令牌无法被加入黑名单（当需要时）
     */
    public function refreshToken(string $oldTokenString, bool $forceForever = false, bool $resetClaims = false): TokenInterface;

    /**
     * 使一个 JWT 失效（将其加入黑名单）。
     *
     * @param TokenInterface $token 要失效的令牌
     * @param bool $forceForever 如果为 true，则即使令牌没有 'jti' 声明，也尝试基于其他方式（可能不太可靠）加入黑名单，
     *                           或者如果黑名单配置为永久存储。
     * @return $this
     * @throws \FriendsOfHyperf\Jwt\Exception\JwtException 如果令牌无法被加入黑名单
     */
    public function invalidate(TokenInterface $token, bool $forceForever = false): self;

    /**
     * 获取 JWT 验证器实例。
     */
    public function getValidator(): ValidatorInterface;

    /**
     * 设置 JWT 验证器实例。
     * @return $this
     */
    public function setValidator(ValidatorInterface $validator): self;

    /**
     * 获取 JWT 黑名单实例。
     */
    public function getBlacklist(): BlacklistInterface;

    /**
     * 设置 JWT 黑名单实例。
     * @return $this
     */
    public function setBlacklist(BlacklistInterface $blacklist): self;

    /**
     * 获取请求解析器工厂实例。
     */
    public function getRequestParserFactory(): RequestParserFactoryInterface;

    /**
     * 设置请求解析器工厂实例。
     * @return $this
     */
    public function setRequestParserFactory(RequestParserFactoryInterface $requestParserFactory): self;

    /**
     * 获取底层的 lcobucci/jwt Configuration 对象。
     * 这允许高级用户直接访问和操作 JWT 的配置。
     */
    public function getLcobucciConfig(): LcobucciConfiguration;

    /**
     * 获取 JWT 载荷的工厂类/方法，用于生成令牌的默认声明。
     * （此方法可能在后续实现 PayloadFactory 时添加）
     * // public function getPayloadFactory(): PayloadFactoryInterface;
     */

    /**
     * 获取用于生成和验证令牌的签名器。
     */
    public function getSigner(): Signer;

    /**
     * 设置令牌的有效期（Time To Live），单位为分钟。
     * @return $this
     */
    public function setTtl(int $ttl): self;

    /**
     * 获取令牌的有效期（Time To Live），单位为分钟。
     */
    public function getTtl(): int;

    /**
     * 获取令牌的刷新期（Refresh Time To Live），单位为分钟。
     */
    public function getRefreshTtl(): int;

    /**
     * 获取subject_claim key
     * @return string
     */
    public function getSubjectClaimKey(): string;
}