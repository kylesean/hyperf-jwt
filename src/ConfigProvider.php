<?php

declare(strict_types=1);

namespace FriendsOfHyperf\Jwt;

use FriendsOfHyperf\Jwt\Blacklist;
use FriendsOfHyperf\Jwt\Cache\CacheFactory;
use FriendsOfHyperf\Jwt\Cache\CacheItemPoolFactory;
use FriendsOfHyperf\Jwt\Command\GenJwtKeyCommand;
use FriendsOfHyperf\Jwt\Contract\BlacklistInterface;
use FriendsOfHyperf\Jwt\Contract\ManagerInterface;
use FriendsOfHyperf\Jwt\Contract\RequestParser\RequestParserFactoryInterface;
use FriendsOfHyperf\Jwt\Contract\RequestParser\RequestParserInterface;
use FriendsOfHyperf\Jwt\Contract\TokenInterface;
use FriendsOfHyperf\Jwt\Contract\ValidatorInterface;
use FriendsOfHyperf\Jwt\Manager;
use FriendsOfHyperf\Jwt\RequestParser\RequestParserFactory;
use FriendsOfHyperf\Jwt\Token;
use FriendsOfHyperf\Jwt\Validator;
use FriendsOfHyperf\Jwt\Contract\PayloadFactoryInterface;
use FriendsOfHyperf\Jwt\PayloadFactory;

class ConfigProvider
{
    public function __invoke(): array
    {
        return [
            'dependencies' => [
                // 核心 JWT 管理器
                ManagerInterface::class => Manager::class,
                // Token 对象实现
                TokenInterface::class => Token::class,
                // JWT 验证器
                ValidatorInterface::class => Validator::class,
                // 黑名单实现
                BlacklistInterface::class => Blacklist::class,
                // 请求解析器工厂
                RequestParserFactoryInterface::class => RequestParserFactory::class,
                // 缓存相关工厂
                CacheFactory::class => CacheFactory::class,
                //CacheItemPoolFactory::class => CacheItemPoolFactory::class,
                PayloadFactoryInterface::class => PayloadFactory::class
            ],
            'commands' => [
                // 生成 JWT 密钥的命令
                GenJwtKeyCommand::class,
            ],
            'publish' => [
                [
                    'id' => 'config',
                    'description' => 'The config for friendsofhyperf/jwt.', // 配置描述
                    'source' => __DIR__ . '/../publish/jwt.php', // 源配置文件路径
                    'destination' => BASE_PATH . '/config/autoload/jwt.php', // 目标配置文件路径
                ],
            ],
            'annotations' => [
                'scan' => [
                    'paths' => [
                        __DIR__, // 扫描当前包的注解，如果需要的话
                    ],
                ],
            ],
        ];
    }
}