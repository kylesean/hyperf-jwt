<?php

declare(strict_types=1);

namespace Kylesean\Jwt;

use Kylesean\Jwt\Blacklist;
use Kylesean\Jwt\Cache\CacheFactory;
use Kylesean\Jwt\Cache\CacheItemPoolFactory;
use Kylesean\Jwt\Command\GenJwtKeyCommand;
use Kylesean\Jwt\Contract\BlacklistInterface;
use Kylesean\Jwt\Contract\ManagerInterface;
use Kylesean\Jwt\Contract\RequestParser\RequestParserFactoryInterface;
use Kylesean\Jwt\Contract\RequestParser\RequestParserInterface;
use Kylesean\Jwt\Contract\TokenInterface;
use Kylesean\Jwt\Contract\ValidatorInterface;
use Kylesean\Jwt\Manager;
use Kylesean\Jwt\RequestParser\RequestParserFactory;
use Kylesean\Jwt\Token;
use Kylesean\Jwt\Validator;
use Kylesean\Jwt\Contract\PayloadFactoryInterface;
use Kylesean\Jwt\PayloadFactory;

class ConfigProvider
{
    public function __invoke(): array
    {
        return [
            'dependencies' => [
                    // 核心 JWT 管理器
                ManagerInterface::class => Manager::class,
                // Lcobucci JWT 配置对象
                \Lcobucci\JWT\Configuration::class => \Kylesean\Jwt\Factory\LcobucciFactory::class,
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
                    'description' => 'The config for kylesean/hyperf-jwt.', // 配置描述
                    'source' => __DIR__ . '/../publish/jwt.php',
                    'destination' => (defined('BASE_PATH') ? BASE_PATH : '') . '/config/autoload/jwt.php',
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