<?php

declare(strict_types=1);

namespace Kylesean\Jwt;

use Kylesean\Jwt\Blacklist;
use Kylesean\Jwt\Cache\CacheFactory;
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
    /**
     * @return array<string, mixed>
     */
    public function __invoke(): array
    {
        return [
            'dependencies' => [
                // core jwt manager
                ManagerInterface::class => Manager::class,
                // Lcobucci JWT Configuration Object
                \Lcobucci\JWT\Configuration::class => \Kylesean\Jwt\Factory\LcobucciFactory::class,
                // Token object implementation
                TokenInterface::class => Token::class,
                // JWT validator
                ValidatorInterface::class => Validator::class,
                // blacklist implementation
                BlacklistInterface::class => Blacklist::class,
                // request parser factory
                RequestParserFactoryInterface::class => RequestParserFactory::class,
                // cache related factory
                CacheFactory::class => CacheFactory::class,
                // payload factory
                PayloadFactoryInterface::class => PayloadFactory::class
            ],
            'commands' => [
                // generate jwt key command
                GenJwtKeyCommand::class,
            ],
            'publish' => [
                [
                    'id' => 'config',
                    'description' => 'The config for kylesean/hyperf-jwt.',
                    'source' => __DIR__ . '/../publish/jwt.php',
                    'destination' => (defined('BASE_PATH') ? BASE_PATH : '') . '/config/autoload/jwt.php',
                ],
            ],
            'annotations' => [
                'scan' => [
                    'paths' => [
                        __DIR__, // scan current package annotations if needed
                    ],
                ],
            ],
        ];
    }
}