<?php

declare(strict_types=1);

namespace FriendsOfHyperf\Jwt\RequestParser;

use FriendsOfHyperf\Jwt\Contract\RequestParser\RequestParserFactoryInterface;
use FriendsOfHyperf\Jwt\Contract\RequestParser\RequestParserInterface;
use Hyperf\Contract\ConfigInterface;
use Psr\Container\ContainerInterface;
// 引入我们已创建的解析器类，以便在默认配置中使用
use FriendsOfHyperf\Jwt\RequestParser\AuthorizationHeader;
use FriendsOfHyperf\Jwt\RequestParser\QueryString;
use FriendsOfHyperf\Jwt\RequestParser\InputSource;
use FriendsOfHyperf\Jwt\RequestParser\Cookie;

class RequestParserFactory implements RequestParserFactoryInterface
{
    protected ContainerInterface $container;

    /**
     * 存储解析器的原始配置。
     * @var array
     */
    protected array $parsersConfig = [];

    /**
     * 缓存已实例化的解析器链。
     * @var RequestParserInterface[]|null
     */
    protected ?array $parserChainCache = null;

    /**
     * 默认的解析器配置。
     * 如果用户没有在 jwt.php 中配置 token_parsers，则使用此配置。
     * @var array
     */
    protected array $defaultParserConfigs = [
        AuthorizationHeader::class,
        QueryString::class,
        InputSource::class,
        Cookie::class,
    ];

    /**
     * 构造函数。
     *
     * @param ContainerInterface $container PSR-11 依赖注入容器
     * @param ConfigInterface $config Hyperf 配置接口，用于获取包配置
     */
    public function __construct(ContainerInterface $container, ConfigInterface $config)
    {
        $this->container = $container;
        // 从 jwt.php 配置文件中获取 'token_parsers'，如果未定义则使用默认配置
        $userParserConfigs = $config->get('jwt.token_parsers', $this->defaultParserConfigs);
        $this->setParsersConfig($userParserConfigs);
    }

    /**
     * 设置要使用的解析器配置。
     *
     * @param array $parsersConfig 解析器配置数组
     * @return $this
     */
    public function setParsersConfig(array $parsersConfig): self
    {
        $this->parsersConfig = $parsersConfig;
        $this->parserChainCache = null; // 配置更改时，清除缓存的解析器链
        return $this;
    }

    /**
     * 获取配置的请求解析器链。
     *
     * @return RequestParserInterface[]
     */
    public function getParserChain(): array
    {
        if ($this->parserChainCache !== null) {
            return $this->parserChainCache;
        }

        $chain = [];
        foreach ($this->parsersConfig as $configItem) {
            $parser = $this->createParser($configItem);
            if ($parser instanceof RequestParserInterface) {
                $chain[] = $parser;
            }
            // 你可以在此处添加日志记录，如果 createParser 返回 null，说明配置项有问题
            // else {
            //     // 例如：$this->container->get(LoggerInterface::class)->warning("Invalid parser configuration: " . json_encode($configItem));
            // }
        }
        $this->parserChainCache = $chain;
        return $this->parserChainCache;
    }

    /**
     * 根据给定的解析器类名或配置数组，创建一个解析器实例。
     *
     * @param string|array|RequestParserInterface $parserConfig 解析器的类名，配置数组，或已实例化的对象。
     *        配置数组格式可以是:
     *        - ClassName::class (字符串)
     *        - [ClassName::class] (单元素数组)
     *        - [ClassName::class, ['option_key' => 'value', ...]] (元组风格)
     *        - ['class' => ClassName::class, 'options' => ['option_key' => 'value', ...]] (映射风格)
     * @return RequestParserInterface|null 如果无法创建解析器则返回 null。
     */
    public function createParser(string|array|RequestParserInterface $parserConfig): ?RequestParserInterface
    {
        if ($parserConfig instanceof RequestParserInterface) {
            return $parserConfig; // 如果已经是实例，直接返回
        }

        $className = null;
        $options = [];

        if (is_string($parserConfig)) {
            // Case 1: 直接是类名字符串
            $className = $parserConfig;
        } elseif (is_array($parserConfig)) {
            if (empty($parserConfig)) {
                // logging: "Empty array provided for parser configuration."
                return null;
            }

            // Case 2: 元组风格 [ClassName::class, $optionsArray] 或 [ClassName::class]
            // 检查数组第一个元素是否为字符串（类名）
            if (is_string($parserConfig[0])) {
                $className = $parserConfig[0];
                // 如果有第二个元素且是数组，则将其作为选项
                $options = (isset($parserConfig[1]) && is_array($parserConfig[1])) ? $parserConfig[1] : [];
            }
            // Case 3: 映射风格 ['class' => ClassName::class, 'options' => $optionsArray]
            elseif (isset($parserConfig['class']) && is_string($parserConfig['class'])) {
                $className = $parserConfig['class'];
                $options = (isset($parserConfig['options']) && is_array($parserConfig['options'])) ? $parserConfig['options'] : [];
            } else {
                // logging: "Invalid array format for parser configuration: " . json_encode($parserConfig)
                return null;
            }
        } else {
            // logging: "Invalid parser configuration type: " . gettype($parserConfig)
            return null;
        }

        if (!$className || !class_exists($className)) {
            // logging: "Parser class '{$className}' does not exist or invalid class name provided."
            return null;
        }

        // 确保类实现了正确的接口
        if (!is_subclass_of($className, RequestParserInterface::class)) {
            // logging: "Parser class '{$className}' must implement " . RequestParserInterface::class
            return null;
        }

        try {
            // 使用 Hyperf DI 容器创建实例，允许通过 $options 传递构造函数参数
            // Hyperf 的容器可以根据参数名匹配 $options 数组中的键值对
            return $this->container->make($className, $options);
        } catch (\Throwable $e) {
            // logging: "Failed to create parser '{$className}': " . $e->getMessage()
            // 在生产环境中，应该记录这个错误 $e
            return null;
        }
    }
}