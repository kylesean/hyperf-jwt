<?php

declare(strict_types=1);

namespace Kylesean\Jwt\RequestParser;

use Hyperf\Contract\ConfigInterface;
use Hyperf\Contract\ContainerInterface;
use Kylesean\Jwt\Contract\RequestParser\RequestParserFactoryInterface;
use Kylesean\Jwt\Contract\RequestParser\RequestParserInterface;
use Psr\Log\LoggerInterface;

class RequestParserFactory implements RequestParserFactoryInterface
{
    /**
     * save parser config
     * @var array<int, string|array<string, mixed>|RequestParserInterface>
     */
    protected array $parsersConfig = [];

    /**
     * save parser chain cache
     * @var RequestParserInterface[]|null
     */
    protected ?array $parserChainCache = null;

    /**
     * save default parser config
     * if user not config token_parsers in jwt.php, use this config
     * @var array<int, class-string<RequestParserInterface>>
     */
    protected array $defaultParserConfigs = [
        AuthorizationHeader::class,
        QueryString::class,
        InputSource::class,
        Cookie::class,
    ];

    public function __construct(protected ContainerInterface $container, ConfigInterface $config)
    {
        // get token_parsers from jwt.php config, if not found, use default config
        $userParserConfigs = $config->get('jwt.token_parsers', $this->defaultParserConfigs);
        $this->setParsersConfig($userParserConfigs);
    }

    /**
     * set parser config
     *
     * @param array<int, string|array<string, mixed>|RequestParserInterface> $parsersConfig parser config array
     * @return $this
     */
    public function setParsersConfig(array $parsersConfig): self
    {
        $this->parsersConfig = $parsersConfig;
        // clear cache when config change
        $this->parserChainCache = null;

        return $this;
    }

    /**
     * get parser chain
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
            } else {
                $this->logWarning(sprintf(
                    'Invalid JWT token parser configuration skipped: %s',
                    is_object($configItem) ? get_class($configItem) : json_encode($configItem)
                ));
            }
        }
        $this->parserChainCache = $chain;

        return $this->parserChainCache;
    }

    /**
     * create parser instance by parser config
     *
     * @param string|array<mixed>|RequestParserInterface $parserConfig parser config
     *        parser config format:
     *        - ClassName::class (string)
     *        - [ClassName::class] (array)
     *        - [ClassName::class, ['option_key' => 'value', ...]] (tuple style)
     *        - ['class' => ClassName::class, 'options' => ['option_key' => 'value', ...]] (map style)
     * @return RequestParserInterface|null if create parser failed return null
     */
    public function createParser(string|array|RequestParserInterface $parserConfig): ?RequestParserInterface
    {
        if ($parserConfig instanceof RequestParserInterface) {
            return $parserConfig; // if already an instance, return it directly
        }

        $options = [];

        if (is_string($parserConfig)) {
            // Case 1: string
            $className = $parserConfig;
        } else {
            // After the instanceof and is_string() guards only arrays remain.
            if (empty($parserConfig)) {
                $this->logWarning('Empty array provided for JWT token parser configuration.');

                return null;
            }

            // Case 2: tuple style [ClassName::class, $optionsArray] or [ClassName::class]
            // check first element is string (class name)
            if (isset($parserConfig[0]) && is_string($parserConfig[0])) {
                $className = $parserConfig[0];
                // if second element is array, use it as options
                $options = (isset($parserConfig[1]) && is_array($parserConfig[1])) ? $parserConfig[1] : [];
            } elseif (isset($parserConfig['class']) && is_string($parserConfig['class'])) {
                // Case 3: map style ['class' => ClassName::class, 'options' => $optionsArray]
                $className = $parserConfig['class'];
                $options = (isset($parserConfig['options']) && is_array($parserConfig['options'])) ? $parserConfig['options'] : [];
            } else {
                $this->logWarning('Invalid array format for JWT token parser configuration: ' . json_encode($parserConfig));

                return null;
            }
        }

        if (!$className || !class_exists($className)) {
            $this->logWarning("JWT token parser class '{$className}' does not exist.");

            return null;
        }

        // check class implements RequestParserInterface
        if (!is_subclass_of($className, RequestParserInterface::class)) {
            $this->logWarning("JWT token parser class '{$className}' must implement " . RequestParserInterface::class);

            return null;
        }

        try {
            // use Hyperf DI container to create instance, allow to pass $options as constructor arguments
            // Hyperf container can match $options array keys with constructor argument names
            return $this->container->make($className, $options);
        } catch (\Throwable $e) {
            $this->logWarning("Failed to create JWT token parser '{$className}': " . $e->getMessage());

            return null;
        }
    }

    /**
     * Log a warning through the PSR-3 logger when one is bound in the container.
     * Logging is optional: when no logger is available the failure is skipped silently.
     */
    protected function logWarning(string $message): void
    {
        if ($this->container->has(LoggerInterface::class)) {
            $this->container->get(LoggerInterface::class)->warning($message);
        }
    }
}
