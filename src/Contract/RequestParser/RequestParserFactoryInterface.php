<?php

declare(strict_types=1);

namespace Kylesean\Jwt\Contract\RequestParser;

/**
 * Interface RequestParserFactoryInterface.
 *
 * Responsible for creating and providing an ordered chain of RequestParserInterface instances.
 * Manager will use this factory to get parsers and try to extract JWT from the request in order.
 */
interface RequestParserFactoryInterface
{
    /**
     * Get the configured request parser chain.
     *
     * @return RequestParserInterface[] An array of RequestParserInterface instances that will be used in order to try to parse the JWT.
     */
    public function getParserChain(): array;

    /**
     * Create a parser instance based on the given parser class name or configuration array.
     *
     * @param string|array<int|string, mixed> $parserConfig The class name of the parser, or a configuration array containing 'class' and optional parameters.
     * @return RequestParserInterface|null Returns null if the parser cannot be created.
     */
    public function createParser(string|array $parserConfig): ?RequestParserInterface;

    /**
     * Set the parser configuration to be used.
     * This usually comes from the 'token_parsers' definition in the user's configuration file.
     *
     * @param array<int, string|array<string, mixed>|RequestParserInterface> $parsersConfig An array of parser configurations, where each element can be a class name or a configuration array.
     *                             For example:
     *                             [
     *                                 \Kylesean\Jwt\RequestParser\AuthorizationHeader::class,
     *                                 ['class' => \Kylesean\Jwt\RequestParser\QueryString::class, 'options' => ['name' => 'custom_token_param']],
     *                                 new MyCustomParser(), // can also be an instantiated parser object
     *                             ]
     * @return $this
     */
    public function setParsersConfig(array $parsersConfig): self;
}