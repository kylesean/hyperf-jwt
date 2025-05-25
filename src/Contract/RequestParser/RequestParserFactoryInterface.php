<?php

declare(strict_types=1);

namespace FriendsOfHyperf\Jwt\Contract\RequestParser;

/**
 * Interface RequestParserFactoryInterface.
 *
 * 负责创建和提供一个有序的 RequestParserInterface 实例链。
 * Manager 将使用这个工厂来获取解析器，并按顺序尝试从请求中提取 JWT。
 */
interface RequestParserFactoryInterface
{
    /**
     * 获取配置的请求解析器链。
     *
     * @return RequestParserInterface[] 返回一个 RequestParserInterface 实例的数组，
     *                                  这些实例将按顺序用于尝试解析 JWT。
     */
    public function getParserChain(): array;

    /**
     * 根据给定的解析器类名或配置数组，创建一个解析器实例。
     *
     * @param string|array $parserConfig 解析器的类名，或者一个包含 'class' 和可选参数的配置数组。
     *                                   例如：\FriendsOfHyperf\Jwt\RequestParser\AuthorizationHeader::class
     *                                   或：[
     *                                       'class' => \FriendsOfHyperf\Jwt\RequestParser\QueryString::class,
     *                                       'options' => ['name' => 'jwt_token']
     *                                   ]
     * @return RequestParserInterface|null 如果无法创建解析器则返回 null。
     */
    public function createParser(string|array $parserConfig): ?RequestParserInterface;

    /**
     * 设置要使用的解析器配置。
     * 这通常来自用户配置文件中 'token_parsers' 的定义。
     *
     * @param array $parsersConfig 一个解析器配置数组，每个元素可以是类名或配置数组。
     *                             例如：
     *                             [
     *                                 \FriendsOfHyperf\Jwt\RequestParser\AuthorizationHeader::class,
     *                                 ['class' => \FriendsOfHyperf\Jwt\RequestParser\QueryString::class, 'options' => ['name' => 'custom_token_param']],
     *                                 new MyCustomParser(), // 也可以是已实例化的解析器对象
     *                             ]
     * @return $this
     */
    public function setParsersConfig(array $parsersConfig): self;
}