<?php

declare(strict_types=1);

namespace FriendsOfHyperf\Jwt\Tests;

// 继承 Hyperf 的测试基类
use Hyperf\Testing\TestCase as HyperfTestCase;
use Mockery; // 如果你还想在其他非Hyperf特定测试中使用Mockery

/**
 * 基础测试用例类
 * 所有单元测试都应继承此类
 */
abstract class TestCase extends HyperfTestCase // 修改这里
{
    // setUp 和 tearDown 通常由 HyperfTestCase 处理，
    // 或者你可以覆盖它们，但记得调用 parent::setUp() / parent::tearDown()

    // 如果你之前在 TestCase 中有 Mockery::close()，可以保留或移到需要的测试类的 tearDown
    // protected function tearDown(): void
    // {
    //     Mockery::close();
    //     parent::tearDown();
    // }
}