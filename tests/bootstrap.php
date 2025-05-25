<?php

declare(strict_types=1);

error_reporting(E_ALL);
date_default_timezone_set('Asia/Shanghai'); // 或者你需要的时区

use Psr\SimpleCache\CacheInterface;

// Composer 自动加载
require_once dirname(__DIR__) . '/vendor/autoload.php';

// Hyperf DI 容器初始化 (如果测试需要)
// 如果你的单元测试不依赖 Hyperf 容器，可以暂时不初始化，或者使用 Hyperf\Testing\TestCase
// 这里我们先假设 Provider 的单元测试可以不完全依赖 Hyperf 容器的完整启动


echo "PHPUnit bootstrap file loaded.\n";
echo "PHP version: " . PHP_VERSION . "\n";
// 可选: 输出一些环境信息帮助调试