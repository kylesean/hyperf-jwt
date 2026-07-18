<?php

declare(strict_types=1);

error_reporting(E_ALL);
date_default_timezone_set('Asia/Shanghai');

require_once dirname(__DIR__) . '/vendor/autoload.php';


// Optional: Print environment info for debugging

if (!function_exists('env')) {
    function env(string $key, mixed $default = null): mixed
    {
        return \Hyperf\Support\env($key, $default);
    }
}


// Hyperf DI container initialization (if required for tests)
// If unit tests do not depend on the Hyperf container, initialization can be skipped or Hyperf\Testing\TestCase can be used.
// Here we assume provider unit tests do not strictly require a full Hyperf container boot.

echo "PHPUnit bootstrap file loaded.\n";
echo "PHP version: " . PHP_VERSION . "\n";