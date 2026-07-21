<?php

declare(strict_types=1);

error_reporting(E_ALL);

require_once dirname(__DIR__) . '/vendor/autoload.php';

if (!function_exists('env')) {
    function env(string $key, mixed $default = null): mixed
    {
        return \Hyperf\Support\env($key, $default);
    }
}
