<?php

declare(strict_types=1);

namespace Kylesean\Jwt\Tests;

use Kylesean\Jwt\Command\GenJwtKeyCommand;
use Kylesean\Jwt\ConfigProvider;
use Kylesean\Jwt\Contract\ManagerInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(ConfigProvider::class)]
class ConfigProviderTest extends TestCase
{
    public function testInvokeReturnsValidConfigurationArray(): void
    {
        $configProvider = new ConfigProvider();
        $config = $configProvider();

        $this->assertIsArray($config);
        $this->assertArrayHasKey('dependencies', $config);
        $this->assertArrayHasKey('commands', $config);
        $this->assertArrayHasKey('publish', $config);
        $this->assertArrayHasKey('annotations', $config);

        // Verify key DI bindings
        $this->assertArrayHasKey(ManagerInterface::class, $config['dependencies']);

        // Verify commands
        $this->assertContains(GenJwtKeyCommand::class, $config['commands']);

        // Verify publish structure
        $this->assertNotEmpty($config['publish']);
        $this->assertEquals('config', $config['publish'][0]['id']);
    }
}
