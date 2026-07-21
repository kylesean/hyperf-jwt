<?php

declare(strict_types=1);

namespace Kylesean\Jwt\Tests\Command;

use Kylesean\Jwt\Command\GenJwtKeyCommand;
use Mockery;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[CoversClass(GenJwtKeyCommand::class)]
class GenJwtKeyCommandTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    protected Mockery\MockInterface|ContainerInterface $mockContainer;
    protected GenJwtKeyCommand $command;

    protected function setUp(): void
    {
        parent::setUp();
        $this->mockContainer = Mockery::mock(ContainerInterface::class);
        $this->command = new GenJwtKeyCommand($this->mockContainer);
    }

    protected function createMockInput(array $options = []): InputInterface|Mockery\MockInterface
    {
        $mockInput = Mockery::mock(InputInterface::class);
        $mockInput->shouldReceive('bind')->andReturnUndefined()->byDefault();
        $mockInput->shouldReceive('isInteractive')->andReturn(false)->byDefault();
        $mockInput->shouldReceive('hasArgument')->andReturn(false)->byDefault();
        $mockInput->shouldReceive('validate')->andReturnUndefined()->byDefault();

        // Default getOption handler returns null for any unspecified option
        $mockInput->shouldReceive('getOption')
            ->andReturnUsing(fn (string $name) => $options[$name] ?? null)
            ->byDefault();

        return $mockInput;
    }

    protected function createMockOutput(): SymfonyStyle|Mockery\MockInterface
    {
        $mockOutput = Mockery::mock(SymfonyStyle::class);
        $mockOutput->shouldReceive('success')->byDefault();
        $mockOutput->shouldReceive('writeln')->byDefault();
        $mockOutput->shouldReceive('block')->byDefault();
        $mockOutput->shouldReceive('error')->byDefault();
        $mockOutput->shouldReceive('info')->byDefault();
        $mockOutput->shouldReceive('warning')->byDefault();

        return $mockOutput;
    }

    public function testCommandNameAndDescription(): void
    {
        $this->assertEquals('jwt:gen-key', $this->command->getName());
        $this->assertNotEmpty($this->command->getDescription());
    }

    public function testGenerateHmacSecretHs256(): void
    {
        $mockInput = $this->createMockInput([
            'algo' => 'hs256',
            'update-env' => false,
        ]);
        $mockOutput = $this->createMockOutput();

        $this->command->setInput($mockInput);
        $this->command->setOutput($mockOutput);

        $exitCode = $this->command->handle();
        $this->assertEquals(0, $exitCode);
    }

    public function testGenerateHmacSecretHs512(): void
    {
        $mockInput = $this->createMockInput([
            'algo' => 'hs512',
            'update-env' => false,
        ]);
        $mockOutput = $this->createMockOutput();

        $this->command->setInput($mockInput);
        $this->command->setOutput($mockOutput);

        $exitCode = $this->command->handle();
        $this->assertEquals(0, $exitCode);
    }

    public function testGenerateRsaKeyPair(): void
    {
        $mockInput = $this->createMockInput([
            'algo' => 'rs256',
            'bits' => 2048,
            'password' => null,
            'update-env' => false,
            'output-private-key' => null,
            'output-public-key' => null,
        ]);
        $mockOutput = $this->createMockOutput();

        $this->command->setInput($mockInput);
        $this->command->setOutput($mockOutput);

        $exitCode = $this->command->handle();
        $this->assertEquals(0, $exitCode);
    }

    public function testGenerateEcdsaKeyPair(): void
    {
        $mockInput = $this->createMockInput([
            'algo' => 'es256',
            'curve' => 'prime256v1',
            'password' => null,
            'update-env' => false,
            'output-private-key' => null,
            'output-public-key' => null,
        ]);
        $mockOutput = $this->createMockOutput();

        $this->command->setInput($mockInput);
        $this->command->setOutput($mockOutput);

        $exitCode = $this->command->handle();
        $this->assertEquals(0, $exitCode);
    }

    public function testUnsupportedAlgorithmReturnsError(): void
    {
        $mockInput = $this->createMockInput([
            'algo' => 'unsupported_algo',
        ]);
        $mockOutput = $this->createMockOutput();

        $this->command->setInput($mockInput);
        $this->command->setOutput($mockOutput);

        $exitCode = $this->command->handle();
        $this->assertEquals(1, $exitCode);
    }
}
