<?php

declare(strict_types=1);

namespace Kylesean\Jwt\Tests;

use DateTimeImmutable;
use Kylesean\Jwt\PayloadFactory;
use Hyperf\Contract\ConfigInterface;
use Mockery;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(PayloadFactory::class)]
class PayloadFactoryTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    protected Mockery\MockInterface|ConfigInterface $mockConfig;

    protected function setUp(): void
    {
        parent::setUp();
        $this->mockConfig = Mockery::mock(ConfigInterface::class);
    }

    // Helper method to create PayloadFactory instance with preset Config mock
    private function createPayloadFactory(array $configGetReturns = []): PayloadFactory
    {
        // Set default return behavior for ConfigInterface::get
        // If key is not specified in $configGetReturns, return second argument (default value)
        $this->mockConfig->shouldReceive('get')
            ->with(Mockery::any(), Mockery::any()) // Match any key and default value
            ->andReturnUsing(function ($key, $default) use ($configGetReturns) {
                return $configGetReturns[$key] ?? $default; // Use specified return value if set in test
            })
            ->byDefault(); // Allow override in specific tests

        return new PayloadFactory($this->mockConfig);
    }

    public function testConstructorInitializesPropertiesFromConfigWithDefaults(): void
    {
        // Test whether hardcoded defaults are used when no jwt.* entries exist in config
        // createPayloadFactory([]) causes all config->get calls to return their second argument (default value)
        $factory = $this->createPayloadFactory([
            // Simulate ConfigInterface::get('jwt.ttl', 60) returning 60 (second parameter)
            // Simulate ConfigInterface::get('jwt.nbf_offset_seconds', 0) returning 0 (second parameter)
            // ...etc.
        ]);

        $this->assertEquals(60, $factory->getTtl());
        $this->assertEquals(0, $factory->getNbfOffsetSeconds());
        $this->assertEquals('Hyperf App', $factory->getIssuer()); // Default value in PayloadFactory constructor
        $this->assertEquals('Hyperf App', $factory->getAudience()); // Same as above
    }

    public function testConstructorInitializesPropertiesFromConfigWithProvidedValues(): void
    {
        $factory = $this->createPayloadFactory([
            'jwt.ttl' => 120,
            'jwt.nbf_offset_seconds' => 10,
            'jwt.issuer' => 'my-custom-issuer',
            'jwt.audience' => ['aud1', 'aud2'],
        ]);

        $this->assertEquals(120, $factory->getTtl());
        $this->assertEquals(10, $factory->getNbfOffsetSeconds());
        $this->assertEquals('my-custom-issuer', $factory->getIssuer());
        $this->assertEquals(['aud1', 'aud2'], $factory->getAudience());
    }

    public function testSetAndGetTtl(): void
    {
        $factory = $this->createPayloadFactory(); // Construct with default config
        $factory->setTtl(90);
        $this->assertEquals(90, $factory->getTtl());

        $factory->setTtl(0); // Test boundary, should be at least 1
        $this->assertEquals(1, $factory->getTtl());

        $factory->setTtl(-10); // Test negative number, should be at least 1
        $this->assertEquals(1, $factory->getTtl());

        // Test maximum TTL boundary (1 year)
        $factory->setTtl(PayloadFactory::MAX_TTL_MINUTES);
        $this->assertEquals(PayloadFactory::MAX_TTL_MINUTES, $factory->getTtl());

        // Test TTL exceeds maximum, should be capped
        $factory->setTtl(PayloadFactory::MAX_TTL_MINUTES + 1);
        $this->assertEquals(PayloadFactory::MAX_TTL_MINUTES, $factory->getTtl());
    }

    public function testSetAndGetRefreshTtl(): void
    {
        $factory = $this->createPayloadFactory();

        $factory->setRefreshTtl(30000);
        $this->assertEquals(30000, $factory->getRefreshTtl());

        $factory->setRefreshTtl(0); // Test boundary, should be at least 1
        $this->assertEquals(1, $factory->getRefreshTtl());

        $factory->setRefreshTtl(-10); // Test negative number, should be at least 1
        $this->assertEquals(1, $factory->getRefreshTtl());

        // Test maximum refresh TTL boundary (2 years)
        $factory->setRefreshTtl(PayloadFactory::MAX_REFRESH_TTL_MINUTES);
        $this->assertEquals(PayloadFactory::MAX_REFRESH_TTL_MINUTES, $factory->getRefreshTtl());

        // Test refresh TTL exceeds maximum, should be capped
        $factory->setRefreshTtl(PayloadFactory::MAX_REFRESH_TTL_MINUTES + 100);
        $this->assertEquals(PayloadFactory::MAX_REFRESH_TTL_MINUTES, $factory->getRefreshTtl());
    }

    public function testSetAndGetNbfOffsetSeconds(): void
    {
        $factory = $this->createPayloadFactory();
        $factory->setNbfOffsetSeconds(30);
        $this->assertEquals(30, $factory->getNbfOffsetSeconds());

        $factory->setNbfOffsetSeconds(-5); // Allow negative numbers, though not practically useful
        $this->assertEquals(-5, $factory->getNbfOffsetSeconds());
    }

    public function testSetAndGetIssuer(): void
    {
        $factory = $this->createPayloadFactory();
        $factory->setIssuer('new-issuer');
        $this->assertEquals('new-issuer', $factory->getIssuer());
    }

    public function testSetAndGetAudience(): void
    {
        $factory = $this->createPayloadFactory();
        $factory->setAudience('single-aud');
        $this->assertEquals('single-aud', $factory->getAudience());

        $factory->setAudience(['aud-array1', 'aud-array2']);
        $this->assertEquals(['aud-array1', 'aud-array2'], $factory->getAudience());
    }

    public function testGetCurrentTime(): void
    {
        $factory = $this->createPayloadFactory();
        $this->assertInstanceOf(DateTimeImmutable::class, $factory->getCurrentTime());
        // Can assert time is roughly accurate with slight millisecond delta
        $this->assertEqualsWithDelta(time(), $factory->getCurrentTime()->getTimestamp(), 1.0);
    }

    public function testGenerateJti(): void
    {
        $factory = $this->createPayloadFactory();
        $jti1 = $factory->generateJti();
        $jti2 = $factory->generateJti();

        $this->assertIsString($jti1);
        $this->assertNotEmpty($jti1);
        $this->assertEquals(32, strlen($jti1)); // bin2hex(random_bytes(16)) results in 32 hex characters
        $this->assertNotEquals($jti1, $jti2);
    }

    public function testGetClaimsToRefreshDefault(): void
    {
        // Test returning defaults when 'jwt.claims_to_refresh' is not in config
        $factory = $this->createPayloadFactory([
            'jwt.claims_to_refresh' => null, // Simulate missing or null entry in config
        ]);
        $this->assertEquals(['iat', 'exp', 'nbf', 'jti'], $factory->getClaimsToRefresh());
    }

    public function testGetClaimsToRefreshWithUserConfig(): void
    {
        $factory = $this->createPayloadFactory([
            'jwt.claims_to_refresh' => ['custom_claim1', 'iat'], // User config, iat is duplicated
        ]);
        $expected = ['iat', 'exp', 'nbf', 'jti', 'custom_claim1'];
        $actual = $factory->getClaimsToRefresh();
        // Compare elements exist regardless of array_unique and array_merge order
        sort($expected);
        sort($actual);
        $this->assertEquals($expected, $actual);
    }

    public function testGetClaimsToRefreshWithEmptyUserConfig(): void
    {
        $factory = $this->createPayloadFactory([
            'jwt.claims_to_refresh' => [], // User config is empty array
        ]);
        // Default 'iat', 'exp', 'nbf', 'jti' should still be present even if config is empty
        $this->assertEquals(['iat', 'exp', 'nbf', 'jti'], $factory->getClaimsToRefresh());
    }
}