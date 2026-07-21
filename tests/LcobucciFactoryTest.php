<?php

declare(strict_types=1);

namespace Kylesean\Jwt\Tests;

use Hyperf\Contract\ConfigInterface;
use Kylesean\Jwt\Exception\JwtException;
use Kylesean\Jwt\Factory\LcobucciFactory;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Hmac\Sha256 as HmacSha256;
use Lcobucci\JWT\Signer\Hmac\Sha384 as HmacSha384;
use Lcobucci\JWT\Signer\Hmac\Sha512 as HmacSha512;
use Mockery;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;

#[CoversClass(LcobucciFactory::class)]
class LcobucciFactoryTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    protected Mockery\MockInterface|ContainerInterface $mockContainer;
    protected Mockery\MockInterface|ConfigInterface $mockConfig;
    protected LcobucciFactory $factory;

    protected function setUp(): void
    {
        parent::setUp();
        $this->mockContainer = Mockery::mock(ContainerInterface::class);
        $this->mockConfig = Mockery::mock(ConfigInterface::class);

        $this->mockContainer->shouldReceive('get')
            ->with(ConfigInterface::class)
            ->andReturn($this->mockConfig)
            ->byDefault();

        $this->factory = new LcobucciFactory();
    }

    protected function setupDefaultConfigMocks(): void
    {
        $this->mockConfig->shouldReceive('get')
            ->with('jwt.lcobucci_config_factory')
            ->andReturn(null)
            ->byDefault();
    }

    // --- HMAC (Symmetric) Tests ---

    public function testCreatesSymmetricHs256Configuration(): void
    {
        $this->setupDefaultConfigMocks();
        $this->mockConfig->shouldReceive('get')
            ->with('jwt.algo', Mockery::any())
            ->andReturn(HmacSha256::class);
        $this->mockConfig->shouldReceive('get')
            ->with('jwt.secret')
            ->andReturn('a_sufficiently_long_secret_key_for_hs256_testing');

        $this->mockContainer->shouldReceive('get')
            ->with(HmacSha256::class)
            ->andReturn(new HmacSha256());

        $config = ($this->factory)($this->mockContainer);

        $this->assertInstanceOf(Configuration::class, $config);
        $this->assertInstanceOf(HmacSha256::class, $config->signer());
    }

    public function testCreatesSymmetricHs384Configuration(): void
    {
        $this->setupDefaultConfigMocks();
        $this->mockConfig->shouldReceive('get')
            ->with('jwt.algo', Mockery::any())
            ->andReturn(HmacSha384::class);
        $this->mockConfig->shouldReceive('get')
            ->with('jwt.secret')
            ->andReturn('a_sufficiently_long_secret_key_for_hs384_testing_48bytes!');

        $this->mockContainer->shouldReceive('get')
            ->with(HmacSha384::class)
            ->andReturn(new HmacSha384());

        $config = ($this->factory)($this->mockContainer);

        $this->assertInstanceOf(Configuration::class, $config);
        $this->assertInstanceOf(HmacSha384::class, $config->signer());
    }

    public function testCreatesSymmetricHs512Configuration(): void
    {
        $this->setupDefaultConfigMocks();
        $this->mockConfig->shouldReceive('get')
            ->with('jwt.algo', Mockery::any())
            ->andReturn(HmacSha512::class);
        $this->mockConfig->shouldReceive('get')
            ->with('jwt.secret')
            ->andReturn('a_very_sufficiently_long_secret_key_for_hs512_testing_that_is_64bytes_long_!');

        $this->mockContainer->shouldReceive('get')
            ->with(HmacSha512::class)
            ->andReturn(new HmacSha512());

        $config = ($this->factory)($this->mockContainer);

        $this->assertInstanceOf(Configuration::class, $config);
        $this->assertInstanceOf(HmacSha512::class, $config->signer());
    }

    public function testThrowsExceptionWhenHmacSecretIsEmpty(): void
    {
        $this->expectException(JwtException::class);
        $this->expectExceptionMessage('JWT secret is not configured for HMAC algorithm.');

        $this->setupDefaultConfigMocks();
        $this->mockConfig->shouldReceive('get')
            ->with('jwt.algo', Mockery::any())
            ->andReturn(HmacSha256::class);
        $this->mockConfig->shouldReceive('get')
            ->with('jwt.secret')
            ->andReturn('');

        $this->mockContainer->shouldReceive('get')
            ->with(HmacSha256::class)
            ->andReturn(new HmacSha256());

        ($this->factory)($this->mockContainer);
    }

    public function testThrowsExceptionWhenHmacSecretIsNull(): void
    {
        $this->expectException(JwtException::class);
        $this->expectExceptionMessage('JWT secret is not configured for HMAC algorithm.');

        $this->setupDefaultConfigMocks();
        $this->mockConfig->shouldReceive('get')
            ->with('jwt.algo', Mockery::any())
            ->andReturn(HmacSha256::class);
        $this->mockConfig->shouldReceive('get')
            ->with('jwt.secret')
            ->andReturn(null);

        $this->mockContainer->shouldReceive('get')
            ->with(HmacSha256::class)
            ->andReturn(new HmacSha256());

        ($this->factory)($this->mockContainer);
    }

    // --- Invalid Algorithm Tests ---

    public function testThrowsExceptionForInvalidAlgoClass(): void
    {
        $this->expectException(JwtException::class);
        $this->expectExceptionMessage('Invalid JWT algorithm class');

        $this->setupDefaultConfigMocks();
        $this->mockConfig->shouldReceive('get')
            ->with('jwt.algo', Mockery::any())
            ->andReturn('NonExistentAlgoClass');

        ($this->factory)($this->mockContainer);
    }

    public function testThrowsExceptionForNonSignerClass(): void
    {
        $this->expectException(JwtException::class);
        $this->expectExceptionMessage('Invalid JWT algorithm class');

        $this->setupDefaultConfigMocks();
        $this->mockConfig->shouldReceive('get')
            ->with('jwt.algo', Mockery::any())
            ->andReturn(\stdClass::class);

        ($this->factory)($this->mockContainer);
    }

    // --- Custom Factory Tests ---

    public function testUsesCustomCallableFactory(): void
    {
        $expectedConfig = Configuration::forSymmetricSigner(
            new HmacSha256(),
            \Lcobucci\JWT\Signer\Key\InMemory::plainText('custom_factory_secret_key_32bytes!')
        );

        $this->mockConfig->shouldReceive('get')
            ->with('jwt.lcobucci_config_factory')
            ->andReturn(function ($container) use ($expectedConfig) {
                return $expectedConfig;
            });

        $config = ($this->factory)($this->mockContainer);

        $this->assertSame($expectedConfig, $config);
    }

    public function testUsesCustomStringFactory(): void
    {
        $expectedConfig = Configuration::forSymmetricSigner(
            new HmacSha256(),
            \Lcobucci\JWT\Signer\Key\InMemory::plainText('string_factory_secret_key_32bytes!')
        );

        $this->mockConfig->shouldReceive('get')
            ->with('jwt.lcobucci_config_factory')
            ->andReturn('CustomConfigFactory');

        $this->mockContainer->shouldReceive('has')
            ->with('CustomConfigFactory')
            ->andReturn(true);
        $this->mockContainer->shouldReceive('get')
            ->with('CustomConfigFactory')
            ->andReturn($expectedConfig);

        $config = ($this->factory)($this->mockContainer);

        $this->assertSame($expectedConfig, $config);
    }

    public function testThrowsExceptionForInvalidCustomFactory(): void
    {
        $this->expectException(JwtException::class);
        $this->expectExceptionMessage('Invalid jwt.lcobucci_config_factory configuration.');

        $this->mockConfig->shouldReceive('get')
            ->with('jwt.lcobucci_config_factory')
            ->andReturn('NonExistentFactory');

        $this->mockContainer->shouldReceive('has')
            ->with('NonExistentFactory')
            ->andReturn(false);

        ($this->factory)($this->mockContainer);
    }

    // --- Asymmetric (RSA) Tests ---

    public function testCreatesAsymmetricRsaConfiguration(): void
    {
        $this->setupDefaultConfigMocks();

        // Generate a real RSA key pair for testing
        $rsaConfig = [
            'digest_alg' => 'sha256',
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ];
        $privateKeyResource = openssl_pkey_new($rsaConfig);
        if ($privateKeyResource === false) {
            $this->markTestSkipped('OpenSSL RSA key generation not available.');
        }
        $privateKeyPem = '';
        openssl_pkey_export($privateKeyResource, $privateKeyPem);
        $publicKeyDetails = openssl_pkey_get_details($privateKeyResource);
        $publicKeyPem = $publicKeyDetails['key'];

        $this->mockConfig->shouldReceive('get')
            ->with('jwt.algo', Mockery::any())
            ->andReturn(Signer\Rsa\Sha256::class);
        $this->mockConfig->shouldReceive('get')
            ->with('jwt.keys.private')
            ->andReturn($privateKeyPem);
        $this->mockConfig->shouldReceive('get')
            ->with('jwt.keys.public')
            ->andReturn($publicKeyPem);
        $this->mockConfig->shouldReceive('get')
            ->with('jwt.keys.passphrase')
            ->andReturn(null);

        $this->mockContainer->shouldReceive('get')
            ->with(Signer\Rsa\Sha256::class)
            ->andReturn(new Signer\Rsa\Sha256());

        $config = ($this->factory)($this->mockContainer);

        $this->assertInstanceOf(Configuration::class, $config);
        $this->assertInstanceOf(Signer\Rsa\Sha256::class, $config->signer());
    }

    public function testThrowsExceptionWhenAsymmetricKeysAreMissing(): void
    {
        $this->expectException(JwtException::class);
        $this->expectExceptionMessage('Private or public key is not configured for asymmetric algorithm.');

        $this->setupDefaultConfigMocks();
        $this->mockConfig->shouldReceive('get')
            ->with('jwt.algo', Mockery::any())
            ->andReturn(Signer\Rsa\Sha256::class);
        $this->mockConfig->shouldReceive('get')
            ->with('jwt.keys.private')
            ->andReturn('');
        $this->mockConfig->shouldReceive('get')
            ->with('jwt.keys.public')
            ->andReturn('');
        $this->mockConfig->shouldReceive('get')
            ->with('jwt.keys.passphrase')
            ->andReturn(null);

        $this->mockContainer->shouldReceive('get')
            ->with(Signer\Rsa\Sha256::class)
            ->andReturn(new Signer\Rsa\Sha256());

        ($this->factory)($this->mockContainer);
    }

    // --- ECDSA Tests ---

    public function testCreatesAsymmetricEcdsaConfiguration(): void
    {
        $this->setupDefaultConfigMocks();

        // Generate a real ECDSA key pair for testing
        $ecConfig = [
            'digest_alg' => 'sha256',
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ];
        $privateKeyResource = openssl_pkey_new($ecConfig);
        if ($privateKeyResource === false) {
            $this->markTestSkipped('OpenSSL ECDSA key generation not available.');
        }
        $privateKeyPem = '';
        openssl_pkey_export($privateKeyResource, $privateKeyPem);
        $publicKeyDetails = openssl_pkey_get_details($privateKeyResource);
        $publicKeyPem = $publicKeyDetails['key'];

        $this->mockConfig->shouldReceive('get')
            ->with('jwt.algo', Mockery::any())
            ->andReturn(Signer\Ecdsa\Sha256::class);
        $this->mockConfig->shouldReceive('get')
            ->with('jwt.keys.private')
            ->andReturn($privateKeyPem);
        $this->mockConfig->shouldReceive('get')
            ->with('jwt.keys.public')
            ->andReturn($publicKeyPem);
        $this->mockConfig->shouldReceive('get')
            ->with('jwt.keys.passphrase')
            ->andReturn(null);

        $this->mockContainer->shouldReceive('get')
            ->with(Signer\Ecdsa\Sha256::class)
            ->andReturn(new Signer\Ecdsa\Sha256());

        $config = ($this->factory)($this->mockContainer);

        $this->assertInstanceOf(Configuration::class, $config);
        $this->assertInstanceOf(Signer\Ecdsa\Sha256::class, $config->signer());
    }
}
