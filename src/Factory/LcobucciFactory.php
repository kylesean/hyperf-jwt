<?php

declare(strict_types=1);

namespace FriendsOfHyperf\Jwt\Factory;

use FriendsOfHyperf\Jwt\Exception\JwtException;
use Hyperf\Contract\ConfigInterface;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key\InMemory;
use Psr\Container\ContainerInterface;

class LcobucciFactory
{
    public function __invoke(ContainerInterface $container): Configuration
    {
        $config = $container->get(ConfigInterface::class);

        // 1. 检查是否有自定义的映射或工厂
        $customFactory = $config->get('jwt.lcobucci_config_factory');
        if ($customFactory) {
            if (is_callable($customFactory)) {
                return call_user_func($customFactory, $container);
            }
            if (is_string($customFactory) && $container->has($customFactory)) {
                return $container->get($customFactory);
            }
            throw new JwtException('Invalid jwt.lcobucci_config_factory configuration.');
        }

        // 2. 自动构建 Configuration
        $algoClass = $config->get('jwt.algo', Signer\Hmac\Sha256::class);
        if (!class_exists($algoClass) || !is_subclass_of($algoClass, Signer::class)) {
            throw new JwtException("Invalid JWT algorithm class: {$algoClass}");
        }

        $signer = is_string($algoClass) ? $container->get($algoClass) : $algoClass;

        if ($signer instanceof Signer\Hmac) {
            return $this->createSymmetricConfiguration($signer, $config);
        }

        if ($signer instanceof Signer\Rsa || $signer instanceof Signer\Ecdsa) {
            return $this->createAsymmetricConfiguration($signer, $config);
        }

        throw new JwtException('Unsupported JWT signer type: ' . get_class($signer));
    }

    protected function createSymmetricConfiguration(Signer\Hmac $signer, ConfigInterface $config): Configuration
    {
        $secret = (string) $config->get('jwt.secret');
        if (empty($secret)) {
            throw new JwtException('JWT secret is not configured for HMAC algorithm.');
        }

        return Configuration::forSymmetricSigner($signer, InMemory::plainText($secret));
    }

    protected function createAsymmetricConfiguration(Signer $signer, ConfigInterface $config): Configuration
    {
        $privateKeyPathOrContent = (string) $config->get('jwt.keys.private');
        $publicKeyPathOrContent = (string) $config->get('jwt.keys.public');
        $passphrase = $config->get('jwt.keys.passphrase');

        if (empty($privateKeyPathOrContent) || empty($publicKeyPathOrContent)) {
            throw new JwtException('Private or public key is not configured for asymmetric algorithm.');
        }

        $privateKeyPassphrase = ($passphrase === '' || $passphrase === null) ? '' : (string) $passphrase;

        $privateKey = str_starts_with($privateKeyPathOrContent, 'file://')
            ? InMemory::file(substr($privateKeyPathOrContent, 7), $privateKeyPassphrase)
            : InMemory::plainText($privateKeyPathOrContent, $privateKeyPassphrase);

        $publicKey = str_starts_with($publicKeyPathOrContent, 'file://')
            ? InMemory::file(substr($publicKeyPathOrContent, 7))
            : InMemory::plainText($publicKeyPathOrContent);

        return Configuration::forAsymmetricSigner($signer, $privateKey, $publicKey);
    }
}
