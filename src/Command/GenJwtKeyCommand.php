<?php

declare(strict_types=1);

namespace FriendsOfHyperf\Jwt\Command;

use Hyperf\Command\Command as HyperfCommand;
use Hyperf\Command\Annotation\Command;
use Psr\Container\ContainerInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Input\InputArgument; // 用于输出文件路径

#[Command]
class GenJwtKeyCommand extends HyperfCommand
{
    protected ContainerInterface $container;

    public function __construct(ContainerInterface $container)
    {
        parent::__construct('jwt:gen-key');
        $this->container = $container;
        $this->setDescription('Generate a new JWT secret key (for HMAC) or key pair (for RSA/ECDSA).');
    }

    public function handle()
    {
        $algoOption = $this->input->getOption('algo');
        $algo = is_string($algoOption) ? strtolower($algoOption) : 'hs256';

        if (str_starts_with($algo, 'hs')) {
            $this->generateHmacSecret($algo);
        } elseif (str_starts_with($algo, 'rs')) {
            $this->generateRsaKeyPair($algo);
        } elseif (str_starts_with($algo, 'es')) {
            $this->generateEcdsaKeyPair($algo);
        } else {
            $this->output->error(sprintf('Unsupported algorithm: %s. Supported families: HS*, RS*, ES*.', $algo));
            return 1;
        }
        return 0;
    }

    protected function generateHmacSecret(string $algo): void
    {
        // ... (HMAC 生成逻辑保持不变) ...
        $length = 32;
        if ($algo === 'hs384') { $length = 48; }
        elseif ($algo === 'hs512') { $length = 64; }

        try {
            $key = random_bytes($length);
            $secret = bin2hex($key);
        } catch (\Exception $e) {
            $this->output->error('Could not generate a cryptographically secure random key: ' . $e->getMessage());
            // ... (降级逻辑) ...
            $secret = sha1(uniqid((string) microtime(true) . random_int(0, mt_getrandmax()), true));
            $secret = substr($secret . sha1($secret), 0, $length * 2);
        }

        $this->output->success(sprintf('Successfully generated new JWT secret for %s.', strtoupper($algo)));
        $this->output->writeln('');
        $this->output->writeln('Your new JWT secret is:');
        $this->output->block($secret);
        $this->output->writeln('');
        $this->output->writeln('Please set this value in your <comment>.env</comment> file as:');
        $this->output->writeln("JWT_SECRET={$secret}");
        // ... (其他提示信息)
        $signerClass = '\\Lcobucci\\JWT\\Signer\\Hmac\\Sha' . substr($algo, 2);
        $this->output->writeln("<info>'algo' => {$signerClass}::class,</info>");
        $this->output->writeln('');

        if ($this->input->getOption('update-env')) {
            $this->updateEnvFile('JWT_SECRET', $secret);
        } elseif ($this->input->isInteractive() && $this->output->confirm('Do you want to attempt to update your .env file automatically?', false)) {
            $this->updateEnvFile('JWT_SECRET', $secret);
        }
    }

    protected function generateRsaKeyPair(string $algo): void
    {
        $bits = (int) $this->input->getOption('bits');
        $password = $this->input->getOption('password');
        if ($password === null && $this->input->isInteractive() && $this->output->confirm('Do you want to protect the private key with a password?', false)) {
            $password = $this->output->askHidden('Enter password for private key (leave empty for no password):');
            if (empty($password)) $password = null;
        }


        $this->output->writeln(sprintf('Generating RSA-%d key pair for %s...', $bits, strtoupper($algo)));

        $config = [
            "digest_alg" => match (strtoupper($algo)) { // 根据算法选择合适的摘要算法
                "RS384" => "sha384",
                "RS512" => "sha512",
                default => "sha256", // RS256
            },
            "private_key_bits" => $bits,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        ];

        // 生成密钥对
        $privateKeyResource = openssl_pkey_new($config);
        if ($privateKeyResource === false) {
            $this->output->error('Failed to generate RSA private key: ' . openssl_error_string());
            return;
        }

        // 导出私钥
        $privateKeyPem = '';
        $exportResult = $password
            ? openssl_pkey_export($privateKeyResource, $privateKeyPem, $password)
            : openssl_pkey_export($privateKeyResource, $privateKeyPem);

        if ($exportResult === false) {
            $this->output->error('Failed to export RSA private key: ' . openssl_error_string());
            return;
        }

        // 获取公钥详情
        $publicKeyDetails = openssl_pkey_get_details($privateKeyResource);
        if ($publicKeyDetails === false || !isset($publicKeyDetails['key'])) {
            $this->output->error('Failed to get RSA public key details: ' . openssl_error_string());
            return;
        }
        $publicKeyPem = $publicKeyDetails['key'];

        $this->outputKeyPairResults($privateKeyPem, $publicKeyPem, $password, strtoupper($algo));
    }

    protected function generateEcdsaKeyPair(string $algo): void
    {
        $curve = (string) $this->input->getOption('curve');
        $password = $this->input->getOption('password');
        if ($password === null && $this->input->isInteractive() && $this->output->confirm('Do you want to protect the private key with a password?', false)) {
            $password = $this->output->askHidden('Enter password for private key (leave empty for no password):');
            if (empty($password)) $password = null;
        }

        $this->output->writeln(sprintf('Generating ECDSA key pair with curve %s for %s...', $curve, strtoupper($algo)));

        $config = [
            "digest_alg" => match (strtoupper($algo)) { // 根据算法选择合适的摘要算法
                "ES384" => "sha384",
                "ES512" => "sha512",
                default => "sha256", // ES256
            },
            "private_key_type" => OPENSSL_KEYTYPE_EC,
            "curve_name" => $curve,
        ];

        $privateKeyResource = openssl_pkey_new($config);
        if ($privateKeyResource === false) {
            $this->output->error('Failed to generate ECDSA private key: ' . openssl_error_string() . ' (Ensure the curve name is valid and OpenSSL supports it)');
            return;
        }

        // 导出私钥 (ECDSA 私钥导出通常不直接在 openssl_pkey_export 中使用密码参数进行 PKCS#1 加密，而是导出为 PKCS#8 格式再加密)
        // 我们先导出未加密的 PKCS#8，如果需要加密，再进行一次转换
        $privateKeyPemUnencrypted = '';
        if (!openssl_pkey_export($privateKeyResource, $privateKeyPemUnencrypted)) { // 先导出未加密的
            $this->output->error('Failed to export ECDSA private key (initial export): ' . openssl_error_string());
            return;
        }

        $privateKeyPem = $privateKeyPemUnencrypted; // 默认使用未加密的

        if ($password) {
            // 如果需要密码，将未加密的 PKCS#8 私钥用密码加密
            // Lcobucci/jwt 的 InMemory::file/plainText 期望的是 PKCS#1 (RSA) 或 PKCS#8 (EC) 加密格式
            // openssl_pkey_export 导出的 EC 私钥已经是 PKCS#8 格式（如果 OpenSSL 版本较新）
            // 如果要加密，可能需要类似 `openssl pkcs8 -topk8 -passout ...` 的操作，PHP中略复杂
            // 对于 ECDSA，一个简单的方法是提示用户如何手动加密，或者使用未加密的私钥并强调文件权限保护
            // 这里我们暂时不直接在PHP中实现EC私钥的密码加密，因为openssl_pkey_export对EC密钥的密码支持不如RSA直接
            $this->output->warning("Password protection for ECDSA private keys via this command is complex to implement directly in PHP for broad compatibility. The private key is generated عشقunencrypted.");
            $this->output->writeln("It's highly recommended to secure the unencrypted private key file with strict file permissions, or encrypt it manually using OpenSSL tools if password protection is required for the key file itself.");
            $this->output->writeln("Example: openssl ec -in <unencrypted_private_key.pem> -out <encrypted_private_key.pem> -aes256 -passout pass:your_password");
            $password = null; // 重置password变量，因为我们没实际用它加密EC私钥
        }


        $publicKeyDetails = openssl_pkey_get_details($privateKeyResource);
        if ($publicKeyDetails === false || !isset($publicKeyDetails['key'])) {
            $this->output->error('Failed to get ECDSA public key details: ' . openssl_error_string());
            return;
        }
        $publicKeyPem = $publicKeyDetails['key'];

        $this->outputKeyPairResults($privateKeyPem, $publicKeyPem, $password, strtoupper($algo));
    }

    protected function outputKeyPairResults(string $privateKeyPem, string $publicKeyPem, ?string $password, string $algoName): void
    {
        $this->output->success(sprintf('Successfully generated new JWT key pair for %s.', $algoName));
        $this->output->writeln('');

        $this->output->writeln('<comment>Private Key (SAVE THIS SECURELY - DO NOT COMMIT TO VERSION CONTROL IF HARDCODED):</comment>');
        $this->output->block($privateKeyPem);
        $this->output->writeln('');

        $this->output->writeln('<comment>Public Key:</comment>');
        $this->output->block($publicKeyPem);
        $this->output->writeln('');

        $this->output->writeln('Please configure these in your <comment>jwt.php</comment> config or <comment>.env</comment> file:');
        $this->output->writeln('');
        $this->output->writeln("<info>// In config/autoload/jwt.php or your .env file:</info>");
        $signerClassParts = explode('\\', $this->input->getOption('algo')); // 获取用户输入的算法类名
        $signerClass = $this->input->getOption('algo');
        if (!class_exists($signerClass)) { // 如果用户输入的是简写，尝试构建
            $algoShort = str_replace(['rs','es'], '', strtolower($algoName)); // 256, 384, 512
            $algoFamily = strtolower(substr($algoName, 0, 2)); // rs, es
            $signerClass = '\\Lcobucci\\JWT\\Signer\\' . ucfirst($algoFamily) . '\\Sha' . $algoShort;
        }

        $this->output->writeln("<info>'algo' => {$signerClass}::class,</info>");
        $this->output->writeln("<info>'keys' => [</info>");
        $this->output->writeln("<info>    'public' => env('JWT_PUBLIC_KEY', <<<EOT</info>");
        $this->output->writeln("<info>" . $publicKeyPem . "</info>");
        $this->output->writeln("<info>EOT</info>");
        $this->output->writeln("<info>    ),</info>");
        $this->output->writeln("<info>    'private' => env('JWT_PRIVATE_KEY', <<<EOT</info>");
        $this->output->writeln("<info>" . $privateKeyPem . "</info>");
        $this->output->writeln("<info>EOT</info>");
        $this->output->writeln("<info>    ),</info>");
        if ($password) {
            $this->output->writeln("<info>    'passphrase' => env('JWT_PASSPHRASE', '{$password}'),</info>");
        } else {
            $this->output->writeln("<info>    'passphrase' => env('JWT_PASSPHRASE', null),</info>");
        }
        $this->output->writeln("<info>],</info>");
        $this->output->writeln('');
        $this->output->writeln("Or, use 'file:///path/to/your/key.pem' for key paths.");

        // 尝试写入文件 (可选)
        $privateKeyFile = $this->input->getOption('output-private-key');
        $publicKeyFile = $this->input->getOption('output-public-key');

        if ($privateKeyFile) {
            if (file_put_contents($privateKeyFile, $privateKeyPem) !== false) {
                $this->output->info("Private key saved to: {$privateKeyFile}");
            } else {
                $this->output->warning("Failed to save private key to: {$privateKeyFile}");
            }
        }
        if ($publicKeyFile) {
            if (file_put_contents($publicKeyFile, $publicKeyPem) !== false) {
                $this->output->info("Public key saved to: {$publicKeyFile}");
            } else {
                $this->output->warning("Failed to save public key to: {$publicKeyFile}");
            }
        }
    }

    // updateEnvFile 保持不变
    protected function updateEnvFile(string $keyName, string $keyValue): void
    {
        // ... (代码同前) ...
    }

    protected function configure(): void
    {
        parent::configure(); // 调用父类的 configure
        $this->addOption('algo', 'a', InputOption::VALUE_OPTIONAL, 'The signing algorithm (e.g., HS256, RS256, ES256, or full class name). Default: HS256.', 'HS256');
        $this->addOption('update-env', null, InputOption::VALUE_NONE, 'Attempt to update the .env file automatically (for HMAC secret).');

        // RSA Options
        $this->addOption('bits', 'b', InputOption::VALUE_OPTIONAL, 'For RSA: the number of bits for the private key.', 2048);

        // ECDSA Options
        $this->addOption('curve', 'c', InputOption::VALUE_OPTIONAL, 'For ECDSA: the curve name (e.g., prime256v1, secp384r1).', 'prime256v1');

        // Common for Asymmetric
        $this->addOption('password', 'p', InputOption::VALUE_OPTIONAL, 'Password to protect the private key (optional).');
        $this->addOption('output-private-key', null, InputOption::VALUE_OPTIONAL, 'File path to save the generated private key.');
        $this->addOption('output-public-key', null, InputOption::VALUE_OPTIONAL, 'File path to save the generated public key.');
    }
}