<?php

declare(strict_types=1);

namespace Kylesean\Jwt\Command;

use Hyperf\Command\Annotation\Command;
use Hyperf\Command\Command as HyperfCommand;
use Psr\Container\ContainerInterface;
use Symfony\Component\Console\Input\InputOption;

#[Command]
class GenJwtKeyCommand extends HyperfCommand
{
    public function __construct(protected ContainerInterface $container)
    {
        parent::__construct('jwt:gen-key');
        $this->setDescription('Generate a new JWT secret key (for HMAC) or key pair (for RSA/ECDSA).');
    }

    public function handle(): int
    {
        $algoOption = $this->input->getOption('algo');
        $algo = is_string($algoOption) ? strtolower($algoOption) : 'hs256';

        if (str_starts_with($algo, 'hs')) {
            $success = $this->generateHmacSecret($algo);
        } elseif (str_starts_with($algo, 'rs')) {
            $success = $this->generateRsaKeyPair($algo);
        } elseif (str_starts_with($algo, 'es')) {
            $success = $this->generateEcdsaKeyPair($algo);
        } else {
            $this->output->error(sprintf('Unsupported algorithm: %s. Supported families: HS*, RS*, ES*.', $algo));

            return self::FAILURE;
        }

        return $success ? self::SUCCESS : self::FAILURE;
    }

    protected function generateHmacSecret(string $algo): bool
    {
        $length = 32;
        if ($algo === 'hs384') {
            $length = 48;
        } elseif ($algo === 'hs512') {
            $length = 64;
        }

        try {
            $key = random_bytes($length);
            $secret = bin2hex($key);
        } catch (\Exception $e) {
            $this->output->error('CRITICAL: Could not generate a cryptographically secure random key.');
            $this->output->writeln('');
            $this->output->writeln('<comment>This is a security-critical failure. Do NOT use a weak fallback.</comment>');
            $this->output->writeln('');
            $this->output->writeln('Possible solutions:');
            $this->output->writeln('  1. Ensure your PHP installation has a proper random source configured.');
            $this->output->writeln('  2. On Linux, ensure /dev/urandom is available and readable.');
            $this->output->writeln('  3. Try running: php -r "echo bin2hex(random_bytes(32));" to test your system.');
            $this->output->writeln('');
            $this->output->writeln('Error details: ' . $e->getMessage());

            return false; // Abort key generation instead of using insecure fallback
        }

        $this->output->success(sprintf('Successfully generated new JWT secret for %s.', strtoupper($algo)));
        $this->output->writeln('');
        $this->output->writeln('Your new JWT secret is:');
        $this->output->block($secret);
        $this->output->writeln('');
        $this->output->writeln('Please set this value in your <comment>.env</comment> file as:');
        $this->output->writeln("JWT_SECRET={$secret}");
        $signerClass = '\\Lcobucci\\JWT\\Signer\\Hmac\\Sha' . substr($algo, 2);
        $this->output->writeln("<info>'algo' => {$signerClass}::class,</info>");
        $this->output->writeln('');

        if ($this->input->getOption('update-env')) {
            $this->updateEnvFile('JWT_SECRET', $secret);
        } elseif ($this->input->isInteractive() && $this->output->confirm('Do you want to attempt to update your .env file automatically?', false)) {
            $this->updateEnvFile('JWT_SECRET', $secret);
        }

        return true;
    }

    protected function generateRsaKeyPair(string $algo): bool
    {
        $bits = (int) $this->input->getOption('bits');
        $password = $this->input->getOption('password');
        if ($password === null && $this->input->isInteractive() && $this->output->confirm('Do you want to protect the private key with a password?', false)) {
            $password = $this->output->askHidden('Enter password for private key (leave empty for no password):');
            if (empty($password)) {
                $password = null;
            }
        }

        $this->output->writeln(sprintf('Generating RSA-%d key pair for %s...', $bits, strtoupper($algo)));

        $config = [
            'digest_alg' => match (strtoupper($algo)) {
                'RS384' => 'sha384',
                'RS512' => 'sha512',
                default => 'sha256',
            },
            'private_key_bits' => $bits,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ];

        // generate rsa private key
        $privateKeyResource = openssl_pkey_new($config);
        if ($privateKeyResource === false) {
            $this->output->error('Failed to generate RSA private key: ' . openssl_error_string());

            return false;
        }

        // export rsa private key (encrypted with the password when one was given)
        $privateKeyPem = '';
        $exportResult = $password
            ? openssl_pkey_export($privateKeyResource, $privateKeyPem, $password)
            : openssl_pkey_export($privateKeyResource, $privateKeyPem);

        if ($exportResult === false) {
            $this->output->error('Failed to export RSA private key: ' . openssl_error_string());

            return false;
        }

        // get rsa public key details
        $publicKeyDetails = openssl_pkey_get_details($privateKeyResource);
        if ($publicKeyDetails === false || !isset($publicKeyDetails['key'])) {
            $this->output->error('Failed to get RSA public key details: ' . openssl_error_string());

            return false;
        }
        $publicKeyPem = $publicKeyDetails['key'];

        $this->outputKeyPairResults($privateKeyPem, $publicKeyPem, $password, strtoupper($algo), (string) $this->input->getOption('algo'));

        return true;
    }

    protected function generateEcdsaKeyPair(string $algo): bool
    {
        $curve = (string) $this->input->getOption('curve');
        $password = $this->input->getOption('password');
        if ($password === null && $this->input->isInteractive() && $this->output->confirm('Do you want to protect the private key with a password?', false)) {
            $password = $this->output->askHidden('Enter password for private key (leave empty for no password):');
            if (empty($password)) {
                $password = null;
            }
        }

        $this->output->writeln(sprintf('Generating ECDSA key pair with curve %s for %s...', $curve, strtoupper($algo)));

        $config = [
            'digest_alg' => match (strtoupper($algo)) {
                'ES384' => 'sha384',
                'ES512' => 'sha512',
                default => 'sha256',
            },
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => $curve,
        ];

        $privateKeyResource = openssl_pkey_new($config);
        if ($privateKeyResource === false) {
            $this->output->error('Failed to generate ECDSA private key: ' . openssl_error_string() . ' (Ensure the curve name is valid and OpenSSL supports it)');

            return false;
        }

        // export EC private key. openssl_pkey_export() emits PKCS#8 and, when a
        // password is supplied, encrypts it — which is exactly what lcobucci/jwt's
        // InMemory::plainText()/file() accept together with the key passphrase.
        $privateKeyPem = '';
        $exportResult = $password
            ? openssl_pkey_export($privateKeyResource, $privateKeyPem, $password)
            : openssl_pkey_export($privateKeyResource, $privateKeyPem);

        if ($exportResult === false) {
            $this->output->error('Failed to export ECDSA private key: ' . openssl_error_string());

            return false;
        }

        $publicKeyDetails = openssl_pkey_get_details($privateKeyResource);
        if ($publicKeyDetails === false || !isset($publicKeyDetails['key'])) {
            $this->output->error('Failed to get ECDSA public key details: ' . openssl_error_string());

            return false;
        }
        $publicKeyPem = $publicKeyDetails['key'];

        $this->outputKeyPairResults($privateKeyPem, $publicKeyPem, $password, strtoupper($algo), (string) $this->input->getOption('algo'));

        return true;
    }

    protected function outputKeyPairResults(string $privateKeyPem, string $publicKeyPem, ?string $password, string $algoNameForDisplay, string $algoOptionValue): void
    {
        $this->output->success(sprintf('Successfully generated new JWT key pair for %s.', $algoNameForDisplay));
        $this->output->writeln('');

        $this->output->writeln('<comment>Private Key (SAVE THIS SECURELY - DO NOT COMMIT TO VERSION CONTROL IF HARDCODED):</comment>');
        $this->output->block($privateKeyPem);
        $this->output->writeln('');

        $this->output->writeln('<comment>Public Key:</comment>');
        $this->output->block($publicKeyPem);
        $this->output->writeln('');

        $this->output->writeln('Please configure these in your <comment>jwt.php</comment> config or <comment>.env</comment> file:');
        $this->output->writeln('');
        $this->output->writeln('<info>// In config/autoload/jwt.php or your .env file:</info>');
        $signerClass = $algoOptionValue; // directly use the --algo value entered by the user
        if (!class_exists($signerClass)) { // if the user enters a shorthand, try to build it
            $algoShort = str_replace(['rs', 'es'], '', strtolower($algoNameForDisplay)); // 256, 384, 512
            $algoFamily = substr(strtolower($algoNameForDisplay), 0, 2); // rs, es
            // fix class name construction
            $signerClass = '\\Lcobucci\\JWT\\Signer\\' . ucfirst($algoFamily === 'rs' ? 'Rsa' : 'Ecdsa') . '\\Sha' . $algoShort;
        }
        $this->output->writeln("<info>'algo' => {$signerClass}::class,</info>");
        $this->output->writeln("<info>'keys' => [</info>");
        $this->output->writeln("<info>    'public' => env('JWT_PUBLIC_KEY', <<<EOT</info>");
        $this->output->writeln('<info>' . $publicKeyPem . '</info>');
        $this->output->writeln('<info>EOT</info>');
        $this->output->writeln("<info>    ),</info>");
        $this->output->writeln("<info>    'private' => env('JWT_PRIVATE_KEY', <<<EOT</info>");
        $this->output->writeln('<info>' . $privateKeyPem . '</info>');
        $this->output->writeln('<info>EOT</info>');
        $this->output->writeln('<info>    ),</info>');
        if ($password) {
            $this->output->writeln("<info>    'passphrase' => env('JWT_PASSPHRASE', '{$password}'),</info>");
        } else {
            $this->output->writeln("<info>    'passphrase' => env('JWT_PASSPHRASE', null),</info>");
        }
        $this->output->writeln('<info>],</info>');
        $this->output->writeln('');
        $this->output->writeln("Or, use 'file:///path/to/your/key.pem' for key paths.");

        // Try to write file (optional)
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

    /**
     * Try to update the specified key value in the .env file.
     */
    protected function updateEnvFile(string $keyName, string $keyValue): void
    {
        $envPath = (defined('BASE_PATH') ? BASE_PATH : getcwd()) . '/.env';

        if (!file_exists($envPath)) {
            $this->output->warning(".env file not found at: {$envPath}");

            return;
        }

        $content = file_get_contents($envPath);
        if ($content === false) {
            $this->output->warning("Failed to read .env file: {$envPath}");

            return;
        }

        $pattern = '/^' . preg_quote($keyName, '/') . '=.*$/m';

        if (preg_match($pattern, $content)) {
            $content = preg_replace($pattern, "{$keyName}={$keyValue}", $content);
            $this->output->info("Updated existing {$keyName} in .env");
        } else {
            $content .= "\n{$keyName}={$keyValue}\n";
            $this->output->info("Added {$keyName} to .env");
        }

        if (file_put_contents($envPath, $content) === false) {
            $this->output->warning("Failed to write to .env file: {$envPath}");

            return;
        }

        $this->output->success('.env file updated successfully.');
    }

    protected function configure(): void
    {
        parent::configure();
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
