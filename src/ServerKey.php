<?php

namespace Qbil\Control;

use Safe\Exceptions\FilesystemException;
use Safe\Exceptions\OpensslException;
use function Safe\filemtime;
use function Safe\unlink;
use function Safe\openssl_pkey_new;
use function Safe\openssl_pkey_export_to_file;
use function Safe\openssl_pkey_get_private;
use function Safe\file_get_contents;
use function Safe\openssl_private_decrypt;

class ServerKey
{
    /**
     * @var resource|null
     */
    private $key;

    private string $keyFile;

    private int $expireTime;

    public function __construct(?string $keyFile = null, int $expireTime = 30000)
    {
        $this->keyFile = $keyFile ?? '/tmp/servercontrol.key';
        $this->expireTime = $expireTime;
    }

    /**
     * @throws OpensslException
     * @throws FilesystemException
     */
    public function getPublicKey(): string
    {
        if (false === $details = openssl_pkey_get_details($this->getKey())) {
            throw new OpensslException('Could not get private key details');
        }

        return $details['key'];
    }

    /**
     * @throws FilesystemException
     * @throws OpensslException
     */
    public function getPrivateKey(): string
    {
        $this->createKeyIfNotExists();

        return file_get_contents($this->keyFile);
    }

    /**
     * @throws FilesystemException
     * @throws OpensslException
     */
    public function getKeyChecksum(): string
    {
        return md5($this->getPublicKey());
    }

    /**
     * @throws FilesystemException
     * @throws OpensslException
     */
    public function decrypt(string $input): string
    {
        if (
            !openssl_private_decrypt($input, $output, $this->getKey(), \OPENSSL_PKCS1_OAEP_PADDING) &&
            !openssl_private_decrypt($input, $output, $this->getKey())
        ) {
            throw new \RuntimeException('Decryption failed.');
        }

        return $output;
    }

    /**
     * @return resource
     * @throws FilesystemException
     * @throws OpensslException
     */
    private function getKey()
    {
        if (null === $this->key) {
            $this->createKeyIfNotExists();
        }

        return $this->key;
    }

    /**
     * @throws FilesystemException
     * @throws OpensslException
     */
    private function createKeyIfNotExists(): void
    {
        if (!is_file($this->keyFile) || (0 !== $this->expireTime && filemtime($this->keyFile) < time() - 30000)) {
            try {
                unlink($this->keyFile);
            } catch (FilesystemException $e) {
            }
            $this->key = openssl_pkey_new([
                'digest_alg' => 'sha512',
                'private_key_bits' => 4096,
                'private_key_type' => OPENSSL_KEYTYPE_RSA,
            ]);

            openssl_pkey_export_to_file($this->key, $this->keyFile);
        } else {
            $this->key = openssl_pkey_get_private(file_get_contents($this->keyFile));
        }
    }
}
