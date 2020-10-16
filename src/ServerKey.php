<?php

namespace Qbil\Control;

use ParagonIE\Halite\Alerts\CannotPerformOperation;
use ParagonIE\Halite\Alerts\InvalidKey;
use ParagonIE\Halite\Alerts\InvalidMessage;
use ParagonIE\Halite\Alerts\InvalidType;
use ParagonIE\Halite\Asymmetric\Crypto;
use ParagonIE\Halite\Asymmetric\EncryptionPublicKey;
use ParagonIE\Halite\Asymmetric\EncryptionSecretKey;
use ParagonIE\Halite\KeyFactory;
use Safe\Exceptions\FilesystemException;
use function Safe\filemtime;
use function time;

class ServerKey
{
    private ?EncryptionSecretKey $secretKey = null;

    private string $keyFile;

    private int $expireTime;

    public function __construct(?string $keyFile = null, int $expireTime = 30000)
    {
        $this->keyFile = $keyFile ?? '/tmp/servercontrol.key';
        $this->expireTime = $expireTime;
    }

    /**
     * @throws CannotPerformOperation
     * @throws FilesystemException
     * @throws InvalidKey
     */
    public function getPrivateKey(): EncryptionSecretKey
    {
        if (null === $this->secretKey) {
            $this->createKeyIfNotExists();
        }

        return $this->secretKey;
    }

    /**
     * @throws CannotPerformOperation
     * @throws FilesystemException
     * @throws InvalidKey
     */
    public function getPublicKey(): EncryptionPublicKey
    {
        return $this->getPrivateKey()->derivePublicKey();
    }

    /**
     * @throws CannotPerformOperation
     * @throws FilesystemException
     * @throws InvalidKey
     */
    public function getKeyChecksum(): string
    {
        return md5($this->getPublicKey()->getRawKeyMaterial());
    }

    /**
     * @throws CannotPerformOperation
     * @throws FilesystemException
     * @throws InvalidKey
     * @throws InvalidMessage
     * @throws InvalidType
     */
    public function decrypt(string $input): string
    {
        return Crypto::unseal($input, $this->getPrivateKey())->getString();
    }

    /**
     * @throws InvalidKey
     * @throws CannotPerformOperation|FilesystemException
     */
    private function createKeyIfNotExists(): void
    {
        if (!is_file($this->keyFile) || $this->hasKeyExpired()) {
            $encryptionKeyPair = KeyFactory::generateEncryptionKeyPair();
            KeyFactory::save($encryptionKeyPair, $this->keyFile);
        }

        $this->secretKey = KeyFactory::loadEncryptionSecretKey($this->keyFile);
    }

    /**
     * @throws FilesystemException
     */
    private function hasKeyExpired(): bool
    {
        return 0 !== $this->expireTime && filemtime($this->keyFile) < time() - 30000;
    }
}
