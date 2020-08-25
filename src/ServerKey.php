<?php

namespace Qbil\Control;

use Exception;

class ServerKey
{
    private $key;

    public function __construct(?string $keyFile = null, int $expireTime = 30000)
    {
        $keyFile ??= '/tmp/servercontrol.key';

        if (!is_file($keyFile) || (0 !== $expireTime && filemtime($keyFile) < time() - 30000)) {
            @unlink($keyFile);
            $this->key = openssl_pkey_new([
                'digest_alg' => 'sha512',
                'private_key_bits' => 4096,
                'private_key_type' => OPENSSL_KEYTYPE_RSA,
            ]);

            openssl_pkey_export_to_file($this->key, $keyFile);
        } else {
            $this->key = openssl_pkey_get_private(file_get_contents($keyFile));
        }
    }

    public function getPublicKey()
    {
        $details = openssl_pkey_get_details($this->key);

        return $details['key'];
    }

    public function getKeyChecksum()
    {
        return md5($this->getPublicKey());
    }

    public function decrypt($input)
    {
        if (
            !openssl_private_decrypt($input, $output, $this->key, \OPENSSL_PKCS1_OAEP_PADDING) &&
            !openssl_private_decrypt($input, $output, $this->key)
        ) {
            throw new Exception('Decryption failed.');
        }

        return $output;
    }
}
