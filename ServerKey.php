<?php

namespace Qbil\Control;

class ServerKey
{
    private $key;

    public function __construct($keyfile, $expireTime = 30000)
    {
        $keyfile = $keyfile ?: '/tmp/servercontrol.key';
        if (!file_exists($keyfile) || (false !== $expireTime && filemtime($keyfile) < time() - 30000)) {
            @unlink($keyfile);
            $this->key = openssl_pkey_new([
                'digest_alg' => 'sha512',
                'private_key_bits' => 2048,
                'private_key_type' => OPENSSL_KEYTYPE_RSA,
            ]);

            openssl_pkey_export_to_file($this->key, $keyfile);
        } else {
            $this->key = openssl_pkey_get_private(file_get_contents($keyfile));
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
        if (!openssl_private_decrypt($input, $output, $this->key)) {
            throw new Exception('Decryptie mislukt.');
        }

        return $output;
    }
}
