<?php

namespace Qbil\Control;

class QtDatabase
{
    private $config;
    private $adminConfig;

    public function __construct($config, $adminConfig = null)
    {
        $this->config = $config;
        $this->adminConfig = $adminConfig ?: ['username' => 'root', 'password' => 'null', 'hostspec' => 'localhost'];
    }

    public function isAccessible()
    {
        $conn = $this->getConnection();
        if (!$conn) {
            return false;
        }

        if (!@$conn->select_db($this->config['database'])) {
            return false;
        }

        return true;
    }

    public function listDatabases()
    {
        $conn = $this->getAdminConnection();
        $result = $conn->query('SHOW DATABASES');            
        $databases = [];
        while ($row = mysqli_fetch_assoc($result)) {
            $databases[] = $row['Database'];
        }

        return $databases;
    }

    public function doesExist()
    {
        try {
            $conn = $this->getAdminConnection();
        } catch (Exception $e) {
            $conn = $this->getConnection();
            if (!$conn) {
                return null;
            }
        }

        return $conn->select_db($this->config['database']);
    }

    public function makeInaccessible()
    {
        $conn = $this->getAdminConnection();

        if (!preg_match('/-rw$/', $this->config['username'])) {
            throw new \Exception('Illegal username in database config');
        }
        @$conn->query('DROP USER `'.$this->config['username'].'`@localhost');
        @$conn->query('DROP USER `'.$this->config['ro-username'].'`@`%`');
    }

    public function makeAccessible()
    {
        $conn = $this->getAdminConnection();

        if (!preg_match('/-rw$/', $this->config['username'])) {
            throw new \Exception('Illegal username in database config');
        }
        $hostResult = $conn->query("SELECT SUBSTRING_INDEX(USER(), '@', -1) AS host");

        $result = @$conn->query('GRANT ALL ON '.$this->config['database'].'.* TO `'.$this->config['username']."`@`".mysqli_fetch_assoc($hostResult)['host']."` identified by '".$conn->real_escape_string($this->config['password'])."'");
        if (!$result) {
            throw new \Exception($conn->error);
        }
        $result = @$conn->query('GRANT SELECT,EXECUTE ON '.$this->config['database'].'.* TO `'.$this->config['ro-username']."`@`%` identified by '".$conn->real_escape_string($this->config['ro-password'].file_get_contents(APPEND_KEY_PATH))."' require ssl");
        if (!$result) {
            throw new \Exception($conn->error);
        }

        return true;
    }

    public function loadDump($dumpFile, ServerKey $key, FtpServer $ftpServer)
    {
        try {
            $dataFile = tempnam('/tmp', 'dump');
            $keyFile = tempnam('/tmp', 'key');
            $zipFile = tempnam('/tmp', 'zip');
            if (!($ftpServer->downloadFile($dataFile, $dumpFile.'.aes') && $extension = 'aes') && !($ftpServer->downloadFile($dataFile, $dumpFile.'.box') && $extension = 'box')) {
                throw new \Exception('Kon '.$dumpFile.'.aes niet downloaden.');
            }
            if (!$ftpServer->downloadFile($keyFile, $dumpFile.'.key.'.$key->getKeyChecksum())) {
                throw new \Exception('Kon '.$dumpFile.'.key.'.$key->getKeyChecksum().' niet downloaden.');
            }
            $symmKey = $key->decrypt(file_get_contents($keyFile));

            if ('aes' === $extension) {
                $iv = file_get_contents($dataFile, false, null, -1, 32);
                $td = mcrypt_module_open(MCRYPT_RIJNDAEL_256, '', MCRYPT_MODE_CBC, '');
                mcrypt_generic_init($td, $symmKey, $iv);
                $zipData = mdecrypt_generic($td, file_get_contents($dataFile, false, null, 32));
            } else {
                $zipData = sodium_crypto_secretbox_open(file_get_contents($dataFile, false, null, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES), file_get_contents($dataFile, false, null, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES), $symmKey);
            }
            if (!$zipData) {
                throw new \Exception('Decryptie mislukt.');
            }
            file_put_contents($zipFile, $zipData);

            $zip = new \ZipArchive();
            if (!$zip->open($zipFile) || !($stat = @$zip->statIndex(0)) || !($stream = @$zip->getStream($zip->getNameIndex(0)))) {
                throw new \Exception('Fout bij het lezen van het zip-bestand.');
            }
            if ($this->doesExist() && !$this->getAdminConnection()->query('DROP DATABASE '.$this->config['database'])) {
                throw new \Exception('Kon database niet verwijderen.');
            }
            if (!$this->getAdminConnection()->query('CREATE DATABASE '.$this->config['database'])) {
                throw new \Exception('Kon database niet aanmaken.');
            }
            $this->makeAccessible();
            $conn = @mysqli_connect($this->config['hostspec'], $this->config['username'], $this->config['password']);
            $conn->select_db($this->config['database']);

            $statement = '';
            $delimiter = ';';

            while (!feof($stream)) {
                $line = trim(fgets($stream), "\t\n\r\0");
                if ('--' != substr($line, 0, 2)) {
                    if ('' != $statement && ' ' != substr($statement, -1) && ' ' != $line[0]) {
                        $statement .= ' ';
                    }
                    $statement .= $line;
                    if (preg_match("'^DELIMITER (.+)$'", $statement, $matches)) {
                        $delimiter = $matches[1];
                        $statement = '';
                    } elseif (preg_match('/'.str_replace(';', '\;', $delimiter).'$/', $statement)) {
                        // Filter definer information
                        $statement = preg_replace('/ DEFINER=`[^`]+`@`[^`]+`/', '', $statement);
                        // Filter database name
                        $statement = preg_replace('/ALTER DATABASE `[a-z0-9_]+`/i', 'ALTER DATABASE', $statement);
                        if (!$conn->query($statement)) {
                            throw new \Exception($conn->error.' ('.$statement.')');
                        }
                        $statement = '';
                    }
                }
            }
            fclose($stream);

            $conn->query('DROP TABLE IF EXISTS dbrevision;');
        } catch (Exception $e) {
            @unlink($aesFile);
            @unlink($keyFile);
            @unlink($zipFile);
            throw $e;
        }
        @unlink($aesFile);
        @unlink($keyFile);
        @unlink($zipFile);
    }

    public function killProcess($id)
    {
        echo 'KILL '.$id;
        $conn = $this->getAdminConnection();
        $conn->query('KILL '.$id);
    }

    public function getProcessList()
    {
        $conn = $this->getAdminConnection();
        $result = $conn->query('SHOW FULL PROCESSLIST');
        $processList = [];
        while ($row = mysqli_fetch_assoc($result)) {
            $processList[] = $row;
        }

        return $processList;
    }

    public function isTweakActive()
    {
        try {
            $conn = $this->getAdminConnection();
            $result = $conn->query('SELECT @@GLOBAL.tmpdir');
            $row = mysqli_fetch_row($result);

            return is_dir($row[0]) && is_dir($row[0].'/.snap');
        } catch (Exception $e) {
            return null;
        }
    }

    public function getVersion()
    {
        try {
            $conn = $this->getAdminConnection();

            return $conn->server_info;
        } catch (Exception $e) {
            return 'unknown';
        }
    }

    private function getConnection()
    {
        $conn = @mysqli_connect($this->config['hostspec'], $this->config['username'], $this->config['password']);

        return $conn;
    }

    private function getAdminConnection()
    {
        $conn = @mysqli_connect($this->adminConfig['hostspec'], $this->adminConfig['username'], $this->adminConfig['password']);
        if (!$conn) {
            throw new \Exception('Root access to database unavailable.');
        }

        return $conn;
    }
}
