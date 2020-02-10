<?php

namespace Qbil\Control;

class QtDatabase
{
    private $config;
    private $adminConfig;

    public function __construct($config, $adminConfig = null)
    {
        $this->config = $config;
        $this->adminConfig = $adminConfig ?: ['username' => 'root', 'password' => null, 'hostspec' => 'localhost'];
    }

    /**
     * @throws \RuntimeException
     */
    public static function fromDatabaseUrl(string $databaseUrl, ?string $databaseRoUrl): self
    {
        [
            'host' => $host,
            'user' => $user,
            'pass' => $pass,
            'path' => $path,
        ] = self::parseUrl($databaseUrl);

        $adminConfig = [
            'username' => $user,
            'password' => $pass,
            'hostspec' => $host,
        ];

        $dsn = $adminConfig + ['database' => ltrim($path, '/')];

        if (null !== $databaseRoUrl) {
            [
                'host' => $host,
                'user' => $user,
                'pass' => $pass,
            ] = self::parseUrl($databaseRoUrl);
        }

        $dsn += [
            'ro-username' => $user,
            'ro-password' => $pass,
            'ro-hostspec' => $host,
        ];

        return new self($dsn, $adminConfig);
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
        } catch (\Exception $e) {
            $conn = $this->getConnection();
            if (!$conn) {
                return null;
            }
        }

        return $conn->select_db($this->config['database']);
    }

    public function makeInaccessible(string $host = '%')
    {
        $conn = $this->getAdminConnection();
        @$conn->query("DROP USER `{$this->config['username']}`@`{$host}`");
        @$conn->query("DROP USER `{$this->config['ro-username']}`@`%`");
    }

    public function setReadOnlyAccount()
    {
        $conn = $this->getAdminConnection();

        $password = $this->config['ro-password'];

        if (defined('APPEND_KEY_PATH') && file_exists(APPEND_KEY_PATH)) {
            $password .= file_get_contents(APPEND_KEY_PATH);
        }

        $result = @$conn->query("GRANT SELECT,EXECUTE ON {$this->config['database']}.* TO `{$this->config['ro-username']}`@`%` identified by '{$conn->real_escape_string($password)}' require ssl");
        if (!$result) {
            throw new \Exception($conn->error);
        }

        return true;
    }

    public function makeAccessible(string $host = '%')
    {
        if ($this->adminConfig['username'] === $this->config['username']) {
            return true;
        }

        $conn = $this->getAdminConnection();

        $result = @$conn->query(
            "GRANT select,
                   insert, 
                   update,
                   delete, 
                   create, 
                   drop, 
                   references, 
                   index, 
                   alter, 
                   create temporary tables, 
                   lock tables, 
                   execute, 
                   create view, 
                   show view, 
                   create routine, 
                   alter routine, 
                   event, 
                   trigger 
               ON {$this->config['database']}.* 
               TO `{$this->config['username']}`@`{$host}` 
               identified by '{$conn->real_escape_string($this->config['password'])}'"
        );

        if (!$result) {
            throw new \Exception($conn->error);
        }

        return $this->setReadOnlyAccount();
    }

    public function loadDump($dumpFile, ServerKey $key, FtpServer $ftpServer)
    {
        try {
            $dataFile = tempnam('/tmp', 'dump');
            $keyFile = tempnam('/tmp', 'key');
            $zipFile = tempnam('/tmp', 'zip');

            $this->writeLn('Downloading dump file');

            if (!($ftpServer->downloadFile($dataFile, $dumpFile.'.aes') && $extension = 'aes') && !($ftpServer->downloadFile($dataFile, $dumpFile.'.box') && $extension = 'box')) {
                throw new \Exception('Could not download '.$dumpFile);
            }

            $this->writeLn('Downloading key file');

            if (!$ftpServer->downloadFile($keyFile, $dumpFile.'.key.'.$key->getKeyChecksum())) {
                throw new \Exception('Could not download '.$dumpFile.'.key.'.$key->getKeyChecksum());
            }

            $this->writeLn('Decrypting key file');

            $symmKey = $key->decrypt(file_get_contents($keyFile));

            $this->writeLn('Decrypting dump file');

            if ('aes' === $extension) {
                $iv = file_get_contents($dataFile, false, null, 0, 32);
                $td = mcrypt_module_open(MCRYPT_RIJNDAEL_256, '', MCRYPT_MODE_CBC, '');
                mcrypt_generic_init($td, $symmKey, $iv);
                $zipData = mdecrypt_generic($td, file_get_contents($dataFile, false, null, 32));
            } else {
                $zipData = sodium_crypto_secretbox_open(file_get_contents($dataFile, false, null, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES), file_get_contents($dataFile, false, null, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES), $symmKey);
            }
            if (!$zipData) {
                throw new \Exception('Decryption failed.');
            }

            $this->writeLn('Writing zip file');
            file_put_contents($zipFile, $zipData);

            $this->writeLn('Extracting zip file');

            $zip = new \ZipArchive();
            if (!$zip->open($zipFile) || !($stat = @$zip->statIndex(0)) || !($stream = @$zip->getStream($zip->getNameIndex(0)))) {
                throw new \Exception('Error reading the zip file.');
            }

            $this->writeLn('Dropping and re-creating database');
            if ($this->doesExist() && !$this->getAdminConnection()->query('DROP DATABASE '.$this->config['database'])) {
                throw new \Exception('Could not drop database.');
            }
            if (!$this->getAdminConnection()->query('CREATE DATABASE '.$this->config['database'])) {
                throw new \Exception('Could not create database.');
            }
            try {
                $this->makeAccessible();
            } catch (\Exception $exception) {
                // Fail silently
            }
            $conn = @mysqli_connect($this->config['hostspec'], $this->config['username'], $this->config['password']);
            $conn->select_db($this->config['database']);
            @$conn->query('set sql_mode=NO_ENGINE_SUBSTITUTION,innodb_strict_mode=0');

            $statement = '';
            $delimiter = ';';

            $this->writeLn('Importing dump');
            while (!feof($stream)) {
                $line = trim(fgets($stream), "\t\n\r\0");
                if ('--' != substr($line, 0, 2)) {
                    if ('' != $statement && ' ' != substr($statement, -1) && $line && ' ' != $line[0]) {
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
            $conn->query('CREATE TABLE dbrevision (branch TEXT, revision varchar(255), masked tinyint not null default 0);');
            $regex = "/^(test_|masked_|)[a-zA-Z0-9\-]+_[0-9]+\-[0-9]+(_([[:alnum:]\$\-]+)|)(_([a-f0-9v\.]+)|)$/";

            if (preg_match($regex, $dumpFile, $matches)) {
                list(, $masked, , $matchedBranch, , $matchedRevision) = $matches;
                $branch = str_replace('$', '/', $matchedBranch);
                $revision = preg_match('/[0-9v\.]+/', $matchedRevision) ? $matchedRevision : 'latest';
                $isMasked = 'masked_' === $masked ? 1 : 0;

                $stmt = $conn->prepare('INSERT INTO dbrevision values(?, ?, ?)');
                $stmt->bind_param(
                    'ssi',
                    $branch,
                    $revision,
                    $isMasked
                );
                $stmt->execute();
            }

            $this->writeLn('<close>Done</close>');
        } catch (\Exception $e) {
            @unlink($dataFile);
            @unlink($keyFile);
            @unlink($zipFile);
            throw $e;
        }
        @unlink($dataFile);
        @unlink($keyFile);
        @unlink($zipFile);
    }

    public function killProcess($id)
    {
        echo "KILL {$id}";
        $conn = $this->getAdminConnection();
        $conn->query("KILL {$id}");
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
        } catch (\Exception $e) {
            return null;
        }
    }

    public function getVersion()
    {
        try {
            $conn = $this->getAdminConnection();

            return $conn->server_info;
        } catch (\Exception $e) {
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

    private function writeLn($message)
    {
        if ('cli' !== php_sapi_name()) {
            return;
        }

        echo "<info>{$message}</info>";
    }

    /**
     * @throws \RuntimeException
     */
    private static function parseUrl(string $url)
    {
        if (false === $parsedUrl = parse_url($url)) {
            throw new \RuntimeException('Malformatted database url');
        }

        return $parsedUrl;
    }
}
