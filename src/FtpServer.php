<?php

namespace Qbil\Control;

class FtpServer
{
    /**
     * @var resource
     */
    private $conn;
    /**
     * @var string
     */
    private $host;
    /**
     * @var string
     */
    private $username;
    /**
     * @var string
     */
    private $password;
    /**
     * @var bool
     */
    private $passive;
    /**
     * @var int
     */
    private $timeout;

    public function __construct(string $host, string $username, string $password, bool $passive = true, int $timeout = 30)
    {
        $this->host = $host;
        $this->username = $username;
        $this->password = $password;
        $this->passive = $passive;
        $this->timeout = $timeout;
    }

    /**
     * @throws FtpException
     */
    public function listFilesMatching(string $directory, string $regex): array
    {
        $this->connect();
        $files = @ftp_nlist($this->conn, $directory);
        if (false === $files) {
            throw new FtpException('Could not retrieve list of files.');
        }
        $matchingFiles = [];
        foreach ($files as $file) {
            if (!preg_match($regex, $file, $matches)) {
                continue;
            }
            $matchingFiles[] = $matches[1];
        }
        $this->close();

        return $matchingFiles;
    }

    public function downloadFile(string $localPath, string $remotePath): bool
    {
        $this->connect();
        $result = @ftp_get($this->conn, $localPath, $remotePath, FTP_BINARY);
        $this->close();

        return $result;
    }

    /**
     * @throws FtpException
     */
    private function connect(): void
    {
        if (!$this->conn = ftp_connect($this->host, null, $this->timeout)) {
            throw new FtpException('Could not connect to FTP');
        }

        if (!@ftp_login($this->conn, $this->username, $this->password)) {
            throw new FtpException('Could not login to FTP');
        }

        ftp_pasv($this->conn, $this->passive);
    }

    private function close(): void
    {
        ftp_close($this->conn);
    }


    public function uploadFile(string $localPath, string $remotePath): bool
    {
        $this->connect();
        $result = @ftp_put($this->conn, $remotePath, $localPath, FTP_BINARY);
        $this->close();

        return $result;
    }
}
