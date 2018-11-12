<?php

namespace Qbil\Control;

class FtpServer
{
    private $conn;

    public function __construct($host, $username, $password)
    {
        $this->conn = ftp_connect($host, null, 3);
        if (!$this->conn || !ftp_login($this->conn, $username, $password)) {
            throw new \Exception('Could not login or connect to FTP');
        }
    }

    public function listFilesMatching($directory, $regex)
    {
        $files = @ftp_nlist($this->conn, $directory);
        if (!$files) {
            throw new \Exception('Kon lijst met bestanden niet ophalen.');
        }
        $matchingFiles = [];
        foreach ($files as $file) {
            if (!preg_match($regex, $file, $matches)) {
                continue;
            }
            $matchingFiles[] = $matches[1];
        }

        return $matchingFiles;
    }

    public function downloadFile($localPath, $remotePath)
    {
        return @ftp_get($this->conn, $localPath, $remotePath, FTP_BINARY);
    }
}
