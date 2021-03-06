<?php

namespace Qbil\Control;

use Symfony\Component\Process\PhpProcess;
use UptimeRobot\API;

class QtInstallation
{
    public static $installPath = '';
    protected $name;
    protected $path;
    private $configuration;
    private $projectDir;

    public function __construct($path, $projectDir = null)
    {
        if (defined('INSTALL_PATH')) {
            self::$installPath = INSTALL_PATH;
        }

        $this->name = basename($path);
        $this->path = ($this->name === $path ? self::$installPath : dirname($path)).DIRECTORY_SEPARATOR;
        $this->projectDir = $projectDir ?: $this->getHtdocsFolder();
    }

    public function erase()
    {
        if ($this->getDatabase()->doesExist()) {
            throw new \Exception('A database exists');
        }
        if (is_dir(self::$installPath.$this->name.'/storage') && count(glob(self::$installPath.$this->name.'/storage'))) {
            throw new \Exception('Contains stored files');
        }
        if (!preg_match('/^[a-z0-9\-]+$/i', $this->name)) {
            throw new \Exception('Illegal installation name');
        }
        if (!delTree(self::$installPath.$this->name)) {
            throw new \Exception('Could not delete folder');
        }

        return true;
    }

    public function composerInstall($dev = false, $scripts = true)
    {
        chdir($this->projectDir);
        if (!file_exists('composer.json')) {
            chdir('symfony');
        }
        exec('env HOME='.$this->projectDir.' PATH='.$this->getPath().' SYMFONY_ENV=prod composer install '.($dev ? '' : '--no-dev ').($scripts ? '' : '--no-scripts ').' 2>&1', $output, $retval);
        if ($retval) {
            throw new \Exception(implode("\n", $output));
        }

        return true;
    }

    public function cacheClear()
    {
        $cacheFolders = array_filter([$this->projectDir.'/symfony/app/cache/', $this->projectDir.'/symfony/var/cache/', $this->projectDir.'/var/cache/'], 'is_dir');
        if (!count($cacheFolders)) {
            throw new \Exception('Cache super folder not found.');
        }
        foreach ($cacheFolders as $cacheFolder) {
            if (is_dir($cacheFolder.'prod') && !delTree($cacheFolder.'prod')) {
                throw new \Exception('Could not clear cache.');
            }
            if (is_dir($cacheFolder.'dev') && !delTree($cacheFolder.'dev')) {
                throw new \Exception('Could not clear cache.');
            }
        }

        return true;
    }

    public function asseticDump()
    {
        chdir($this->projectDir.'/symfony');
        exec('env PATH='.$this->getPath().' SYMFONY_ENV=prod php app/console assetic:dump 2>&1', $output, $retval);
        if ($retval) {
            throw new \Exception(implode("\n", $output));
        }

        return true;
    }

    public function getDatabase($adminConfig = null)
    {
        $dbConfig = $this->getDatabaseSettings();

        return new QtDatabase($dbConfig, $adminConfig);
    }

    public function getSitekey()
    {
        $this->parseConfiguration();

        return $this->configuration['license']['sitekey'];
    }

    public function getRemoteControlPid()
    {
        if (getenv('INSTALLATION_NAME')) {
            return file_get_contents('/var/storage/'.$this->name.'/rc.pid');
        }

        if (file_exists($pidFile = $this->path.$this->name.'/rc.pid')) {
            return file_get_contents($pidFile);
        }

        return false;
    }

    public function isRemoteControlActive()
    {
        if (!($pid = $this->getRemoteControlPid()) || !file_exists($cmdlineFile = '/proc/'.$pid.'/cmdline') || !strstr(file_get_contents($cmdlineFile), 'RemoteControlService')) {
            return false;
        }

        return true;
    }

    public function stopRemoteControl()
    {
        if (!($pid = $this->getRemoteControlPid())) {
            return false;
        }
        if (!posix_kill($pid, 15)) {
            return false;
        }
        usleep(10000);

        return !$this->isRemoteControlActive();
    }

    public function startRemoteControl()
    {
        chdir($this->projectDir.'/utilities');
        if (defined('FREEBSD_SYSTEM')) {
            @system('env PATH='.$this->getPath().' daemon -p ../../rc.pid /usr/local/bin/php RemoteControlService.php '.$this->name.' > /dev/null 2>&1');
        } elseif (getenv('INSTALLATION_NAME')) {
            @system('env PATH='.$this->getPath().' nohup php RemoteControlService.php >> ../var/logs/rc.log 2>&1 & echo -n $! > /var/storage/'.$this->name.'/rc.pid');
        } else {
            @system('env PATH='.$this->getPath().' nohup php RemoteControlService.php '.$this->name.' > /dev/null 2>&1 & echo -n $! > ../../rc.pid');
        }
        sleep(1);

        return $this->isRemoteControlActive();
    }

    public function getDatabaseSettings()
    {
        $this->parseConfiguration();

        return $this->configuration['database']['dsn'];
    }

    public function getMonitorDetails()
    {
        if (preg_match('/-(acceptatie|test)$/', $this->name)) {
            return null;
        }
        try {
            if (!$results = $this->monitorCommand('/getMonitors', ['search' => $this->name, 'showMonitorAlertContacts' => false])) {
                return null;
            }

            if ('ok' != $results['stat']) {
                return false;
            }

            foreach ($results['monitors']['monitor'] as $result) {
                if ($result['friendlyname'] == $this->name) {
                    return $result;
                }
            }

            return false;
        } catch (\Exception $e) {
            return null;
        }
    }

    public function removeMonitor()
    {
        try {
            $monitor = $this->getMonitorDetails();
            $results = $this->monitorCommand('/deleteMonitor', ['monitorID' => $monitor['id']]);

            return $results && 'ok' == $results['stat'];
        } catch (\Exception $e) {
            return false;
        }
    }

    public function createMonitor()
    {
        try {
            $results = $this->monitorCommand('/newMonitor', [
                'monitorFriendlyName' => $this->name,
                'monitorURL' => 'https://'.$this->name.'.qbiltrade.com/ui/login.php',
                'monitorType' => 2,
                'monitorKeywordType' => 2,
                'monitorKeywordValue' => 'Password',
                'monitorAlertContacts' => '0175644_0_0-2286993_0_0-2375626_0_0-2375643_0_0',
            ]);

            return $results && 'ok' == $results['stat'];
        } catch (\Exception $e) {
            return false;
        }
    }

    protected function getHtdocsFolder()
    {
        return $this->path.$this->name.'/htdocs';
    }

    private function getPath()
    {
        $pathComponents = explode(PATH_SEPARATOR, $_SERVER['PATH'] ?: $_SERVER['Path']);
        $pathComponents[] = '/usr/local/bin';

        return implode(PATH_SEPARATOR, $pathComponents);
    }

    private function parseConfiguration()
    {
        if (null !== $this->configuration) {
            return;
        }
        chdir($this->projectDir.'/logic');
        $process = new PhpProcess(<<<EOF
<?php
require('../vendor/autoload.php');
require('configuration.php');
echo(json_encode(\$configuration));
EOF
        );
        $process->run();

        $this->configuration = json_decode($process->getOutput(), true);
        chdir(__DIR__);
    }

    private function monitorCommand($url, $args = null)
    {
        if (!$apiKey = getenv('UPTIMEROBOTKEY') ?: (defined('UPTIMEROBOTKEY') ? UPTIMEROBOTKEY : null)) {
            return null;
        }

        $api = new API(['url' => 'https://api.uptimerobot.com', 'apiKey' => $apiKey]);

        return $api->request($url, $args);
    }
}
