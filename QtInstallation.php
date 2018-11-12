<?php

namespace Qbil\Control;

class QtInstallation
{
    private $name;
    private $configuration;

    public function __construct($name)
    {
        $this->name = $name;
    }

    public function erase()
    {
        if ($this->getDatabase()->doesExist()) {
            throw new \Exception('A database exists');
        }
        if (is_dir(INSTALL_PATH.$this->name.'/storage') && count(glob(INSTALL_PATH.$this->name.'/storage'))) {
            throw new \Exception('Contains stored files');
        }
        if (!preg_match('/^[a-z0-9\-]+$/i', $this->name)) {
            throw new \Exception('Illegal installation name');
        }
        if (!delTree(INSTALL_PATH.$this->name)) {
            throw new \Exception('Could not delete folder');
        }

        return true;
    }

    private function getPath()
    {
        $pathComponents = explode(PATH_SEPARATOR, $_SERVER['PATH'] ?: $_SERVER['Path']);
        $pathComponents[] = '/usr/local/bin';

        return implode(PATH_SEPARATOR, $pathComponents);
    }

    public function composerInstall()
    {
        chdir(INSTALL_PATH.$this->name.'/htdocs');
        if (!file_exists('composer.json')) {
            chdir('symfony');
        }
        exec('env HOME='.INSTALL_PATH.' PATH='.$this->getPath().' SYMFONY_ENV=prod composer install -o --no-dev 2>&1', $output, $retval);
        if ($retval) {
            throw new Exception(implode("\n", $output));
        }

        return true;
    }

    public function cacheClear()
    {
        $cacheFolders = array_filter([INSTALL_PATH.$this->name.'/htdocs/symfony/app/cache/', INSTALL_PATH.$this->name.'/htdocs/symfony/var/cache/'], 'is_dir');
        if (!count($cacheFolders)) {
            throw new Exception('Cache super folder not found.');
        }
        foreach ($cacheFolders as $cacheFolder) {
            if (is_dir($cacheFolder.'prod') && !delTree($cacheFolder.'prod')) {
                throw new Exception('Could not clear cache.');
            }
            if (is_dir($cacheFolder.'dev') && !delTree($cacheFolder.'dev')) {
                throw new Exception('Could not clear cache.');
            }
        }

        return true;
    }

    public function asseticDump()
    {
        chdir(INSTALL_PATH.$this->name.'/htdocs/symfony');
        exec('env PATH='.$this->getPath().' SYMFONY_ENV=prod php app/console assetic:dump 2>&1', $output, $retval);
        if ($retval) {
            throw new Exception(implode("\n", $output));
        }

        return true;
    }

    public function getDatabase()
    {
        $dbConfig = $this->getDatabaseSettings();

        return new QtDatabase($dbConfig);
    }

    public function getRemoteControlPid()
    {
        if (!file_exists($pidFile = INSTALL_PATH.$this->name.'/rc.pid') || !($pid = file_get_contents($pidFile))) {
            return false;
        }

        return $pid;
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
        chdir(INSTALL_PATH.$this->name.'/htdocs/utilities');
        if (FREEBSD_SYSTEM) {
            @system('env PATH='.$this->getPath().' daemon -p ../../rc.pid /usr/local/bin/php RemoteControlService.php '.$this->name.' > /dev/null 2>&1');
        } else {
            @system('env PATH='.$this->getPath().' nohup php RemoteControlService.php '.$this->name.' > /dev/null 2>&1 & echo -n $! > ../../rc.pid');
        }
        sleep(1);

        return $this->isRemoteControlActive();
    }

    private function parseConfiguration()
    {
        if (null !== $this->configuration) {
            return;
        }
        chdir(INSTALL_PATH.$this->name.'/htdocs/logic');
        @include '../symfony/vendor/autoload.php';
        include 'configuration.php';
        $this->configuration = $configuration;
        chdir(__DIR__);
    }

    private function getDatabaseSettings()
    {
        $this->parseConfiguration();

        return $this->configuration['database']['dsn'];
    }

    private function monitorCommand($url, $args = null)
    {
        $api = new API(['url' => 'https://api.uptimerobot.com', 'apiKey' => UPTIMEROBOTKEY]);

        return $api->request($url, $args);
    }

    public function getMonitorDetails()
    {
        if (preg_match('/-(acceptatie|test)$/', $this->name)) {
            return null;
        }
        try {
            $results = $this->monitorCommand('/getMonitors', ['search' => $this->name, 'showMonitorAlertContacts' => false]);
            //	      var_dump ($results);
            if (!$results) {
                return null;
            } elseif ('ok' != $results['stat']) {
                return false;
            } else {
                foreach ($results['monitors']['monitor'] as $result) {
                    if ($result['friendlyname'] == $this->name) {
                        return $result;
                    }
                }
            }

            return false;
        } catch (Exception $e) {
            return null;
        }
    }

    public function removeMonitor()
    {
        try {
            $monitor = $this->getMonitorDetails();
            $results = $this->monitorCommand('/deleteMonitor', ['monitorID' => $monitor['id']]);

            return $results && 'ok' == $results['stat'];
        } catch (Exception $e) {
            return false;
        }
    }

    public function createMonitor()
    {
        try {
            $results = $this->monitorCommand('/newMonitor',
                [
                    'monitorFriendlyName' => $this->name,
                    'monitorURL' => 'https://'.$this->name.'.qbiltrade.com/ui/login.php',
                    'monitorType' => 2,
                    'monitorKeywordType' => 2,
                    'monitorKeywordValue' => 'Password',
                    'monitorAlertContacts' => '0175644_0_0-2286993_0_0-2375626_0_0-2375643_0_0',
                ]
            );

            return $results && 'ok' == $results['stat'];
        } catch (Exception $e) {
            return false;
        }
    }
}
