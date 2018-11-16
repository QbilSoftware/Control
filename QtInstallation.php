<?php

namespace Qbil\Control;

use Symfony\Component\Process\PhpProcess;

class QtInstallation
{
    protected $name;
    protected $path;
    private $configuration;

    public function __construct($path)
    {
        $this->name = basename($path);
        $this->path = $this->name === $path ? INSTALL_PATH : dirname($path);
    }
    
    protected function getHtdocsFolder()
    {
        return $this->path.$this->name.'/htdocs';
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

    public function composerInstall($dev = false, $scripts = true)
    {
        chdir($this->getHtdocsFolder());
        if (!file_exists('composer.json')) {
            chdir('symfony');
        }
        exec('env HOME='.$this->getHtdocsFolder().' PATH='.$this->getPath().' SYMFONY_ENV=prod composer install '.($dev ? '' : '--no-dev ').($scripts ? '' : '--no-scripts ').' 2>&1', $output, $retval);
        if ($retval) {
            throw new \Exception(implode("\n", $output));
        }

        return true;
    }

    public function cacheClear()
    {
        $cacheFolders = array_filter([$this->getHtdocsFolder().'/symfony/app/cache/', $this->getHtdocsFolder().'/symfony/var/cache/'], 'is_dir');
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
        chdir($this->getHtdocsFolder().'/symfony');
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
        chdir($this->getHtdocsFolder().'/utilities');
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
        chdir($this->getHtdocsFolder().'/logic');
        $process = new PhpProcess(<<<EOF
<?php
require('../symfony/vendor/autoload.php');
require('configuration.php');
echo(json_encode(\$configuration));
EOF
);
        $process->run();

        $this->configuration = json_decode($process->getOutput(), true);
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
