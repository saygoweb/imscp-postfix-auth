<?php
/**
 * Drive the i-MSCP plugin manager from a shell, for development.
 *
 * The panel offers no CLI for plugin management, so every deploy/install cycle
 * would otherwise be a trip through the web interface. This boots the panel's
 * own environment and calls the same PluginManager the interface calls, so the
 * behaviour under test is the real one.
 *
 * Development only: excluded from the release archive.
 *
 * Run inside the box, as the panel user so that anything it writes stays
 * readable by the panel:
 *
 *   sudo -u vu2000 php /usr/local/src/imscp-postfix-auth/tools/plugin-ctl.php install
 *
 * It runs from the working copy rather than the deployed plugin: the plugins
 * directory is scanned for plugins, and a tools directory sitting in it would
 * be taken for one.
 *
 * Commands: sync, status, install, enable, disable, uninstall, update, delete
 */

use iMSCP\Registry;

if (PHP_SAPI !== 'cli') {
    exit("This script is for the command line only.\n");
}

$command = isset($argv[1]) ? $argv[1] : 'status';
$pluginName = isset($argv[2]) ? $argv[2] : 'SGW_PostfixAuth';

chdir('/var/www/imscp/gui/public');
require_once '/var/www/imscp/gui/include/imscp-lib.php';

/** @var \iMSCP\Plugin\PluginManager $pm */
$pm = Registry::get('pluginManager');

try {
    switch ($command) {
        case 'sync':
            // Picks up a plugin newly copied into the plugins directory, and
            // re-reads info.php and config.php for one already known.
            $pm->pluginSyncData();
            echo "Plugin data synchronised.\n";
            break;
        case 'install':
            $pm->pluginInstall($pluginName);
            echo "$pluginName: install requested.\n";
            break;
        case 'enable':
            $pm->pluginEnable($pluginName);
            echo "$pluginName: enable requested.\n";
            break;
        case 'disable':
            $pm->pluginDisable($pluginName);
            echo "$pluginName: disable requested.\n";
            break;
        case 'update':
            $pm->pluginUpdate($pluginName);
            echo "$pluginName: update requested.\n";
            break;
        case 'uninstall':
            $pm->pluginUninstall($pluginName);
            echo "$pluginName: uninstall requested.\n";
            break;
        case 'delete':
            $pm->pluginDelete($pluginName);
            echo "$pluginName: deleted.\n";
            break;
        case 'status':
            if (!$pm->pluginIsKnown($pluginName)) {
                echo "$pluginName: not known to the panel; run 'sync' first.\n";
                exit(1);
            }

            printf(
                "%s: %s%s\n",
                $pluginName,
                $pm->pluginGetStatus($pluginName),
                $pm->pluginHasError($pluginName)
                    ? ' -- ' . $pm->pluginGetError($pluginName) : ''
            );
            break;
        default:
            exit("Unknown command '$command'.\n");
    }
} catch (Exception $e) {
    // The manager reports a plugin's own failure through plugin_error rather
    // than by throwing, so print both.
    fwrite(STDERR, $e->getMessage() . "\n");

    if ($pm->pluginIsKnown($pluginName) && $pm->pluginHasError($pluginName)) {
        fwrite(STDERR, $pm->pluginGetError($pluginName) . "\n");
    }

    exit(1);
}

// Every action above only queues work for the backend; nothing has happened on
// the server until the request manager has run.
if (in_array($command, array('install', 'enable', 'disable', 'update', 'uninstall'), true)) {
    echo "Now run: sudo perl /var/www/imscp/engine/imscp-rqst-mngr\n";
}
