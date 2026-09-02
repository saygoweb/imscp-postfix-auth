<?php
namespace iMSCP\Plugin\SGW_PostfixAuth;
/**
 * i-MSCP SGW_PostfixAuth plugin
 * Copyright (C) 2026 Cambell Prince <cambell.prince@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

use iMSCP\Event\Event;
use iMSCP\Event\EventManagerInterface;
use iMSCP\Event\Events;
use iMSCP\Plugin\AbstractPlugin;
use iMSCP\Plugin\PluginException;
use iMSCP\Plugin\PluginManager;
use iMSCP\Registry;

/**
 * Email authentication plugin.
 *
 * Gives every domain and domain alias a DKIM signing key, a customisable SPF
 * record and a DMARC record. The records are published through i-MSCP's own
 * custom DNS machinery, so a customer sees them in their DNS list but cannot
 * edit them out from under the plugin.
 */
class SGW_PostfixAuth extends AbstractPlugin
{
    /**
     * Name this plugin claims its DNS resource records under.
     *
     * i-MSCP renders a record owned by anything other than the custom DNS
     * feature as read-only, which is exactly what these records should be.
     */
    const DNS_OWNER = 'SGW_PostfixAuth';

    /**
     * Statuses that mean the backend has nothing left to do for a zone
     */
    const SETTLED_STATUSES = array('ok', 'disabled');

    /**
     * Statuses the backend consumes
     */
    const PENDING_STATUSES = array(
        'toadd', 'tochange', 'toenable', 'todisable', 'todelete'
    );

    /**
     * Plugin initialization
     *
     * @return void
     */
    public function init()
    {
        l10n_addTranslations(__DIR__ . '/l10n', 'Array', $this->getName());
    }

    /**
     * Register event listeners
     *
     * @param EventManagerInterface $eventsManager
     * @return void
     */
    public function register(EventManagerInterface $eventsManager)
    {
        $eventsManager->registerListener(
            array(
                Events::onResellerScriptStart,
                Events::onClientScriptStart,
                // A zone that goes away must take its key and its records with
                // it. Only domains and aliases have zones; a subdomain is
                // covered by its parent and needs no cleanup of its own.
                Events::onAfterDeleteDomainAlias,
                Events::onAfterDeleteCustomer
            ),
            $this
        );
    }

    /**
     * Plugin installation
     *
     * @throws PluginException
     * @param PluginManager $pluginManager
     * @return void
     */
    public function install(PluginManager $pluginManager)
    {
        try {
            $this->migrateDb('up');
        } catch (PluginException $e) {
            throw new PluginException($e->getMessage(), $e->getCode(), $e);
        }
    }

    /**
     * Plugin update
     *
     * @throws PluginException
     * @param PluginManager $pluginManager
     * @param string $fromVersion
     * @param string $toVersion
     * @return void
     */
    public function update(PluginManager $pluginManager, $fromVersion, $toVersion)
    {
        try {
            $this->migrateDb('up');
            $this->clearTranslations();
        } catch (PluginException $e) {
            throw new PluginException($e->getMessage(), $e->getCode(), $e);
        }
    }

    /**
     * Plugin uninstallation
     *
     * @throws PluginException
     * @param PluginManager $pluginManager
     * @return void
     */
    public function uninstall(PluginManager $pluginManager)
    {
        try {
            $this->migrateDb('down');
            $this->clearTranslations();
        } catch (PluginException $e) {
            throw new PluginException($e->getMessage(), $e->getCode(), $e);
        }
    }

    /**
     * onResellerScriptStart event listener
     *
     * @return void
     */
    public function onResellerScriptStart()
    {
        $this->setupNavigation('reseller');
    }

    /**
     * onClientScriptStart event listener
     *
     * @return void
     */
    public function onClientScriptStart()
    {
        if (self::customerHasPostfixAuth(intval($_SESSION['user_id']))) {
            $this->setupNavigation('client');
        }
    }

    /**
     * onAfterDeleteCustomer event listener
     *
     * @param Event $event
     * @return void
     */
    public function onAfterDeleteCustomer(Event $event)
    {
        exec_query(
            'UPDATE postfix_auth SET status = ? WHERE admin_id = ?',
            array('todelete', $event->getParam('customerId'))
        );
        exec_query(
            'DELETE FROM postfix_auth_perm WHERE admin_id = ?',
            array($event->getParam('customerId'))
        );
    }

    /**
     * onAfterDeleteDomainAlias event listener
     *
     * @param Event $event
     * @return void
     */
    public function onAfterDeleteDomainAlias(Event $event)
    {
        exec_query(
            'UPDATE postfix_auth SET status = ? WHERE domain_type = ? AND domain_id = ?',
            array('todelete', 'als', $event->getParam('domainAliasId'))
        );
    }

    /**
     * Get routes
     *
     * @return array
     */
    public function getRoutes()
    {
        $pluginDir = $this->getPluginManager()->pluginGetRootDir() . '/' . $this->getName();

        return array(
            '/client/postfix_auth.php'      => $pluginDir . '/frontend/client/postfix_auth.php',
            '/client/postfix_auth_edit.php' => $pluginDir . '/frontend/client/postfix_auth_edit.php',
            '/reseller/postfix_auth.php'    => $pluginDir . '/frontend/reseller/postfix_auth.php'
        );
    }

    /**
     * Get status of items with errors
     *
     * @return array
     */
    public function getItemWithErrorStatus()
    {
        $stmt = exec_query(
            "
                SELECT postfix_auth_id AS item_id, domain_name AS item_name,
                    'postfix_auth' AS `table`, 'status' AS field
                FROM postfix_auth
                WHERE status NOT IN(?, ?, ?, ?, ?, ?, ?)
            ",
            array_merge(self::SETTLED_STATUSES, self::PENDING_STATUSES)
        );

        if ($stmt->rowCount()) {
            return $stmt->fetchAll(\PDO::FETCH_ASSOC);
        }

        return array();
    }

    /**
     * Set status of the given plugin item to 'tochange'
     *
     * @param string $table Table name
     * @param string $field Status field name
     * @param int $itemId Item unique identifier
     * @return void
     */
    public function changeItemStatus($table, $field, $itemId)
    {
        if ($table == 'postfix_auth' && $field == 'status') {
            exec_query(
                'UPDATE postfix_auth SET status = ? WHERE postfix_auth_id = ?',
                array('tochange', $itemId)
            );
        }
    }

    /**
     * Return count of requests in progress
     *
     * @return int
     */
    public function getCountRequests()
    {
        $stmt = exec_query(
            'SELECT COUNT(postfix_auth_id) AS cnt FROM postfix_auth WHERE status IN (?, ?, ?, ?, ?)',
            self::PENDING_STATUSES
        );
        $row = $stmt->fetchRow(\PDO::FETCH_ASSOC);

        return $row['cnt'];
    }

    /**
     * Is email authentication available to the given customer?
     *
     * Available to everyone unless a reseller has explicitly withdrawn it,
     * which is recorded as a row in postfix_auth_perm.
     *
     * @param int $customerId Customer unique identifier
     * @return bool
     */
    public static function customerHasPostfixAuth($customerId)
    {
        static $hasAccess = array();

        if (!array_key_exists($customerId, $hasAccess)) {
            $stmt = exec_query(
                'SELECT allowed FROM postfix_auth_perm WHERE admin_id = ?',
                array($customerId)
            );
            $row = $stmt->fetchRow(\PDO::FETCH_ASSOC);
            $hasAccess[$customerId] = ($row === false)
                ? self::allowedByDefault() : (bool)$row['allowed'];
        }

        return $hasAccess[$customerId];
    }

    /**
     * Does a customer with no explicit permission row get the feature?
     *
     * @return bool
     */
    public static function allowedByDefault()
    {
        static $allowed = NULL;

        if ($allowed === NULL) {
            $allowed = true;

            // Guarded rather than assumed: this is reached from page code that
            // has no plugin instance to hand, and a plugin whose config could
            // not be read should still show its pages rather than lock every
            // customer out.
            if (Registry::isRegistered('pluginManager')) {
                try {
                    $plugin = Registry::get('pluginManager')->pluginGet('SGW_PostfixAuth');
                    $allowed = (bool)$plugin->getConfigParam('allowed_by_default', true);
                } catch (\Exception $e) {
                    // Keep the default.
                }
            }
        }

        return $allowed;
    }

    /**
     * Inject links into the navigation object
     *
     * @param string $level UI level (reseller|client)
     * @return void
     */
    protected function setupNavigation($level)
    {
        if (!Registry::isRegistered('navigation')) {
            return;
        }

        /** @var \Zend_Navigation $navigation */
        $navigation = Registry::get('navigation');

        if ($level == 'reseller') {
            if (($page = $navigation->findOneBy('uri', '/reseller/users.php'))) {
                $page->addPage(array(
                    'label'              => tr('Email authentication'),
                    'uri'                => '/reseller/postfix_auth.php',
                    'title_class'        => 'users',
                    'privilege_callback' => array('name' => 'resellerHasCustomers')
                ));
            }
        } elseif ($level == 'client') {
            // Under Mail rather than Domains: what this configures is how the
            // customer's mail is authenticated, even though it is published
            // as DNS.
            if (($page = $navigation->findOneBy('uri', '/client/mail_accounts.php'))) {
                $page->addPage(array(
                    'label'       => tr('Email authentication'),
                    'uri'         => '/client/postfix_auth.php',
                    'title_class' => 'email',
                    // The edit page has to be a navigation page in its own
                    // right: the shared layout renders its heading from the
                    // active page, and dies if the current URI matches none.
                    'pages'       => array(
                        'postfix_auth_edit' => array(
                            'label'       => tr('Edit email authentication'),
                            'uri'         => '/client/postfix_auth_edit.php',
                            'title_class' => 'email'
                        )
                    )
                ));
            }
        }
    }

    /**
     * Clear translations if any
     *
     * @return void
     */
    protected function clearTranslations()
    {
        /** @var \Zend_Translate $translator */
        $translator = Registry::get('translator');

        if ($translator->hasCache()) {
            $translator->clearCache($this->getName());
        }
    }
}
