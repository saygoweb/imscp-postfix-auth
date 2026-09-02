<?php
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

namespace SGW_PostfixAuth;

use iMSCP\Event\EventAggregator;
use iMSCP\Event\Events;
use iMSCP\Plugin\SGW_PostfixAuth\SGW_PostfixAuth;
use iMSCP\TemplateEngine;
use PDO;

require_once __DIR__ . '/../common.php';

/***********************************************************************************************************************
 * Functions
 */

/**
 * The reseller's customers, with their permission and signing counts.
 *
 * @param int $resellerId Reseller unique identifier
 * @return array
 */
function getCustomers($resellerId)
{
    $stmt = exec_query(
        '
            SELECT a.admin_id, a.admin_name,
                COALESCE(p.allowed, ?) AS allowed,
                (
                    SELECT COUNT(*) FROM postfix_auth AS z
                    WHERE z.admin_id = a.admin_id AND z.dkim_enabled = 1
                ) AS dkim_count
            FROM admin AS a
            LEFT JOIN postfix_auth_perm AS p ON p.admin_id = a.admin_id
            WHERE a.created_by = ? AND a.admin_type = ?
            ORDER BY a.admin_name
        ',
        array(
            SGW_PostfixAuth::allowedByDefault() ? 1 : 0,
            $resellerId,
            'user'
        )
    );

    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

/**
 * Is this customer one of the reseller's own?
 *
 * @param int $resellerId Reseller unique identifier
 * @param int $customerId Customer unique identifier
 * @return bool
 */
function ownsCustomer($resellerId, $customerId)
{
    $stmt = exec_query(
        'SELECT COUNT(admin_id) AS cnt FROM admin WHERE admin_id = ? AND created_by = ? AND admin_type = ?',
        array($customerId, $resellerId, 'user')
    );
    $row = $stmt->fetchRow(PDO::FETCH_ASSOC);

    return $row['cnt'] > 0;
}

/**
 * Turn DKIM signing on or off across every zone a customer owns.
 *
 * Only DKIM: SPF and DMARC say what receivers should do with a customer's
 * mail, and that is the customer's decision to make per domain. Signing is the
 * part an operator can reasonably switch on for everybody.
 *
 * @param int $customerId Customer unique identifier
 * @param bool $enable
 * @return int Number of zones affected
 */
function bulkSetDkim($customerId, $enable)
{
    $count = 0;

    foreach (getZones($customerId) as $zone) {
        // A zone the backend is mid-way through is left alone rather than
        // having a second change stacked on top of it.
        if (!isSettled($zone['status'])) {
            continue;
        }

        $row = getOrCreateRow($zone, $customerId);

        // A zone that ends up with nothing turned on goes back to 'todisable',
        // so the backend takes it off its books rather than keeping an empty
        // configuration alive.
        $stillConfigured = $enable || $row['dmarc_enabled'] || $row['spf_mode'] !== 'off';

        exec_query(
            'UPDATE postfix_auth SET dkim_enabled = ?, status = ? WHERE postfix_auth_id = ?',
            array(
                $enable ? 1 : 0,
                $stillConfigured ? 'tochange' : 'todisable',
                $row['postfix_auth_id']
            )
        );
        $count++;
    }

    return $count;
}

/**
 * Apply an action requested from the list.
 *
 * @param int $resellerId Reseller unique identifier
 * @return void
 */
function handleAction($resellerId)
{
    if (!isset($_GET['action'], $_GET['customer_id'])) {
        return;
    }

    $action = clean_input($_GET['action']);
    $customerId = intval($_GET['customer_id']);

    if (!ownsCustomer($resellerId, $customerId)) {
        showBadRequestErrorPage();
    }

    switch ($action) {
        case 'allow':
        case 'deny':
            $allowed = ($action === 'allow') ? 1 : 0;
            exec_query(
                '
                    INSERT INTO postfix_auth_perm (admin_id, allowed) VALUES (?, ?)
                    ON DUPLICATE KEY UPDATE allowed = ?
                ',
                array($customerId, $allowed, $allowed)
            );

            // Withdrawing the feature has to take the signing with it,
            // otherwise the customer keeps signed mail but loses the switch -
            // and with it any way to replace a key.
            if (!$allowed) {
                $count = bulkSetDkim($customerId, false);
                send_request();
                set_page_message(
                    tr('Email authentication withdrawn, and signing disabled on %d domain(s).', $count),
                    'success'
                );
            } else {
                set_page_message(tr('Email authentication made available to the customer.'), 'success');
            }
            break;

        case 'enable_all':
        case 'disable_all':
            $enable = ($action === 'enable_all');

            if ($enable && !SGW_PostfixAuth::customerHasPostfixAuth($customerId)) {
                set_page_message(
                    tr('This customer is not allowed to use email authentication.'), 'error'
                );
                break;
            }

            $count = bulkSetDkim($customerId, $enable);
            send_request();
            set_page_message(
                $enable
                    ? tr('DKIM scheduled to be enabled on %d domain(s).', $count)
                    : tr('DKIM scheduled to be disabled on %d domain(s).', $count),
                'success'
            );
            break;

        default:
            showBadRequestErrorPage();
    }

    redirectTo('postfix_auth.php');
}

/**
 * Fill the customer table.
 *
 * @param TemplateEngine $tpl
 * @param int $resellerId Reseller unique identifier
 * @return void
 */
function generatePage($tpl, $resellerId)
{
    $customers = getCustomers($resellerId);

    if (!$customers) {
        $tpl->assign(array(
            'CUSTOMER_LIST' => '',
            'NO_CUSTOMERS'  => tr('You have no customers yet.')
        ));
        $tpl->parse('NO_CUSTOMERS_BLOCK', 'no_customers_block');

        return;
    }

    $tpl->assign('NO_CUSTOMERS_BLOCK', '');

    foreach ($customers as $customer) {
        $allowed = (bool)$customer['allowed'];
        $link = 'postfix_auth.php?customer_id=' . $customer['admin_id'] . '&action=';

        $tpl->assign(array(
            'CUSTOMER_NAME' => tohtml(decode_idna($customer['admin_name'])),
            'ALLOWED'       => $allowed ? tr('yes') : tr('no'),
            'ALLOWED_ICON'  => $allowed ? 'ok' : 'disabled',
            'DKIM_COUNT'    => tohtml($customer['dkim_count']),
            'PERM_LINK'     => tohtml($link . ($allowed ? 'deny' : 'allow'), 'htmlAttr'),
            'PERM_LABEL'    => $allowed ? tr('Withdraw') : tr('Allow'),
            'PERM_ICON'     => $allowed ? 'close' : 'ok',
            // Only withdrawing is destructive, so only withdrawing confirms.
            'PERM_ONCLICK'  => $allowed
                ? tohtml("return confirm('" . tojs(tr('Withdrawing the feature also stops signing this customer\'s mail. Continue?')) . "');", 'htmlAttr')
                : '',
            'ENABLE_LINK'   => tohtml($link . 'enable_all', 'htmlAttr'),
            'DISABLE_LINK'  => tohtml($link . 'disable_all', 'htmlAttr')
        ));

        if ($allowed) {
            $tpl->parse('BULK_ACTIONS', 'bulk_actions');
        } else {
            $tpl->assign('BULK_ACTIONS', '');
        }

        $tpl->parse('CUSTOMER_ITEM', '.customer_item');
    }
}

/***********************************************************************************************************************
 * Main
 */

EventAggregator::getInstance()->dispatch(Events::onResellerScriptStart);
check_login('reseller');

$resellerId = intval($_SESSION['user_id']);

handleAction($resellerId);

$tpl = new TemplateEngine();
$tpl->define_dynamic(array(
    'layout'             => 'shared/layouts/ui.tpl',
    'page'               => '../../plugins/SGW_PostfixAuth/themes/default/view/reseller/postfix_auth.tpl',
    'page_message'       => 'layout',
    'no_customers_block' => 'page',
    'customer_list'      => 'page',
    'customer_item'      => 'customer_list',
    'bulk_actions'       => 'customer_item'
));
$tpl->assign(array(
    'TR_PAGE_TITLE'      => tr('Reseller / Customers / Email authentication'),
    'TR_INTRO'           => tr('Decide which customers may configure DKIM, SPF and DMARC for their domains, and switch DKIM signing on or off across all of a customer\'s domains at once. SPF and DMARC stay with the customer: those records say what receivers should do with their mail.'),
    'TR_CUSTOMER'        => tr('Customer'),
    'TR_ALLOWED'         => tr('Allowed'),
    'TR_DKIM_COUNT'      => tr('Domains signed'),
    'TR_ACTION'          => tr('Actions'),
    'TR_ENABLE_ALL'      => tr('Sign all domains'),
    'TR_DISABLE_ALL'     => tr('Stop signing all domains'),
    'TR_ENABLE_CONFIRM'  => tr('Sign mail for every domain this customer owns?'),
    'TR_DISABLE_CONFIRM' => tr('Stop signing mail for every domain this customer owns?')
));

generateNavigation($tpl);
generatePage($tpl, $resellerId);
generatePageMessage($tpl);

$tpl->parse('LAYOUT_CONTENT', 'page');
EventAggregator::getInstance()->dispatch(Events::onResellerScriptEnd, array('templateEngine' => $tpl));
$tpl->prnt();
