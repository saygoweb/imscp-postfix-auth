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

require_once __DIR__ . '/../common.php';

/***********************************************************************************************************************
 * Functions
 */

/**
 * How a zone's SPF setting reads in the list.
 *
 * @param array $row
 * @return string
 */
function spfSummary(array $row)
{
    switch ($row['spf_mode']) {
        case 'guided':
        case 'raw':
            return tr('custom');
        default:
            return tr('default');
    }
}

/**
 * Fill the zone table.
 *
 * @param TemplateEngine $tpl
 * @param int $adminId Customer unique identifier
 * @return void
 */
function generatePage($tpl, $adminId)
{
    $labels = array('dmn' => tr('Domain'), 'als' => tr('Alias'));

    $rows = getZones($adminId);

    if (!$rows) {
        $tpl->assign(array(
            'ZONE_LIST' => '',
            'NO_ZONES'  => tr('You have no domains yet.')
        ));
        $tpl->parse('NO_ZONES_BLOCK', 'no_zones_block');

        return;
    }

    $tpl->assign('NO_ZONES_BLOCK', '');

    $defaults = defaults();

    foreach ($rows as $row) {
        // A zone nobody has configured yet has no row of its own, so show the
        // settings it would be given rather than a line full of nulls.
        if ($row['postfix_auth_id'] === null) {
            $row = array_merge($row, $defaults);
        }

        $tpl->assign(array(
            'DOMAIN_NAME' => tohtml(decode_idna($row['domain_name'])),
            'ZONE_KIND'   => tohtml($labels[$row['domain_type']]),
            'STATUS'      => tohtml(statusText($row['status'])),
            'STATUS_ICON' => statusIcon($row['status']),
            'DKIM'        => $row['dkim_enabled'] ? tr('on') : tr('off'),
            'SPF'         => tohtml(spfSummary($row)),
            'DMARC'       => $row['dmarc_enabled']
                ? tohtml('p=' . $row['dmarc_p']) : tr('off'),
            'PUBLISH_DNS' => $row['publish_dns'] ? tr('this server') : tr('elsewhere'),
            'NOTE'        => tohtml($row['state']),
            'EDIT_LINK'   => tohtml('postfix_auth_edit.php?type=' . $row['domain_type']
                . '&id=' . $row['domain_id'], 'htmlAttr')
        ));

        // Only a settled zone may be edited; while the backend is working on
        // one, its actions are replaced by a plain "updating" note.
        if (isSettled($row['status'])) {
            $tpl->parse('ZONE_ACTIONS', 'zone_actions');
            $tpl->assign('ZONE_BUSY', '');
        } else {
            $tpl->assign('ZONE_ACTIONS', '');
            $tpl->parse('ZONE_BUSY', 'zone_busy');
        }

        $tpl->parse('ZONE_ITEM', '.zone_item');
    }
}

/***********************************************************************************************************************
 * Main
 */

EventAggregator::getInstance()->dispatch(Events::onClientScriptStart);
check_login('user');

$adminId = intval($_SESSION['user_id']);

if (!SGW_PostfixAuth::customerHasPostfixAuth($adminId)) {
    showBadRequestErrorPage();
}

$tpl = new TemplateEngine();
$tpl->define_dynamic(array(
    'layout'         => 'shared/layouts/ui.tpl',
    'page'           => '../../plugins/SGW_PostfixAuth/themes/default/view/client/postfix_auth.tpl',
    'page_message'   => 'layout',
    'no_zones_block' => 'page',
    'zone_list'      => 'page',
    'zone_item'      => 'zone_list',
    'zone_actions'   => 'zone_item',
    'zone_busy'      => 'zone_item'
));
$tpl->assign(array(
    'TR_PAGE_TITLE'  => tr('Client / Mail / Email authentication'),
    'TR_INTRO'       => tr('Prove that mail claiming to come from your domains really does. DKIM signs the mail your server sends, SPF says which servers may send it, and DMARC tells everyone else what to do with mail that fails both.'),
    'TR_DOMAIN_NAME' => tr('Domain'),
    'TR_ZONE_KIND'   => tr('Type'),
    'TR_STATUS'      => tr('Status'),
    'TR_DKIM'        => tr('DKIM'),
    'TR_SPF'         => tr('SPF'),
    'TR_DMARC'       => tr('DMARC'),
    'TR_PUBLISH_DNS' => tr('DNS served by'),
    'TR_NOTE'        => tr('Notes'),
    'TR_ACTION'      => tr('Actions'),
    'TR_EDIT'        => tr('Edit'),
    'TR_BUSY'        => tr('Updating...')
));

generateNavigation($tpl);
generatePage($tpl, $adminId);
generatePageMessage($tpl);

$tpl->parse('LAYOUT_CONTENT', 'page');
EventAggregator::getInstance()->dispatch(Events::onClientScriptEnd, array('templateEngine' => $tpl));
$tpl->prnt();
