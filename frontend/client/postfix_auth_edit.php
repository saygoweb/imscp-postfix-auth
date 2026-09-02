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
 * Read the posted settings, clamping anything a browser could have sent.
 *
 * @return array
 */
function readPostedSettings()
{
    $defaults = defaults();

    $text = function ($name) {
        return isset($_POST[$name]) ? clean_input($_POST[$name]) : '';
    };

    $choice = function ($name, array $allowed) use ($defaults) {
        $value = isset($_POST[$name]) ? clean_input($_POST[$name]) : '';

        return in_array($value, $allowed, true) ? $value : $defaults[$name];
    };

    $keySize = isset($_POST['dkim_key_size']) ? intval($_POST['dkim_key_size']) : 2048;

    return array(
        'publish_dns'   => isset($_POST['publish_dns']) ? 1 : 0,
        'dkim_enabled'  => isset($_POST['dkim_enabled']) ? 1 : 0,
        'dkim_key_size' => in_array($keySize, array(1024, 2048, 4096), true) ? $keySize : 2048,
        'spf_mode'      => $choice('spf_mode', array('off', 'guided', 'raw')),
        'spf_a'         => isset($_POST['spf_a']) ? 1 : 0,
        'spf_mx'        => isset($_POST['spf_mx']) ? 1 : 0,
        'spf_hosts'     => $text('spf_hosts'),
        'spf_includes'  => $text('spf_includes'),
        'spf_redirect'  => $text('spf_redirect'),
        'spf_qualifier' => $choice('spf_qualifier', array('-all', '~all', '?all')),
        'spf_raw'       => $text('spf_raw'),
        'dmarc_enabled' => isset($_POST['dmarc_enabled']) ? 1 : 0,
        'dmarc_p'       => $choice('dmarc_p', array('none', 'quarantine', 'reject')),
        'dmarc_sp'      => $choice('dmarc_sp', array('', 'none', 'quarantine', 'reject')),
        'dmarc_pct'     => max(0, min(100, isset($_POST['dmarc_pct']) ? intval($_POST['dmarc_pct']) : 100)),
        'dmarc_rua'     => $text('dmarc_rua'),
        'dmarc_ruf'     => $text('dmarc_ruf'),
        'dmarc_adkim'   => $choice('dmarc_adkim', array('r', 's')),
        'dmarc_aspf'    => $choice('dmarc_aspf', array('r', 's')),
        'dmarc_fo'      => $choice('dmarc_fo', array('0', '1', 'd', 's')),
        // An hour is the shortest interval a reporter will honour; a fortnight
        // is longer than any report is useful for.
        'dmarc_ri'      => max(3600, min(1209600, isset($_POST['dmarc_ri']) ? intval($_POST['dmarc_ri']) : 86400))
    );
}

/**
 * Check the posted settings, adding a page message for each problem found.
 *
 * @param array $settings
 * @param array $zone Row as returned by getZones()
 * @return bool True when the settings may be saved
 */
function validateSettings(array $settings, array $zone)
{
    $ok = true;

    if ($settings['spf_mode'] === 'raw') {
        $raw = trim($settings['spf_raw']);

        if ($raw === '') {
            set_page_message(tr('The SPF record cannot be empty when you are writing it yourself.'), 'error');
            $ok = false;
        } elseif (stripos($raw, 'v=spf1') !== 0) {
            set_page_message(tr('An SPF record must begin with "v=spf1".'), 'error');
            $ok = false;
        }
    }

    if ($settings['spf_mode'] !== 'off') {
        // Counted on the composed record for the guided mode too: enough
        // include: entries reaches the cap just as easily as a hand-written
        // record does.
        $record = ($settings['spf_mode'] === 'raw')
            ? $settings['spf_raw'] : previewSpf($settings);
        $lookups = spfLookupCount($record);

        if ($lookups > 10) {
            set_page_message(tr(
                'This SPF record needs %d DNS lookups, and the limit is 10. Over the limit, receivers treat the record as broken rather than ignoring the excess.',
                $lookups
            ), 'error');
            $ok = false;
        }
    }

    foreach (array('dmarc_rua' => tr('aggregate'), 'dmarc_ruf' => tr('forensic')) as $field => $label) {
        if (!$settings['dmarc_enabled'] || trim($settings[$field]) === '') {
            continue;
        }

        foreach (explode(',', $settings[$field]) as $address) {
            $address = trim($address);
            if ($address === '') {
                continue;
            }

            $address = preg_replace('/^mailto:/i', '', $address);

            if (!filter_var($address, FILTER_VALIDATE_EMAIL)) {
                set_page_message(tr(
                    '"%s" is not a valid address for %s reports.', tohtml($address), $label
                ), 'error');
                $ok = false;
            }
        }
    }

    if ($settings['dmarc_enabled'] && $settings['dmarc_p'] !== 'none'
        && !$settings['dkim_enabled']
    ) {
        set_page_message(tr(
            'A DMARC policy stronger than "none" without DKIM will have your mail quarantined or rejected whenever SPF alone does not align. Turn DKIM on first.'
        ), 'error');
        $ok = false;
    }

    return $ok;
}

/**
 * Compose the guided SPF record for display and for lookup counting.
 *
 * This mirrors the backend's own composition; it is the backend's version that
 * is published, and what the panel shows once a zone has been saved is read
 * back from the database rather than composed here.
 *
 * @param array $settings
 * @return string
 */
function previewSpf(array $settings)
{
    $terms = array('v=spf1');

    if ($settings['spf_a']) {
        $terms[] = 'a';
    }

    if ($settings['spf_mx']) {
        $terms[] = 'mx';
    }

    foreach (preg_split('/[\r\n,]+/', $settings['spf_hosts']) as $host) {
        $host = trim($host);
        if ($host === '') {
            continue;
        }

        // Named mechanisms rather than "word, then colon": an IPv6 address is
        // full of colons and would otherwise look like a prefixed term.
        if (preg_match('/^[+\-~?]?(ip4|ip6|a|mx|include|exists|ptr|redirect|exp)[:=]/i', $host)) {
            $terms[] = $host;
        } else {
            $terms[] = (strpos($host, ':') !== false ? 'ip6:' : 'ip4:') . $host;
        }
    }

    foreach (preg_split('/[\r\n,]+/', $settings['spf_includes']) as $include) {
        $include = trim($include);
        if ($include === '') {
            continue;
        }

        $terms[] = (stripos($include, 'include:') === 0) ? $include : 'include:' . $include;
    }

    $redirect = trim($settings['spf_redirect']);

    if ($redirect !== '') {
        $terms[] = (stripos($redirect, 'redirect=') === 0) ? $redirect : 'redirect=' . $redirect;
    } else {
        $terms[] = $settings['spf_qualifier'];
    }

    return implode(' ', $terms);
}

/**
 * Save the posted settings and hand the zone to the backend.
 *
 * @param array $zone Row as returned by getZones()
 * @param int $adminId Customer unique identifier
 * @return void
 */
function saveSettings(array $zone, $adminId)
{
    $row = getOrCreateRow($zone, $adminId);
    $settings = readPostedSettings();

    if (!validateSettings($settings, $zone)) {
        return;
    }

    if ($settings['dmarc_adkim'] === 's' && hasMailSubdomains($zone)) {
        set_page_message(tr(
            'This domain has subdomains that send mail. Their mail is signed with this domain\'s key, which strict DKIM alignment will not accept, so DMARC will fail for them.'
        ), 'warning');
    }

    $configured = $settings['dkim_enabled'] || $settings['dmarc_enabled']
        || $settings['spf_mode'] !== 'off';

    exec_query(
        '
            UPDATE postfix_auth SET
                publish_dns = ?, dkim_enabled = ?, dkim_key_size = ?,
                spf_mode = ?, spf_a = ?, spf_mx = ?, spf_hosts = ?,
                spf_includes = ?, spf_redirect = ?, spf_qualifier = ?,
                spf_raw = ?, dmarc_enabled = ?, dmarc_p = ?, dmarc_sp = ?,
                dmarc_pct = ?, dmarc_rua = ?, dmarc_ruf = ?, dmarc_adkim = ?,
                dmarc_aspf = ?, dmarc_fo = ?, dmarc_ri = ?, status = ?, state = ?
            WHERE postfix_auth_id = ?
        ',
        array(
            $settings['publish_dns'], $settings['dkim_enabled'], $settings['dkim_key_size'],
            $settings['spf_mode'], $settings['spf_a'], $settings['spf_mx'],
            $settings['spf_hosts'], $settings['spf_includes'], $settings['spf_redirect'],
            $settings['spf_qualifier'], $settings['spf_raw'], $settings['dmarc_enabled'],
            $settings['dmarc_p'], $settings['dmarc_sp'], $settings['dmarc_pct'],
            $settings['dmarc_rua'], $settings['dmarc_ruf'], $settings['dmarc_adkim'],
            $settings['dmarc_aspf'], $settings['dmarc_fo'], $settings['dmarc_ri'],
            // A zone with nothing turned on is taken back off the backend's
            // books entirely, rather than left "configured" with no content.
            $configured ? 'tochange' : 'todisable', '',
            $row['postfix_auth_id']
        )
    );

    send_request();
    set_page_message(tr('Email authentication settings scheduled for update.'), 'success');
    redirectTo('postfix_auth.php');
}

/**
 * Retire the zone's DKIM key so that the backend issues a new one.
 *
 * The old key is retired rather than deleted, which keeps its selector out of
 * circulation: reusing a selector for different key material would let a
 * resolver still holding the old record verify against the wrong key.
 *
 * @param array $row Row from postfix_auth
 * @return void
 */
function regenerateKey(array $row)
{
    exec_query(
        'UPDATE postfix_auth_key SET retired_at = ? WHERE postfix_auth_id = ? AND retired_at = 0',
        array(time(), $row['postfix_auth_id'])
    );
    exec_query(
        'UPDATE postfix_auth SET status = ? WHERE postfix_auth_id = ?',
        array('tochange', $row['postfix_auth_id'])
    );

    send_request();
    set_page_message(tr(
        'A new DKIM key has been requested. Mail is signed with the new key as soon as it is generated, so publish the new record promptly if you host your own DNS elsewhere.'
    ), 'success');
}

/**
 * Fill the form.
 *
 * @param TemplateEngine $tpl
 * @param array $zone Row as returned by getZones()
 * @param array $row Settings from postfix_auth
 * @param bool $check Resolve each record and report whether it is published
 * @return void
 */
function generatePage($tpl, array $zone, array $row, $check)
{
    $checked = function ($value) {
        return $value ? ' checked' : '';
    };

    $selected = function ($value, $against) {
        return ($value === $against) ? ' selected' : '';
    };

    $tpl->assign(array(
        'DOMAIN_NAME'      => tohtml(decode_idna($zone['domain_name'])),
        'TYPE'             => tohtml($zone['domain_type'], 'htmlAttr'),
        'ID'               => tohtml($zone['domain_id'], 'htmlAttr'),
        'PUBLISH_DNS'      => $checked($row['publish_dns']),
        'DKIM_ENABLED'     => $checked($row['dkim_enabled']),
        'KEY_1024'         => $selected('1024', (string)$row['dkim_key_size']),
        'KEY_2048'         => $selected('2048', (string)$row['dkim_key_size']),
        'KEY_4096'         => $selected('4096', (string)$row['dkim_key_size']),
        'SPF_OFF'          => $selected('off', $row['spf_mode']),
        'SPF_GUIDED'       => $selected('guided', $row['spf_mode']),
        'SPF_RAW_MODE'     => $selected('raw', $row['spf_mode']),
        'SPF_A'            => $checked($row['spf_a']),
        'SPF_MX'           => $checked($row['spf_mx']),
        'SPF_HOSTS'        => tohtml($row['spf_hosts']),
        'SPF_INCLUDES'     => tohtml($row['spf_includes']),
        'SPF_REDIRECT'     => tohtml($row['spf_redirect'], 'htmlAttr'),
        'SPF_FAIL'         => $selected('-all', $row['spf_qualifier']),
        'SPF_SOFTFAIL'     => $selected('~all', $row['spf_qualifier']),
        'SPF_NEUTRAL'      => $selected('?all', $row['spf_qualifier']),
        'SPF_RAW'          => tohtml($row['spf_raw']),
        'DMARC_ENABLED'    => $checked($row['dmarc_enabled']),
        'DMARC_P_NONE'     => $selected('none', $row['dmarc_p']),
        'DMARC_P_QUAR'     => $selected('quarantine', $row['dmarc_p']),
        'DMARC_P_REJECT'   => $selected('reject', $row['dmarc_p']),
        'DMARC_SP_SAME'    => $selected('', $row['dmarc_sp']),
        'DMARC_SP_NONE'    => $selected('none', $row['dmarc_sp']),
        'DMARC_SP_QUAR'    => $selected('quarantine', $row['dmarc_sp']),
        'DMARC_SP_REJECT'  => $selected('reject', $row['dmarc_sp']),
        'DMARC_PCT'        => tohtml($row['dmarc_pct'], 'htmlAttr'),
        'DMARC_RUA'        => tohtml($row['dmarc_rua'], 'htmlAttr'),
        'DMARC_RUF'        => tohtml($row['dmarc_ruf'], 'htmlAttr'),
        'DMARC_ADKIM_R'    => $selected('r', $row['dmarc_adkim']),
        'DMARC_ADKIM_S'    => $selected('s', $row['dmarc_adkim']),
        'DMARC_ASPF_R'     => $selected('r', $row['dmarc_aspf']),
        'DMARC_ASPF_S'     => $selected('s', $row['dmarc_aspf']),
        'DMARC_RI'         => tohtml($row['dmarc_ri'], 'htmlAttr'),
        'REGENERATE_LINK'  => tohtml('postfix_auth_edit.php?type=' . $zone['domain_type']
            . '&id=' . $zone['domain_id'] . '&action=regenerate_key', 'htmlAttr'),
        'CHECK_LINK'       => tohtml('postfix_auth_edit.php?type=' . $zone['domain_type']
            . '&id=' . $zone['domain_id'] . '&action=check', 'htmlAttr')
    ));

    $records = zoneRecords($row);

    if (!$records) {
        $tpl->assign('RECORD_LIST', '');
        $tpl->parse('NO_RECORDS_BLOCK', 'no_records_block');

        return;
    }

    $tpl->assign('NO_RECORDS_BLOCK', '');

    $labels = array('dkim' => tr('DKIM'), 'spf' => tr('SPF'), 'dmarc' => tr('DMARC'));
    $verdicts = array(
        'ok'       => array(tr('Published'), 'ok'),
        'mismatch' => array(tr('A different record is published'), 'error'),
        'missing'  => array(tr('Not published yet'), 'disabled')
    );

    foreach ($records as $record) {
        $tpl->assign(array(
            'RECORD_KIND'  => tohtml($labels[$record['kind']]),
            'RECORD_NAME'  => tohtml($record['name']),
            'RECORD_VALUE' => tohtml($record['value'])
        ));

        if ($check) {
            $verdict = $verdicts[checkPublished($record['name'], $record['value'])];
            $tpl->assign(array(
                'RECORD_STATE'      => tohtml($verdict[0]),
                'RECORD_STATE_ICON' => $verdict[1]
            ));
            $tpl->parse('RECORD_STATE_BLOCK', 'record_state_block');
        } else {
            $tpl->assign('RECORD_STATE_BLOCK', '');
        }

        $tpl->parse('RECORD_ITEM', '.record_item');
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

if (!isset($_GET['type']) || !isset($_GET['id'])) {
    showBadRequestErrorPage();
}

$zone = getZone($adminId, clean_input($_GET['type']), intval($_GET['id']));
if ($zone === false) {
    showBadRequestErrorPage();
}

if (!isSettled($zone['status'])) {
    set_page_message(tr('That domain is still being updated. Try again shortly.'), 'warning');
    redirectTo('postfix_auth.php');
}

$check = false;

if (isset($_GET['action'])) {
    switch (clean_input($_GET['action'])) {
        case 'regenerate_key':
            $row = getOrCreateRow($zone, $adminId);

            if (!$row['dkim_enabled']) {
                set_page_message(tr('DKIM is not enabled for this domain.'), 'error');
            } else {
                regenerateKey($row);
            }

            redirectTo('postfix_auth.php');
            break;
        case 'check':
            $check = true;
            break;
        default:
            showBadRequestErrorPage();
    }
}

if (!empty($_POST)) {
    saveSettings($zone, $adminId);
}

$row = getOrCreateRow($zone, $adminId);

$tpl = new TemplateEngine();
$tpl->define_dynamic(array(
    'layout'             => 'shared/layouts/ui.tpl',
    'page'               => '../../plugins/SGW_PostfixAuth/themes/default/view/client/postfix_auth_edit.tpl',
    'page_message'       => 'layout',
    'no_records_block'   => 'page',
    'record_list'        => 'page',
    'record_item'        => 'record_list',
    'record_state_block' => 'record_item'
));
$tpl->assign(array(
    'TR_PAGE_TITLE'         => tr('Client / Mail / Email authentication / Edit'),

    'TR_DNS_SECTION'        => tr('DNS'),
    'TR_PUBLISH_DNS'        => tr('This server publishes the DNS for this domain'),
    'TR_PUBLISH_DNS_HELP'   => tr('Leave this on if your domain uses this server\'s nameservers, and the records below are published for you. Turn it off if your DNS is hosted elsewhere; the records are then shown here for you to publish by hand.'),

    'TR_DKIM_SECTION'       => tr('DKIM'),
    'TR_DKIM_INTRO'         => tr('DKIM adds a signature to every message your domain sends, which a receiver checks against a key published in your DNS. It is what lets a receiver tell your mail apart from mail that merely claims to be yours.'),
    'TR_DKIM_ENABLED'       => tr('Sign this domain\'s outgoing mail'),
    'TR_DKIM_KEY_SIZE'      => tr('Key size [bits]'),
    'TR_DKIM_KEY_SIZE_HELP' => tr('2048 is what every large mailbox provider now expects. Choose 1024 only if a receiver you deal with cannot read a 2048 bit record.'),
    'TR_REGENERATE'         => tr('Replace the key'),
    'TR_REGENERATE_CONFIRM' => tr('Replace this domain\'s DKIM key? Mail is signed with the new key immediately, so if you publish your own DNS elsewhere, update the record straight away.'),
    'TR_SUBDOMAIN_NOTE'     => tr('Mail from your subdomains is signed with this key as well.'),

    'TR_SPF_SECTION'        => tr('SPF'),
    'TR_SPF_INTRO'          => tr('SPF lists the servers allowed to send mail for your domain. Without a record of your own, this server publishes "v=spf1 a mx -all", which covers mail sent from here and nothing else.'),
    'TR_SPF_MODE'           => tr('SPF record'),
    'TR_SPF_MODE_OFF'       => tr('Use the server default'),
    'TR_SPF_MODE_GUIDED'    => tr('Build one from the settings below'),
    'TR_SPF_MODE_RAW'       => tr('Write it myself'),
    'TR_SPF_A'              => tr('Allow the domain\'s own address (a)'),
    'TR_SPF_MX'             => tr('Allow the domain\'s mail servers (mx)'),
    'TR_SPF_HOSTS'          => tr('Additional addresses'),
    'TR_SPF_HOSTS_HELP'     => tr('One IP address or range per line. Bare addresses are turned into ip4: or ip6: as appropriate.'),
    'TR_SPF_INCLUDES'       => tr('Other senders to allow'),
    'TR_SPF_INCLUDES_HELP'  => tr('One domain per line, for the mailing list or newsletter services that send on your behalf. Each one costs a DNS lookup, and the whole record is limited to ten.'),
    'TR_SPF_REDIRECT'       => tr('Or defer entirely to another domain\'s record'),
    'TR_SPF_REDIRECT_HELP'  => tr('A redirect replaces the whole record, so the settings above are ignored when this is set.'),
    'TR_SPF_QUALIFIER'      => tr('Mail from anywhere else'),
    'TR_SPF_FAIL'           => tr('Reject it (-all)'),
    'TR_SPF_SOFTFAIL'       => tr('Accept but mark it (~all)'),
    'TR_SPF_NEUTRAL'        => tr('Say nothing about it (?all)'),
    'TR_SPF_RAW'            => tr('SPF record'),
    'TR_SPF_RAW_HELP'       => tr('The complete record, beginning with v=spf1.'),

    'TR_DMARC_SECTION'      => tr('DMARC'),
    'TR_DMARC_INTRO'        => tr('DMARC tells receivers what to do with mail that fails both SPF and DKIM, and asks them to report back. Start at "take no action" and read the reports for a few weeks before tightening it: anything stronger will drop real mail you have forgotten about.'),
    'TR_DMARC_ENABLED'      => tr('Publish a DMARC record'),
    'TR_DMARC_P'            => tr('Mail that fails'),
    'TR_DMARC_P_NONE'       => tr('Take no action (p=none)'),
    'TR_DMARC_P_QUAR'       => tr('Treat as suspicious (p=quarantine)'),
    'TR_DMARC_P_REJECT'     => tr('Reject it (p=reject)'),
    'TR_DMARC_SP'           => tr('Mail from subdomains'),
    'TR_DMARC_SP_SAME'      => tr('Same as above'),
    'TR_DMARC_PCT'          => tr('Apply the policy to [%]'),
    'TR_DMARC_PCT_HELP'     => tr('Below 100, receivers apply the policy to that share of failing mail and treat the rest more leniently. Useful while tightening a policy.'),
    'TR_DMARC_RUA'          => tr('Send aggregate reports to'),
    'TR_DMARC_RUA_HELP'     => tr('Comma separated addresses. These daily summaries are the whole point of a p=none record: they tell you what sends as your domain before you start rejecting anything.'),
    'TR_DMARC_RUF'          => tr('Send failure reports to'),
    'TR_DMARC_RUF_HELP'     => tr('Comma separated addresses. Few receivers send these, and those that do may include message content.'),
    'TR_DMARC_ADKIM'        => tr('DKIM alignment'),
    'TR_DMARC_ASPF'         => tr('SPF alignment'),
    'TR_DMARC_RELAXED'      => tr('Relaxed'),
    'TR_DMARC_STRICT'       => tr('Strict'),
    'TR_DMARC_ALIGN_HELP'   => tr('Relaxed accepts a signature from the parent domain, which is what your subdomains use. Strict requires an exact match.'),
    'TR_DMARC_RI'           => tr('Reporting interval [seconds]'),

    'TR_RECORDS_SECTION'    => tr('DNS records'),
    'TR_RECORDS_INTRO'      => tr('What this domain\'s settings amount to. These are refreshed after each change is applied, so give the panel a moment after saving.'),
    'TR_NO_RECORDS'         => tr('Nothing is published for this domain yet.'),
    'TR_RECORD_KIND'        => tr('For'),
    'TR_RECORD_NAME'        => tr('Name'),
    'TR_RECORD_TYPE'        => tr('Type'),
    'TR_RECORD_VALUE'       => tr('Value'),
    'TR_RECORD_STATE'       => tr('In DNS'),
    'TR_CHECK'              => tr('Check what is published'),

    'TR_UPDATE'             => tr('Update'),
    'TR_CANCEL'             => tr('Cancel')
));

generateNavigation($tpl);
generatePage($tpl, $zone, $row, $check);
generatePageMessage($tpl);

$tpl->parse('LAYOUT_CONTENT', 'page');
EventAggregator::getInstance()->dispatch(Events::onClientScriptEnd, array('templateEngine' => $tpl));
$tpl->prnt();
