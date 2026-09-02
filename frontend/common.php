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

use iMSCP\Database\DatabaseMySQL;
use iMSCP\Registry;
use PDO;

/**
 * Every DNS zone a customer owns, with its email authentication row if any.
 *
 * A zone, not a vhost: email authentication attaches to the thing that has a
 * zone file, which is a domain or a domain alias. A subdomain has no zone of
 * its own and is covered by its parent's key and records.
 *
 * @param int $adminId Customer unique identifier
 * @return array
 */
function getZones($adminId)
{
    $stmt = exec_query(
        "
            SELECT z.*, p.postfix_auth_id, p.publish_dns, p.dkim_enabled,
                p.spf_mode, p.dmarc_enabled, p.dmarc_p, p.status, p.state
            FROM (
                SELECT 'dmn' AS domain_type, d.domain_id AS domain_id,
                    d.domain_id AS main_domain_id, d.domain_name AS domain_name,
                    d.domain_status AS domain_status
                FROM domain AS d
                WHERE d.domain_admin_id = ?

                UNION ALL

                SELECT 'als', a.alias_id, d.domain_id, a.alias_name, a.alias_status
                FROM domain_aliasses AS a
                JOIN domain AS d USING(domain_id)
                WHERE d.domain_admin_id = ?
            ) AS z
            LEFT JOIN postfix_auth AS p
                ON p.domain_type = z.domain_type AND p.domain_id = z.domain_id
            ORDER BY z.domain_name
        ",
        array($adminId, $adminId)
    );

    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

/**
 * One zone of a customer, with its email authentication row if any, or false.
 *
 * @param int $adminId Customer unique identifier
 * @param string $type One of dmn, als
 * @param int $id Zone unique identifier within its type
 * @return array|false
 */
function getZone($adminId, $type, $id)
{
    foreach (getZones($adminId) as $row) {
        if ($row['domain_type'] === $type && (int)$row['domain_id'] === (int)$id) {
            return $row;
        }
    }

    return false;
}

/**
 * A plugin configuration value.
 *
 * @param string $name
 * @param mixed $default
 * @return mixed
 */
function configParam($name, $default)
{
    static $plugin = NULL;

    if ($plugin === NULL) {
        $plugin = false;

        if (Registry::isRegistered('pluginManager')) {
            try {
                $plugin = Registry::get('pluginManager')->pluginGet('SGW_PostfixAuth');
            } catch (\Exception $e) {
                // Fall back to the defaults below.
            }
        }
    }

    return ($plugin === false) ? $default : $plugin->getConfigParam($name, $default);
}

/**
 * Settings for a zone that has never been configured.
 *
 * Everything is off. DKIM in particular is opt-in: a domain gets no key and
 * signs nothing until its owner asks for it.
 *
 * @return array
 */
function defaults()
{
    return array(
        'publish_dns'   => 1,
        'dkim_enabled'  => 0,
        'dkim_key_size' => (int)configParam('default_key_size', 2048),
        'spf_mode'      => 'off',
        'spf_a'         => 1,
        'spf_mx'        => 1,
        'spf_hosts'     => '',
        'spf_includes'  => '',
        'spf_redirect'  => '',
        'spf_qualifier' => '-all',
        'spf_raw'       => '',
        'dmarc_enabled' => 0,
        'dmarc_p'       => 'none',
        'dmarc_sp'      => '',
        'dmarc_pct'     => 100,
        'dmarc_rua'     => '',
        'dmarc_ruf'     => '',
        'dmarc_adkim'   => 'r',
        'dmarc_aspf'    => 'r',
        'dmarc_fo'      => '0',
        'dmarc_ri'      => 86400,
        'dkim_record'   => '',
        'spf_record'    => '',
        'dmarc_record'  => '',
        'status'        => 'disabled',
        'state'         => ''
    );
}

/**
 * The email authentication row for a zone, creating it from the defaults on
 * first use.
 *
 * @param array $zone Row as returned by getZones()
 * @param int $adminId Customer unique identifier
 * @return array
 */
function getOrCreateRow(array $zone, $adminId)
{
    if ($zone['postfix_auth_id'] !== null) {
        $stmt = exec_query(
            'SELECT * FROM postfix_auth WHERE postfix_auth_id = ?',
            array($zone['postfix_auth_id'])
        );

        return $stmt->fetchRow(PDO::FETCH_ASSOC);
    }

    $row = array_merge(defaults(), array(
        'admin_id'       => $adminId,
        'domain_type'    => $zone['domain_type'],
        'domain_id'      => $zone['domain_id'],
        'main_domain_id' => $zone['main_domain_id'],
        'domain_name'    => $zone['domain_name']
    ));

    exec_query(
        '
            INSERT INTO postfix_auth (
                admin_id, domain_type, domain_id, main_domain_id, domain_name,
                publish_dns, dkim_enabled, dkim_key_size, spf_mode, spf_a,
                spf_mx, spf_hosts, spf_includes, spf_redirect, spf_qualifier,
                spf_raw, dmarc_enabled, dmarc_p, dmarc_sp, dmarc_pct,
                dmarc_rua, dmarc_ruf, dmarc_adkim, dmarc_aspf, dmarc_fo,
                dmarc_ri, status, state
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?
            )
        ',
        array(
            $row['admin_id'], $row['domain_type'], $row['domain_id'],
            $row['main_domain_id'], $row['domain_name'], $row['publish_dns'],
            $row['dkim_enabled'], $row['dkim_key_size'], $row['spf_mode'],
            $row['spf_a'], $row['spf_mx'], $row['spf_hosts'],
            $row['spf_includes'], $row['spf_redirect'], $row['spf_qualifier'],
            $row['spf_raw'], $row['dmarc_enabled'], $row['dmarc_p'],
            $row['dmarc_sp'], $row['dmarc_pct'], $row['dmarc_rua'],
            $row['dmarc_ruf'], $row['dmarc_adkim'], $row['dmarc_aspf'],
            $row['dmarc_fo'], $row['dmarc_ri'], $row['status'], $row['state']
        )
    );

    $row['postfix_auth_id'] = DatabaseMySQL::getInstance()->insertId();

    return $row;
}

/**
 * The selector of a zone's active DKIM key, or '' if it has none yet.
 *
 * @param int $postfixAuthId
 * @return string
 */
function activeSelector($postfixAuthId)
{
    $stmt = exec_query(
        '
            SELECT selector FROM postfix_auth_key
            WHERE postfix_auth_id = ? AND retired_at = 0
            ORDER BY created_at DESC LIMIT 1
        ',
        array($postfixAuthId)
    );
    $row = $stmt->fetchRow(PDO::FETCH_ASSOC);

    return ($row === false) ? '' : $row['selector'];
}

/**
 * The records a zone should carry, as name/value pairs ready to display.
 *
 * The values are what the backend last composed, read back rather than
 * recomposed here: a preview that is assembled a second time in a second
 * language is a preview that can disagree with what was published.
 *
 * @param array $row Row from postfix_auth
 * @return array Array of array('kind', 'name', 'value')
 */
function zoneRecords(array $row)
{
    $zone = $row['domain_name'];
    $records = array();

    if (!empty($row['dkim_record'])) {
        $selector = activeSelector($row['postfix_auth_id']);
        $records[] = array(
            'kind'  => 'dkim',
            'name'  => ($selector === '' ? '' : $selector . '._domainkey.') . $zone . '.',
            'value' => $row['dkim_record']
        );
    }

    if (!empty($row['spf_record'])) {
        $records[] = array('kind' => 'spf', 'name' => $zone . '.', 'value' => $row['spf_record']);
    }

    if (!empty($row['dmarc_record'])) {
        $records[] = array(
            'kind'  => 'dmarc',
            'name'  => '_dmarc.' . $zone . '.',
            'value' => $row['dmarc_record']
        );
    }

    return $records;
}

/**
 * Does the zone have subdomains that send mail?
 *
 * They matter because a subdomain's mail is signed with its parent zone's key,
 * so the signature says d=<zone> while the From: header says user@sub.zone.
 * That is aligned under relaxed DMARC alignment and not under strict.
 *
 * @param array $zone Row as returned by getZones()
 * @return bool
 */
function hasMailSubdomains(array $zone)
{
    if ($zone['domain_type'] === 'als') {
        $stmt = exec_query(
            '
                SELECT COUNT(*) AS cnt
                FROM subdomain_alias AS s
                JOIN mail_users AS m ON m.sub_id = s.subdomain_alias_id
                WHERE s.alias_id = ? AND m.mail_type LIKE ?
            ',
            array($zone['domain_id'], 'alssub_%')
        );
    } else {
        $stmt = exec_query(
            '
                SELECT COUNT(*) AS cnt
                FROM subdomain AS s
                JOIN mail_users AS m ON m.sub_id = s.subdomain_id
                WHERE s.domain_id = ? AND m.mail_type LIKE ?
            ',
            array($zone['domain_id'], 'subdom_%')
        );
    }

    $row = $stmt->fetchRow(PDO::FETCH_ASSOC);

    return $row['cnt'] > 0;
}

/**
 * How many DNS lookups an SPF record costs.
 *
 * RFC 7208 s4.6.4 caps this at ten, and a record over the cap is a permerror:
 * it does not fail soft, it stops working. Counted here as well as in the
 * backend so that a customer is told at the moment they press save.
 *
 * @param string $record
 * @return int
 */
function spfLookupCount($record)
{
    $count = 0;

    foreach (preg_split('/\s+/', trim($record)) as $term) {
        if (preg_match('/^[+\-~?]?(include|a|mx|ptr|exists|redirect)([:=]|$)/i', $term)) {
            $count++;
        }
    }

    return $count;
}

/**
 * Is the record actually published in the DNS?
 *
 * The one check worth having: everything else this page shows is what the
 * server intends, and for a zone served by somebody else's nameservers that
 * intention and reality are unrelated until somebody copies the record across.
 *
 * @param string $name Record name, with or without its trailing dot
 * @param string $expected Expected record value
 * @return string One of 'ok', 'mismatch', 'missing'
 */
function checkPublished($name, $expected)
{
    $name = rtrim($name, '.');

    // A resolver failure and an absent record are indistinguishable here, and
    // both mean the same thing to the customer: it is not answering yet.
    $found = @dns_get_record($name, DNS_TXT);
    if (!is_array($found) || !$found) {
        return 'missing';
    }

    $wanted = normaliseRecord($expected);

    foreach ($found as $record) {
        // 'entries' holds the separate <character-string>s a long record was
        // split into; 'txt' is them joined. A 2048-bit DKIM key is always
        // split, so the joined form is the one to compare.
        $value = isset($record['txt']) ? $record['txt'] : '';

        if (isset($record['entries']) && is_array($record['entries'])) {
            $value = implode('', $record['entries']);
        }

        if (normaliseRecord($value) === $wanted) {
            return 'ok';
        }
    }

    return 'mismatch';
}

/**
 * Compare two TXT record values without tripping over whitespace or quoting.
 *
 * @param string $value
 * @return string
 */
function normaliseRecord($value)
{
    $value = str_replace('"', '', $value);
    $value = preg_replace('/\s+/', ' ', $value);

    return strtolower(trim($value));
}

/**
 * Map an item status onto one of the theme's status icons.
 *
 * @param string|null $status
 * @return string
 */
function statusIcon($status)
{
    if ($status === null || $status === 'disabled') {
        return 'disabled';
    }

    if ($status === 'ok') {
        return 'ok';
    }

    if (in_array($status, array('toadd', 'tochange', 'toenable', 'todisable', 'todelete'))) {
        return 'reload';
    }

    return 'error';
}

/**
 * Human readable item status.
 *
 * @param string|null $status
 * @return string
 */
function statusText($status)
{
    switch ($status) {
        case null:
        case 'disabled':
            return tr('Not configured');
        case 'ok':
            return tr('Configured');
        case 'toadd':
        case 'tochange':
        case 'toenable':
            return tr('Applying...');
        case 'todisable':
        case 'todelete':
            return tr('Removing...');
        default:
            return tr('Error');
    }
}

/**
 * Is the item settled, i.e. is the backend done with it?
 *
 * A busy item must not be edited, or the backend would act on half of one
 * change and half of the next.
 *
 * @param string|null $status
 * @return bool
 */
function isSettled($status)
{
    return $status === null || $status === 'ok' || $status === 'disabled'
        || statusIcon($status) === 'error';
}
