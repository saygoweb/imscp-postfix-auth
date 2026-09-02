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

return array(
    // A row per DNS zone, which is what an email authentication policy
    // attaches to: a domain or a domain alias. Subdomains have no zone of
    // their own and are covered by their parent's key and records.
    //
    // utf8mb4 throughout, matching i-MSCP's own tables, so that comparing a
    // domain name against `domain` or `domain_aliasses` never mixes
    // collations.
    'up'   => "
        CREATE TABLE IF NOT EXISTS `postfix_auth` (
            `postfix_auth_id` int(11) unsigned NOT NULL AUTO_INCREMENT,
            `admin_id`        int(11) unsigned NOT NULL,
            `domain_type`     enum('dmn','als') COLLATE utf8mb4_unicode_ci NOT NULL,
            `domain_id`       int(11) unsigned NOT NULL,
            -- domain.domain_id of the zone's owner. For an alias this is the
            -- parent domain, which is what a domain_dns row has to be keyed by.
            `main_domain_id`  int(11) unsigned NOT NULL,
            `domain_name`     varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
            -- Off when the zone is served by somebody else's nameservers; the
            -- panel then shows the records to publish by hand.
            `publish_dns`     tinyint(1) NOT NULL DEFAULT '1',

            `dkim_enabled`    tinyint(1) NOT NULL DEFAULT '0',
            `dkim_key_size`   int(11) unsigned NOT NULL DEFAULT '2048',

            `spf_mode`        enum('off','guided','raw') COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'off',
            `spf_a`           tinyint(1) NOT NULL DEFAULT '1',
            `spf_mx`          tinyint(1) NOT NULL DEFAULT '1',
            `spf_hosts`       text COLLATE utf8mb4_unicode_ci,
            `spf_includes`    text COLLATE utf8mb4_unicode_ci,
            `spf_redirect`    varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
            `spf_qualifier`   enum('-all','~all','?all') COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '-all',
            `spf_raw`         text COLLATE utf8mb4_unicode_ci,

            `dmarc_enabled`   tinyint(1) NOT NULL DEFAULT '0',
            `dmarc_p`         enum('none','quarantine','reject') COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'none',
            `dmarc_sp`        enum('','none','quarantine','reject') COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
            `dmarc_pct`       int(11) unsigned NOT NULL DEFAULT '100',
            `dmarc_rua`       varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
            `dmarc_ruf`       varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
            `dmarc_adkim`     enum('r','s') COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'r',
            `dmarc_aspf`      enum('r','s') COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'r',
            `dmarc_fo`        varchar(16) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '0',
            `dmarc_ri`        int(11) unsigned NOT NULL DEFAULT '86400',

            -- What the backend last composed for this zone, whether or not it
            -- was published. The panel displays these rather than composing
            -- the records a second time in PHP, so what a customer is told to
            -- publish by hand is exactly what the backend would have written.
            `dkim_record`     text COLLATE utf8mb4_unicode_ci,
            `spf_record`      text COLLATE utf8mb4_unicode_ci,
            `dmarc_record`    text COLLATE utf8mb4_unicode_ci,

            `status`          varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
            `state`           varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
            PRIMARY KEY (`postfix_auth_id`),
            UNIQUE KEY `postfix_auth_zone` (`domain_type`, `domain_id`),
            KEY `postfix_auth_admin_id` (`admin_id`),
            KEY `postfix_auth_status` (`status`(15))
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

        -- DKIM keys. A zone has exactly one active key (retired_at = 0); the
        -- table carries several per zone so that a future rotation can keep a
        -- retiring selector's record published while mail signed with it is
        -- still in flight.
        CREATE TABLE IF NOT EXISTS `postfix_auth_key` (
            `postfix_auth_key_id` int(11) unsigned NOT NULL AUTO_INCREMENT,
            `postfix_auth_id`     int(11) unsigned NOT NULL,
            `selector`            varchar(63) COLLATE utf8mb4_unicode_ci NOT NULL,
            `key_size`            int(11) unsigned NOT NULL DEFAULT '2048',
            `private_key`         text COLLATE utf8mb4_unicode_ci NOT NULL,
            `public_key`          text COLLATE utf8mb4_unicode_ci NOT NULL,
            `created_at`          int(11) unsigned NOT NULL DEFAULT '0',
            `retired_at`          int(11) unsigned NOT NULL DEFAULT '0',
            PRIMARY KEY (`postfix_auth_key_id`),
            UNIQUE KEY `postfix_auth_key_selector` (`postfix_auth_id`, `selector`),
            KEY `postfix_auth_key_zone` (`postfix_auth_id`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

        CREATE TABLE IF NOT EXISTS `postfix_auth_perm` (
            `admin_id` int(11) unsigned NOT NULL,
            `allowed`  tinyint(1) NOT NULL DEFAULT '1',
            PRIMARY KEY (`admin_id`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    ",
    'down' => "
        DROP TABLE IF EXISTS `postfix_auth_perm`;
        DROP TABLE IF EXISTS `postfix_auth_key`;
        DROP TABLE IF EXISTS `postfix_auth`;
    "
);
