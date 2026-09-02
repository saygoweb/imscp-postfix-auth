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
    // Where Postfix reaches the signing milter.
    //
    // A TCP socket rather than a unix one, and not negotiable without also
    // changing master.cf: i-MSCP runs smtpd and cleanup chrooted, so a socket
    // under /run is outside the chroot and simply is not there.
    'milter_host' => '127.0.0.1',
    'milter_port' => 8891,

    // Directory holding opendkim.conf, the key tables and the key material.
    'opendkim_conf_dir' => '/etc/opendkim',

    // Default size of a newly generated DKIM key. 2048 is the floor every
    // large mailbox provider now expects; 1024 remains selectable per domain
    // for the rare validator that cannot read a 2048-bit record.
    'default_key_size' => 2048,

    // TTL written on the DNS records this plugin publishes.
    'dns_ttl' => 3600,

    // Customers may use email authentication unless a reseller says otherwise.
    'allowed_by_default' => true
);
