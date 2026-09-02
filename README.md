# i-MSCP Email Authentication Plugin

Gives every domain and domain alias a DKIM signing key, a customisable SPF
record and a DMARC record — the three things that let a receiver tell a
customer's mail apart from mail that merely claims to be theirs.

i-MSCP has no DKIM support at all, and publishes a single hard-coded SPF
record (`v=spf1 a mx -all`) that no customer can change. This plugin adds the
first and makes the second editable, without patching i-MSCP.

See [CHANGELOG](CHANGELOG.md) for what has changed in each version.

## Requirements

* i-MSCP 1.5.x (plugin API 1.5.1)
* Postfix and BIND as the MTA and nameserver
* Debian 13 (Trixie). Developed and tested against Postfix 3.10.13 and
  OpenDKIM 2.11.0.

The plugin installs `opendkim` and `opendkim-tools` itself, and keeps them
through later i-MSCP installer runs.

## Installation

1. Upload `SGW_PostfixAuth.tgz` through the plugin management interface
2. Install the plugin through the plugin management interface

Installing writes `/etc/opendkim.conf`, starts OpenDKIM, and points Postfix at
it. Nothing is signed until a customer turns DKIM on for a domain: signing is
opt-in, per domain.

## What a customer sees

Under **Mail / Email authentication**, one row per domain and alias, and an
edit page carrying:

| Setting | Meaning |
| --- | --- |
| DNS published by this server | Off for a domain whose nameservers are somebody else's; the records are then shown for the customer to publish by hand |
| DKIM | Sign this domain's outgoing mail, with a 1024, 2048 or 4096 bit key, and a button to replace the key |
| SPF | Keep the server default, build a record from mechanisms and includes, or write one by hand |
| DMARC | Policy, subdomain policy, alignment, sampling percentage, and the addresses reports are sent to |

Below the form, the three records as they will be published, and a **Check
what is published** button that resolves each one and says whether it is
actually there.

A reseller gets **Customers / Email authentication**, which grants or
withdraws the feature per customer and switches DKIM signing on or off across
all of a customer's domains at once. SPF and DMARC deliberately stay with the
customer: those records tell the world what to do with their mail.

## Why the configuration looks the way it does

Six things drive the design, and each was measured on a live box rather than
assumed.

**Postfix reaches the milter over TCP, not a unix socket.** i-MSCP runs
`smtpd` and `cleanup` chrooted (`chroot = y` throughout its `master.cf`), so a
socket under `/run` is outside the chroot and simply is not there. The milter
listens on `inet:127.0.0.1:8891`.

**`milter_default_action` is forced to `accept`.** Postfix's own default is
`shutdown` — confirmed with `postconf -d` — which turns a stopped milter into a
refusal of every connection. Nothing an email authentication plugin offers is
worth a total mail outage when OpenDKIM crashes, so a milter that cannot be
reached is passed by instead.

**Only authenticated and local mail is signed.** The obvious mistake here is
to sign anything whose `From:` header names a domain in the signing table,
which would put the server's signature on a forged message sent from anywhere
on the internet. OpenDKIM's `InternalHosts` covers mail generated on the box,
and `MacroList {auth_authen}` covers mail from a remote client that has
authenticated. `test/dkim-matrix.sh` asserts both directions, and the negative
case — a forged sender arriving on port 25 from a non-local address must not be
signed — is the test that must never be allowed to regress.

**One key per zone, with relaxed DMARC alignment.** A subdomain has no zone of
its own, so mail from `user@blog.example.com` is signed with `example.com`'s
key and carries `d=example.com`. That is aligned under **relaxed** alignment,
which is DMARC's default. The panel warns before letting a customer select
strict DKIM alignment on a domain whose subdomains send mail.

**The records go through i-MSCP's own custom DNS machinery.** Every record is
a row in `domain_dns` owned by `SGW_PostfixAuth`, which buys three things for
free: `bind.pm` already drops its hard-coded `v=spf1` record when a custom TXT
record at the same name is also an SPF record, so customising SPF needs no core
patch; `Modules::CustomDNS` already splits a TXT string over 255 bytes, which
is what a 2048-bit DKIM key needs; and i-MSCP already renders a plugin-owned
record read-only in the customer's DNS list, so they can see it but cannot
break it.

**The Postfix settings are applied by two routes, and both are needed.**
Installing or enabling the plugin applies them directly, so the feature works
without waiting for an installer run. An i-MSCP installer run rebuilds
`main.cf` from a template that knows nothing about milters, so they are applied
again from an `afterMtaBuildConf` listener registered through the plugin API's
`registerSetupListeners`. That listener sits at priority **-1000**, below the
-99 that third-party listeners conventionally use, so it runs last and its
settings survive; and it *adds* to `smtpd_milters` rather than replacing it, so
a listener that has put its own milter there keeps it.

## Publishing DNS elsewhere

Turn **DNS published by this server** off, and the plugin stops writing to
`domain_dns` but still composes and displays every record. Copy them into
whatever hosts the zone, then use **Check what is published**.

That check resolves through the server's own resolver, which is what the rest
of the internet sees rather than what this box intends. A record published
here a moment ago may show as not published until it has propagated.

## Development

The `tools/` and `test/` directories are development-only and are excluded
from the release archive.

```shell
# In the i-MSCP repository, bring up the Debian 13 box:
cd imscp/Vagrant && vagrant up imscp_debian_trixie --provider=libvirt

# Inside the box: deploy the working tree, then install it
sudo /usr/local/src/imscp-postfix-auth/tools/deploy.sh
sudo -u vu2000 php /usr/local/src/imscp-postfix-auth/tools/plugin-ctl.php sync
sudo -u vu2000 php /usr/local/src/imscp-postfix-auth/tools/plugin-ctl.php install
sudo perl /var/www/imscp/engine/imscp-rqst-mngr
```

`deploy.sh` copies the working tree into the panel's plugins directory rather
than mounting it there, because the virtiofs share carries the host's uid and
the panel runs as `vu2000`. It restarts `imscp_panel` afterwards, since that
pool's opcache would otherwise keep serving the previous version of a file.

`plugin-ctl.php` drives the panel's own `PluginManager` from the shell, so a
deploy/install cycle does not need a trip through the web interface. It runs
from the working copy rather than the deployed plugin, because the plugins
directory is scanned for plugins and a `tools` directory sitting in it would be
taken for one.

Tests:

```shell
# The record generators. No live services needed, but must run as root: the
# module pulls in iMSCP::* from the engine, whose directory is not world
# readable.
cd test/backend && sudo perl all.t

# Against the live services, inside the box
sudo test/postfix-integration.sh   # the setup listener, and coexistence
sudo test/dns-sync.sh              # the declarative DNS sync, and its sharp edges
sudo test/dkim-matrix.sh           # what gets signed, and what a resolver sees
sudo test/pages.sh                 # every page the plugin adds actually renders
sudo test/installer-survival.sh    # a full installer run; takes many minutes
```

`dns-sync.sh` and `dkim-matrix.sh` both need a domain with DKIM, SPF and DMARC
turned on. `dns-sync.sh` walks that zone's records through withdrawal,
resurrection and a change of owner, and puts the zone back as it found it;
`dkim-matrix.sh` creates one fixture mailbox and leaves it. `pages.sh` sets the customer and reseller
panel passwords to a known value for the duration of the run and restores them
afterwards.

## Packaging

```shell
make.phar package    # produces SGW_PostfixAuth.tgz
```

Only `tar.gz`, `tar.bz2`, `tar.xz` and `zip` archives are accepted by the
plugin uploader. Do not upload a Git source archive.

## How to Help

Report issues in the
[GitHub issue tracker](https://github.com/saygoweb/imscp-postfix-auth/issues),
with as much detail as you can. Pull requests are welcome.

## License

```
i-MSCP SGW_PostfixAuth plugin
Copyright (C) 2026 Cambell Prince <cambell.prince@gmail.com>

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; version 2 of the License

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
```

## Authors

* Cambell Prince <cambell.prince@gmail.com>
