# SGW_PostfixAuth — development plan

An i-MSCP plugin that gives customers control of the three email
authentication mechanisms i-MSCP either lacks entirely or hard-codes: **DKIM**,
**SPF** and **DMARC**.

Status: **delivered**. Every phase below is implemented and verified on the
Debian 13 box. This file is kept as the record of what was decided and why;
[README.md](README.md) documents the plugin as built, and
[CHANGELOG.md](CHANGELOG.md) what it does. The plan is excluded from the
release archive.

---

## 1. What i-MSCP does today

Verified against `imscp` @ `migrate/2026-09`, running on the Debian 13 Vagrant
box (Postfix 3.10.13, Courier, BIND 9, plugin API 1.5.1).

| Mechanism | Present? | Where |
| --- | --- | --- |
| SPF | Hard-coded, not customisable | `configs/debian/trixie/bind/parts/db.tpl:21` — `@ IN TXT "v=spf1 a mx -all"`, and `db_sub.tpl:5` for subdomains |
| DKIM | Absent | no key material, no milter, `smtpd_milters` and `non_smtpd_milters` are empty |
| DMARC | Absent | nothing publishes `_dmarc` |

Two facts make this tractable rather than invasive:

**The zone builder already yields to custom records.** `bind.pm:551-560` drops a
default RR when a custom RR has the same name/class/type, and for `TXT` it
additionally requires the RDATA of both to look like the same kind of record —
it explicitly recognises `"v=spf1`, `"v=DKIM1;` and `"dkim=`. So a custom
`v=spf1` TXT record at the zone apex **replaces** the hard-coded one. No core
patch is needed to customise SPF.

**Long TXT records are already handled.** `Modules::CustomDNS::_normalizeRRs`
normalises TXT/SPF RDATA and splits any `<character-string>` longer than 255
bytes. A 2048-bit DKIM public key therefore publishes correctly through the
existing path.

Together these mean the plugin can publish every record it needs as rows in
`domain_dns` with `owned_by = 'SGW_PostfixAuth'`, and i-MSCP's own machinery
does the rest. Records owned by a plugin already render read-only in the
customer's DNS list (`gui/public/client/domains_manage.php:560`), so a customer
sees them but cannot break them.

Ordering works in our favour too: `DbTasksProcessor` runs `Modules::Plugin`
(line 65) *before* `Modules::CustomDNS` (line 193), so records the plugin
queues as `toadd` are published in the **same** backend pass.

---

## 2. Playing nice with Postfix listeners

This is the constraint that shapes the backend, and it has a clean answer.

**The problem.** i-MSCP regenerates `main.cf` and `master.cf` from templates on
every installer run, then lets listeners re-apply their changes through
`afterMtaBuildConf`. A plugin's `postconf` calls made at install time are wiped
by the next `imscp-autoinstall` pass. Meanwhile third-party listeners such as
`migrate/listeners/10_saygoweb_postfix.pl` register at priority `-99` and
`replace` whole parameters — so we must neither be overwritten by them nor
overwrite them.

**The answer.** `engine/setup/imscp-setup-functions.pl:459-470` loads every
*enabled* plugin's backend class during setup and calls its
`registerSetupListeners( $class, $events )` class method if it has one. That is
the plugin-native hook, and it means **no file needs to be dropped into
`/etc/imscp/listeners.d/`**. The backend module will implement it and register
an `afterMtaBuildConf` listener at priority **-1000**.

The event manager pops highest priority first, so -1000 runs *after* the
`-99` listeners — our settings land last and win. And within that listener:

* `smtpd_milters` / `non_smtpd_milters` use `action => 'add'`, which appends
  our milter to whatever another listener set rather than replacing it
  (verified in `postfix.pm::postconf`: `add` on an empty parameter is a plain
  push, and a value already present is not duplicated).
* Everything else we set (`milter_protocol`, `milter_default_action`) uses
  `replace`, because those are ours to own.

The same settings are applied directly by the plugin's `install`/`enable`/
`change` actions so they take effect immediately, without waiting for an
installer run.

**Two Postfix details that would otherwise cause an outage:**

1. `smtpd` and `cleanup` run **chrooted** (`chroot = y` in i-MSCP's
   `master.cf`), so a unix-domain milter socket under `/run` is unreachable.
   The milter is therefore reached over **`inet:127.0.0.1:8891`**.
2. Postfix 3.10's built-in `milter_default_action` is **`shutdown`** (confirmed
   with `postconf -d` on the box; i-MSCP sets nothing). If opendkim is stopped
   or crashes, every connection is dropped — a total mail outage caused by an
   optional feature. The plugin sets `milter_default_action = accept`, and
   removes the milter from `smtpd_milters` again whenever it is disabled or
   uninstalled.

---

## 3. Design

### 3.1 Naming

Plugin `SGW_PostfixAuth`, class `iMSCP\Plugin\SGW_PostfixAuth\SGW_PostfixAuth`,
backend `Plugin::SGW_PostfixAuth`, tables `postfix_auth*`, repository
`imscp-postfix-auth`. Menu label **Email authentication**.

The name is deliberately the Postfix one even though every user-facing string
says "email authentication" (SPF/DKIM/DMARC), which is a different thing from
SMTP AUTH. Settled, and not to be revisited after the first release: the name
is baked into the class, the tables and the deployed path.

### 3.2 DKIM

**Signer: OpenDKIM** (`opendkim` 2.11.0~beta2 and `opendkim-tools`, both in
Trixie). Chosen over rspamd because it does one job, is what the existing
i-MSCP OpenDKIM plugin used so operators recognise it, and does not want to own
the whole mail policy stack. rspamd stays a plausible v2 alternative.

**One key per DNS zone**, i.e. per domain and per domain alias, signing with
`d=<zone>`. Mail from a mail-enabled subdomain is signed with the parent zone's
key. That is DMARC-aligned under **relaxed** alignment (`adkim=r`, the DMARC
default), which is why the UI will warn before letting a customer set
`adkim=s` on a zone that has mail-enabled subdomains. The alternative — a key
and a record per subdomain — buys strict alignment at the cost of a much larger
key inventory, and is deferred.

* Key pair generated in the **backend** (`openssl genrsa`), 2048-bit by
  default, 1024 offered for the rare validator that still chokes on 2048.
* Private and public halves stored in the plugin's DB table (i-MSCP already
  keeps TLS private keys in `ssl_certs`, so this is consistent), and the
  backend is the only writer of `/etc/opendkim/keys/<zone>/<selector>.private`
  (mode 0600, owned by `opendkim`).
* `KeyTable` and `SigningTable` regenerated in full from the DB on every
  backend pass, then `opendkim` reloaded. Full regeneration rather than
  incremental edits, so the files can never drift.
* Signing table entries: `*@<zone>` and `*@*.<zone>` → the zone's key.
* Selector default `<yyyymm>` (e.g. `202609`), editable. A date-shaped default
  makes rotation obvious later.
* Published record: `<selector>._domainkey.<zone> IN TXT "v=DKIM1; h=sha256;
  k=rsa; p=..."`.

**Signing only what we should.** The one genuine risk is signing a forged
sender that arrived on port 25 from the internet — that would put our
signature on spam. OpenDKIM signs only for internal/authenticated clients, but
"authenticated" depends on Postfix exporting the `{auth_authen}` macro to the
milter. This is a **verification item, not an assumption**: the test matrix
below asserts both directions explicitly.

**Rotation** is designed for but not implemented in v1: the schema puts keys in
their own table so a zone can carry a retiring selector whose DNS record stays
published for a grace period. v1 ships "regenerate key", which is a rotation
without the grace period.

### 3.3 SPF

Per zone, three modes:

* **Off** — i-MSCP's hard-coded `v=spf1 a mx -all` stands.
* **Guided** — checkboxes and fields for `a`, `mx`, `ip4:`, `ip6:`,
  `include:`, `redirect=`, plus the policy qualifier (`-all` fail /
  `~all` softfail / `?all` neutral). The plugin composes the record.
* **Raw** — the customer types the record; validated for the `v=spf1` prefix,
  the 10-lookup limit (counting `include`/`a`/`mx`/`ptr`/`exists`/`redirect`),
  and length.

The composed record is written as an apex TXT row in `domain_dns`, which
suppresses the default. Subdomain SPF follows the same path (the plugin writes
`sub.zone.` as the record name; the default in `db_sub.tpl` is suppressed by
the same `bind.pm` rule).

### 3.4 DMARC

Per zone, a `_dmarc.<zone>` TXT record built from: `p` (none/quarantine/
reject), `sp`, `pct`, `rua`, `ruf`, `adkim`, `aspf`, `fo`, `ri`. Defaults to
`p=none; rua=mailto:<customer's own address>` — the only responsible starting
point, since anything stronger silently drops mail while the customer is still
finding out what sends as their domain.

The UI will refuse `p=quarantine`/`p=reject` unless DKIM is enabled *and* the
DKIM record verifies as published (see 3.5), with an override for the customer
who knows what they are doing.

Inbound DMARC/SPF **enforcement** (opendmarc, policyd-spf) is out of scope.
It is a server-wide policy decision rather than a per-customer one, and it
changes what mail the server accepts. Publishing the records is the whole job
for v1; nothing in the design forecloses adding enforcement later.

DMARC policy is set **per zone by the customer**. There is no reseller- or
admin-level default that new domains inherit — a policy inherited silently is
a policy nobody knows is in force, and the failure mode is dropped mail.

### 3.5 Externally hosted DNS

Not every domain's DNS is served by this box. Every zone therefore gets a
`publish_dns` flag:

* **on** — records are written to `domain_dns` and BIND serves them.
* **off** — nothing is written; the UI shows the exact record text for
  copy-paste.

Either way the edit page offers **Check published**, which resolves the record
over DNS and compares it to what the plugin expects. For DKIM in particular
this is the difference between "configured" and "actually working", and it is
worth having in v1.

### 3.6 Schema

```
postfix_auth              one row per DNS zone (domain or alias)
  postfix_auth_id, admin_id, domain_type enum('dmn','als'), domain_id,
  domain_name, publish_dns,
  dkim_enabled, dkim_key_size,
  spf_mode enum('off','guided','raw'), spf_flags, spf_hosts, spf_includes,
  spf_redirect, spf_qualifier, spf_raw,
  dmarc_enabled, dmarc_p, dmarc_sp, dmarc_pct, dmarc_rua, dmarc_ruf,
  dmarc_adkim, dmarc_aspf, dmarc_fo, dmarc_ri,
  status, state
  UNIQUE (domain_type, domain_id)

postfix_auth_key          DKIM keys; several per zone once rotation lands
  postfix_auth_key_id, postfix_auth_id, selector, key_size,
  private_key, public_key, created_at, retired_at, status

postfix_auth_perm         admin_id, allowed      -- reseller grant/withdraw
```

Status vocabulary follows the reference plugins exactly: `toadd`, `tochange`,
`toenable`, `todisable`, `todelete` pending; `ok`, `disabled` settled; anything
else is the error message, which is what `getItemWithErrorStatus()` reports.

### 3.7 Backend behaviour

| Action | What it does |
| --- | --- |
| `install` | Check requirements; install `opendkim`/`opendkim-tools` via `beforeInstallPackages`; create `/etc/opendkim`, key root, `opendkim.conf`; apply the postconf settings; enable and start opendkim |
| `enable` | Restore rows disabled by `disable`, apply postconf, process them in the same pass |
| `disable` | Remove the milter from Postfix, remove the plugin's `domain_dns` rows, stop opendkim; every row remembers whether it was enabled |
| `uninstall` | As `disable`, plus delete key material and `opendkim.conf`, remove the package settings |
| `run` | Process pending rows: write/refresh key files, regenerate `KeyTable`/`SigningTable`, sync `domain_dns` rows, reload opendkim and BIND |
| `registerSetupListeners` | Register the `afterMtaBuildConf` listener at -1000 (§2) |

Never leave Postfix pointing at a milter that is not running: the milter
parameter is added only after opendkim is confirmed up, and removed before it
is stopped.

### 3.8 Frontend

Modelled directly on `SGW_ApacheCache`:

* `frontend/common.php` — the union query over `domain` + `domain_aliasses`,
  the defaults, `getOrCreateRow`, and the status→icon/text/settled helpers.
* `client/postfix_auth.php` — one row per zone: DKIM / SPF / DMARC state,
  status icon, edit link.
* `client/postfix_auth_edit.php` — three panels (DKIM, SPF, DMARC), the
  generated record text for each, "Check published", and per-mechanism enable.
* `reseller/postfix_auth.php` — grant/withdraw per customer, and enable across
  all of a customer's zones at once.
* Navigation injected under *Email* for the client (falling back to *Domains*
  if the Email page is not present), and under *Customers* for the reseller.

`config.php` carries the server-wide knobs: milter socket, default key size,
default selector format, whether the feature is allowed by default, and the
phase-5 inbound toggles.

---

## 4. Phasing

| Phase | Deliverable | Verified by |
| --- | --- | --- |
| **0** | Vagrant environment | done — see §5 |
| **1** | Scaffolding: `info.php`, `config.php`, plugin class, `sql/`, `makefile.json`, `tools/deploy.sh`, `README`, `CHANGELOG`, `l10n/en_GB.php` | plugin installs, enables, disables, uninstalls cleanly from the panel |
| **2** | Backend: opendkim install, `opendkim.conf`, postconf integration, `registerSetupListeners` | `postconf -n \| grep milter` correct; a full `imscp-autoinstall` run does **not** lose it; the `10_saygoweb_postfix.pl` listener and ours coexist |
| **3** | DKIM: keys, tables, DNS publication, client UI | signed message verifies; forged port-25 sender is **not** signed |
| **4** | SPF and DMARC editors, publication, "Check published" | records resolve; the hard-coded default is gone from the zone |
| **5** | Reseller page and permissions | withdrawing the feature disables it on that customer's zones |
| **6** | Tests, docs, packaging | below |

Phases 3 and 4 are independent and can land in either order. Inbound
enforcement is not in v1 at all (§3.4).

## 5. Vagrant environment — done

The `imscp_debian_trixie` box was already up and provisioned. Two things were
needed and both are in place:

* `imscp/Vagrant/Vagrantfile` — `imscp-postfix-auth` added to the sibling
  plugin working copies mounted over virtiofs (the list previously held
  `imscp-apache-cache`, `imscp-letsencrypt`, `imscp-php-version`). *This edit
  is uncommitted in the `imscp` repo, alongside the pre-existing uncommitted
  change that introduced the list.*
* The box was reloaded, so `/usr/local/src/imscp-postfix-auth` is now mounted.

Confirmed on the box: Debian 13.6, Postfix 3.10.13, Courier, BIND 9, MariaDB,
`imscp_panel` and Apache all active; i-MSCP `Git 1.5.x`, plugin API `1.5.1`;
one test domain `wpcache.test` with 10 mail accounts; `opendkim`,
`opendkim-tools` and `opendmarc` all available from `trixie/main`.

Still to come with phase 1, following `SGW_ApacheCache`: `tools/deploy.sh`,
which rsyncs the working copy into `/var/www/imscp/gui/plugins/SGW_PostfixAuth`
as `vu2000` and restarts `imscp_panel` (virtiofs carries the host uid, so the
tree is copied rather than mounted into place).

## 6. Testing

**Unit (`test/backend/`, `perl all.t` as root).** The generators are the part
worth unit testing, exactly as in `SGW_ApacheCache`: SPF composition from the
guided fields, SPF validation including the 10-lookup limit, DMARC record
composition, the DKIM TXT record from a fixed public key, and
`KeyTable`/`SigningTable` generation. No live services needed.

**Integration (`test/`, shell, against the box).**

1. Enable DKIM on `wpcache.test`; assert the key file, the tables, the
   `domain_dns` row and the record in the served zone.
2. Submit a message on 587 with SASL AUTH → assert a `DKIM-Signature` header
   with `d=wpcache.test`, and that it verifies against the published key.
3. **Forged sender on port 25 from a non-internal address → assert the message
   is *not* signed.** The one test that must never be skipped.
4. Mail from a mail-enabled subdomain → signed with `d=wpcache.test`, relaxed
   alignment holds.
5. Custom SPF → the hard-coded `v=spf1 a mx -all` is gone from the zone and
   ours is served.
6. DMARC record resolves at `_dmarc.wpcache.test`.
7. Stop opendkim → mail still flows (`milter_default_action = accept`).
8. Run `imscp-autoinstall` → milter settings survive; with
   `10_saygoweb_postfix.pl` also installed, both its settings and ours survive.
9. Disable, re-enable, uninstall: files, records and postconf settings appear
   and disappear together, and previously-enabled zones come back on re-enable.

## 7. Decisions

Settled 2026-09-02, and reflected throughout the plan above.

1. **Plugin name** — `SGW_PostfixAuth`. (§3.1)
2. **DKIM for new domains** — **opt-in**. A domain gets no key and no signed
   mail until its owner asks for it. The reseller page's "enable across all of
   this customer's zones" button is the bulk path for an operator who wants
   everything signed. (§3.2)
3. **DMARC policy** — per zone, set by the customer. No reseller or admin
   default that new domains inherit. (§3.4)
4. **Inbound enforcement** — not in v1. Publishing the records is the whole
   job. (§3.4)
