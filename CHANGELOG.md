# Changelog

## 0.1.0 (unreleased)

First working version.

* Per-domain DKIM signing with OpenDKIM, opt-in, with a 1024/2048/4096 bit key
  and a one-click key replacement. One key per DNS zone; mail from a
  subdomain is signed with its parent's key, which is aligned for DMARC under
  relaxed alignment.
* Only authenticated and locally generated mail is signed. A forged sender
  arriving on port 25 from a non-local address is not, which
  `test/dkim-matrix.sh` asserts explicitly.
* Customisable SPF, replacing i-MSCP's hard-coded `v=spf1 a mx -all`: either
  built from mechanisms, addresses and includes, or written by hand. The
  10-lookup limit is enforced in both the panel and the backend, because a
  record over it is a permerror rather than a partially applied policy.
* DMARC records with policy, subdomain policy, alignment, sampling and report
  addresses. Refuses a policy stronger than `p=none` while DKIM is off.
* Records are published as `domain_dns` rows owned by the plugin, so BIND
  serves them, long DKIM keys are split correctly, and a customer sees them in
  their DNS list read-only. Zones whose DNS is hosted elsewhere get the record
  text to publish by hand, and a check that resolves each one.
* Postfix integration that neither loses to nor clobbers a third-party
  listener: the milter is added to `smtpd_milters` rather than replacing it,
  from an `afterMtaBuildConf` listener at priority -1000 registered through
  `registerSetupListeners`, so it survives a full i-MSCP installer run.
* `milter_default_action` is set to `accept`, so a stopped OpenDKIM degrades
  the feature instead of stopping all mail. Postfix's own default is
  `shutdown`.
* Reseller page to grant or withdraw the feature per customer, and to switch
  signing on or off across all of a customer's domains at once.
* Clean install, disable, re-enable and uninstall cycles: disabling withdraws
  every key file and record but remembers each zone's settings and keeps its
  key, so re-enabling republishes the same public key rather than a new one.
