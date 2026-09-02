#!/bin/bash
# Does a full i-MSCP installer run leave the plugin's Postfix settings alone?
#
# The installer rewrites main.cf from i-MSCP's template, which knows nothing
# about any milter. Everything the plugin put there has to come back through
# the afterMtaBuildConf listener registered by registerSetupListeners.
#
# test/postfix-integration.sh drives that listener directly and runs in
# seconds. This does the real thing, which also proves that the installer
# actually calls registerSetupListeners on an enabled plugin, and that nothing
# later in the run undoes the result. It takes many minutes.
#
#   sudo /usr/local/src/imscp-postfix-auth/test/installer-survival.sh
#
# Run inside the Vagrant box, as root, with the plugin installed and enabled.

set -u

MILTER='inet:127.0.0.1:8891'
PRESEED=/usr/local/src/imscp/Vagrant/preseed.pl
LOG=/tmp/imscp-installer-survival.log

PASSED=0
FAILED=0

ok()  { PASSED=$((PASSED + 1)); printf '  ok    %s\n' "$1"; }
nok() { FAILED=$((FAILED + 1)); printf '  FAIL  %s\n' "$1"; }

[ "$(id -u)" -eq 0 ] || { echo "$0: must be run as root" >&2; exit 1; }
[ -f "$PRESEED" ] || { echo "$0: $PRESEED not found" >&2; exit 1; }

before_milters=$(postconf -h smtpd_milters)
before_keys=$(ls /etc/opendkim/keys 2>/dev/null | wc -l)
before_dns=$(mysql -N -B -e "
    SELECT COUNT(*) FROM imscp.domain_dns WHERE owned_by = 'SGW_PostfixAuth'")

echo "before: milters=[$before_milters] keys=$before_keys dns_rows=$before_dns"

case "$before_milters" in
    *"$MILTER"*) ;;
    *) echo "$0: the plugin's milter is not configured; install and enable first" >&2
       exit 1 ;;
esac

# The same preseed shape the Vagrant provisioner uses: the recorded
# BASE_SERVER_IP is replaced, because it is whatever the box happened to have
# when it was first built.
rm -f /tmp/preseed-survival.pl
head -n -2 "$PRESEED" > /tmp/preseed-survival.pl
cat >> /tmp/preseed-survival.pl <<'EOT'
$::questions{'BASE_SERVER_IP'} = '0.0.0.0';

1;
__END__
EOT

echo "running the installer, logging to $LOG ..."
start=$(date +%s)

if perl /usr/local/src/imscp/imscp-autoinstall --debug --verbose \
    --preseed /tmp/preseed-survival.pl > "$LOG" 2>&1
then
    ok "the installer completed ($(( $(date +%s) - start ))s)"
else
    nok "the installer failed ($(( $(date +%s) - start ))s); see $LOG"
    tail -20 "$LOG" | sed 's/^/        /'
fi

echo
echo '# What survived'

case "$(postconf -h smtpd_milters)" in
    *"$MILTER"*) ok 'smtpd_milters still names the plugin milter' ;;
    *) nok "smtpd_milters lost the plugin milter [$(postconf -h smtpd_milters)]" ;;
esac

case "$(postconf -h non_smtpd_milters)" in
    *"$MILTER"*) ok 'non_smtpd_milters still names the plugin milter' ;;
    *) nok "non_smtpd_milters lost the plugin milter [$(postconf -h non_smtpd_milters)]" ;;
esac

if [ "$(postconf -h milter_default_action)" = 'accept' ]; then
    ok 'milter_default_action is still accept'
else
    nok "milter_default_action reverted to $(postconf -h milter_default_action)"
fi

if [ "$(systemctl is-active opendkim)" = 'active' ]; then
    ok 'opendkim is still running'
else
    nok 'opendkim is not running'
fi

after_keys=$(ls /etc/opendkim/keys 2>/dev/null | wc -l)
if [ "$after_keys" = "$before_keys" ]; then
    ok "the DKIM keys are untouched ($after_keys)"
else
    nok "the DKIM key count changed: $before_keys -> $after_keys"
fi

after_dns=$(mysql -N -B -e "
    SELECT COUNT(*) FROM imscp.domain_dns WHERE owned_by = 'SGW_PostfixAuth'")
if [ "$after_dns" = "$before_dns" ]; then
    ok "the published DNS records are untouched ($after_dns)"
else
    nok "the DNS record count changed: $before_dns -> $after_dns"
fi

echo
printf '%d passed, %d failed\n' "$PASSED" "$FAILED"
[ "$FAILED" -eq 0 ]
