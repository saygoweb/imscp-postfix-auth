#!/bin/bash
# Does the Postfix configuration survive, and does it play nice?
#
# i-MSCP rebuilds main.cf from its template on every installer run, and
# third-party listeners then re-apply their own changes through
# afterMtaBuildConf. The plugin hangs off the same event, via the
# registerSetupListeners class method that i-MSCP calls on every enabled
# plugin during setup (engine/setup/imscp-setup-functions.pl).
#
# This drives that event directly rather than sitting through a full
# imscp-autoinstall run, which exercises the same listener by the same route.
# test/installer-survival.sh does the full run.
#
#   sudo /usr/local/src/imscp-postfix-auth/test/postfix-integration.sh
#
# Run inside the Vagrant box, as root, with the plugin installed and enabled.

set -u

PASSED=0
FAILED=0

ok()  { PASSED=$((PASSED + 1)); printf '  ok    %s\n' "$1"; }
nok() { FAILED=$((FAILED + 1)); printf '  FAIL  %s\n' "$1"; }

[ "$(id -u)" -eq 0 ] || { echo "$0: must be run as root" >&2; exit 1; }

PLUGIN=/var/www/imscp/gui/plugins/SGW_PostfixAuth/backend/SGW_PostfixAuth.pm
MILTER='inet:127.0.0.1:8891'
FOREIGN='inet:127.0.0.1:12345'

[ -f "$PLUGIN" ] || { echo "$0: $PLUGIN not found; deploy and install first" >&2; exit 1; }

# Run the plugin's setup listener the way the i-MSCP installer does: as a class
# method that registers on the event manager, followed by the event itself.
run_setup_listener() {
    perl -I/var/www/imscp/engine/PerlLib -I/var/www/imscp/engine/PerlVendor -e '
        use strict;
        use warnings;
        use iMSCP::Bootstrapper;
        use iMSCP::EventManager;

        iMSCP::Bootstrapper->getInstance()->boot( {
            norequirements => 1, nolock => 1, config_readonly => 1
        } );

        require "'"$PLUGIN"'";

        my $events = iMSCP::EventManager->getInstance();
        Plugin::SGW_PostfixAuth->registerSetupListeners( $events ) == 0
            or die "registerSetupListeners failed\n";
        $events->trigger( "afterMtaBuildConf" ) == 0
            or die "afterMtaBuildConf failed\n";
    ' 2>&1
}

restore=$(postconf -h smtpd_milters)

echo '# The setup listener'

# What an installer run leaves behind before the listeners get their turn:
# main.cf rebuilt from the template, with no milter in it at all.
postconf -X smtpd_milters non_smtpd_milters milter_default_action milter_protocol 2>/dev/null

output=$(run_setup_listener)

if [ -n "$output" ]; then
    nok 'the setup listener runs cleanly'
    echo "$output" | head -5 | sed 's/^/        /'
else
    ok 'the setup listener runs cleanly'
fi

case "$(postconf -h smtpd_milters)" in
    *"$MILTER"*) ok 'the milter is put back into smtpd_milters' ;;
    *)           nok 'the milter is NOT put back into smtpd_milters' ;;
esac

case "$(postconf -h non_smtpd_milters)" in
    *"$MILTER"*) ok 'the milter is put back into non_smtpd_milters' ;;
    *)           nok 'the milter is NOT put back into non_smtpd_milters' ;;
esac

# Postfix's own default is 'shutdown', which would turn a stopped milter into a
# refusal of every connection.
if [ "$(postconf -h milter_default_action)" = 'accept' ]; then
    ok 'milter_default_action is set to accept'
else
    nok "milter_default_action is $(postconf -h milter_default_action), not accept"
fi

echo
echo '# Coexistence with another listener'

# Stand in for a third-party listener that has put its own milter there at a
# higher priority: ours must join it rather than replace it.
postconf -e "smtpd_milters=$FOREIGN"
postconf -e "non_smtpd_milters=$FOREIGN"

run_setup_listener > /dev/null

value=$(postconf -h smtpd_milters)

case "$value" in
    *"$FOREIGN"*)
        case "$value" in
            *"$MILTER"*) ok "another listener's milter is kept alongside ours ($value)" ;;
            *)           nok "our milter was not added ($value)" ;;
        esac
        ;;
    *)
        nok "another listener's milter was clobbered ($value)"
        ;;
esac

# And running twice must not accumulate duplicates.
run_setup_listener > /dev/null
count=$(postconf -h smtpd_milters | tr ',' '\n' | grep -c "$MILTER")

if [ "$count" -eq 1 ]; then
    ok 'a second pass does not add the milter twice'
else
    nok "a second pass left $count copies of the milter"
fi

# Put the box back the way it was found.
postconf -e "smtpd_milters=$restore"
postconf -e "non_smtpd_milters=$restore"
systemctl reload postfix

echo
printf '%d passed, %d failed\n' "$PASSED" "$FAILED"
[ "$FAILED" -eq 0 ]
