#!/bin/bash
# The declarative DNS sync, and the edges where it used to go wrong.
#
# The plugin does not track which domain_dns rows it created. Each pass works
# out what the zone's settings call for, reads back what is there, and queues
# the difference. That is what makes a half-applied change heal itself, and it
# is also where the sharp edges are, because the unique key on domain_dns
# covers a record's content but not its owner.
#
#   sudo /usr/local/src/imscp-postfix-auth/test/dns-sync.sh [domain]
#
# Run inside the Vagrant box, as root, with the plugin installed and enabled
# and a configured zone for the domain.

set -u

DOMAIN="${1:-wpcache.test}"

PASSED=0
FAILED=0

ok()  { PASSED=$((PASSED + 1)); printf '  ok    %s\n' "$1"; }
nok() { FAILED=$((FAILED + 1)); printf '  FAIL  %s\n' "$1"; }

[ "$(id -u)" -eq 0 ] || { echo "$0: must be run as root" >&2; exit 1; }

q() { mysql -N -B -e "$1"; }

ZONE_ID=$(q "SELECT postfix_auth_id FROM imscp.postfix_auth WHERE domain_name = '$DOMAIN'")
[ -n "$ZONE_ID" ] || { echo "$0: no configured zone for $DOMAIN" >&2; exit 1; }

DOMAIN_ID=$(q "SELECT main_domain_id FROM imscp.postfix_auth WHERE postfix_auth_id = $ZONE_ID")
ALIAS_ID=$(q "SELECT IF(domain_type = 'als', domain_id, 0)
              FROM imscp.postfix_auth WHERE postfix_auth_id = $ZONE_ID")

# Every query is scoped to this one zone: another configured zone on the same
# box owns rows too, and counting or rewriting those would make the run lie.
SCOPE="domain_id = $DOMAIN_ID AND alias_id = $ALIAS_ID AND owned_by = 'SGW_PostfixAuth'"

ours()   { q "SELECT COUNT(*) FROM imscp.domain_dns
               WHERE $SCOPE AND domain_dns_status <> 'todelete'"; }
status() { q "SELECT status FROM imscp.postfix_auth WHERE postfix_auth_id = $ZONE_ID"; }

# Queue the zone and let the backend work through it.
run_backend() {
    q "UPDATE imscp.postfix_auth SET status = 'tochange' WHERE postfix_auth_id = $ZONE_ID" \
        > /dev/null
    perl /var/www/imscp/engine/imscp-rqst-mngr > /dev/null 2>&1
}

settled() {
    local s
    s=$(status)

    if [ "$s" = 'ok' ]; then
        return 0
    fi

    printf '        zone status: %s\n' "$(echo "$s" | head -c 200)"
    return 1
}

# Captured so the zone can be handed back exactly as it was found, whatever it
# was configured with.
read -r WAS_DKIM WAS_SPF_MODE WAS_SPF_HOSTS WAS_DMARC <<EOF
$(q "SELECT dkim_enabled, spf_mode, COALESCE(spf_hosts, ''), dmarc_enabled
     FROM imscp.postfix_auth WHERE postfix_auth_id = $ZONE_ID")
EOF

echo "domain=$DOMAIN zone=$ZONE_ID"
echo

run_backend
before=$(ours)

if [ "$before" -gt 0 ] && settled; then
    ok "the zone starts settled with $before record(s)"
else
    nok 'the zone starts settled with records'
fi

echo
echo '# A record on its way out that is wanted again'

# What a full installer run produced: the rows were marked todelete and the
# zone was queued again before Modules::CustomDNS had removed them. Inserting
# a second identical row is what the unique key refuses, so the row has to be
# brought back instead.
q "UPDATE imscp.domain_dns SET domain_dns_status = 'todelete' WHERE $SCOPE" > /dev/null

run_backend

if settled; then
    ok 'the zone survives a pass that wanted a withdrawn record back'
else
    nok 'the zone errored when a withdrawn record was wanted back'
fi

if [ "$(ours)" = "$before" ]; then
    ok "the withdrawn records were brought back ($(ours))"
else
    nok "expected $before record(s) back, found $(ours)"
fi

echo
echo '# A record the customer owns with the same content'

spf=$(q "SELECT spf_record FROM imscp.postfix_auth WHERE postfix_auth_id = $ZONE_ID")

# Hand our own SPF record over to the custom DNS feature, as though the
# customer had typed it in themselves, and check the plugin leaves it be
# rather than trying to insert its own copy.
q "UPDATE imscp.domain_dns SET owned_by = 'custom_dns_feature'
   WHERE $SCOPE AND domain_text = '$spf'" > /dev/null

run_backend

if settled; then
    ok 'an identical record owned by the customer does not break the pass'
else
    nok 'an identical record owned by the customer broke the pass'
fi

mine=$(q "SELECT COUNT(*) FROM imscp.domain_dns
          WHERE domain_id = $DOMAIN_ID AND alias_id = $ALIAS_ID
            AND domain_text = '$spf'")

if [ "$mine" = '1' ]; then
    ok 'the record was not duplicated'
else
    nok "the record now appears $mine times"
fi

# Give it back, so the zone is ours again for the rest of the run.
q "UPDATE imscp.domain_dns SET owned_by = 'SGW_PostfixAuth'
   WHERE domain_id = $DOMAIN_ID AND alias_id = $ALIAS_ID
     AND domain_text = '$spf'" > /dev/null

echo
echo '# A changed record replaces the old one'

q "UPDATE imscp.postfix_auth SET spf_hosts = '203.0.113.7'
   WHERE postfix_auth_id = $ZONE_ID" > /dev/null

run_backend

if q "SELECT domain_text FROM imscp.domain_dns
      WHERE $SCOPE AND domain_dns_status <> 'todelete'" \
    | grep -q '203.0.113.7'
then
    ok 'the new SPF record is published'
else
    nok 'the new SPF record is not published'
fi

if [ "$(ours)" = "$before" ]; then
    ok 'the old SPF record was withdrawn rather than left alongside'
else
    nok "the zone now has $(ours) records, expected $before"
fi

echo
echo '# Turning everything off'

q "UPDATE imscp.postfix_auth
   SET dkim_enabled = 0, spf_mode = 'off', dmarc_enabled = 0
   WHERE postfix_auth_id = $ZONE_ID" > /dev/null

run_backend

if [ "$(ours)" = '0' ]; then
    ok 'every record is withdrawn when nothing is enabled'
else
    nok "$(ours) record(s) survived with nothing enabled"
fi

# Put the zone back the way it was found.
q "UPDATE imscp.postfix_auth
   SET dkim_enabled = $WAS_DKIM, spf_mode = '$WAS_SPF_MODE',
       dmarc_enabled = $WAS_DMARC, spf_hosts = '$WAS_SPF_HOSTS'
   WHERE postfix_auth_id = $ZONE_ID" > /dev/null
run_backend

if [ "$(ours)" = "$before" ] && settled; then
    ok "the zone comes back with its $before record(s)"
else
    nok 'the zone did not come back'
fi

echo
printf '%d passed, %d failed\n' "$PASSED" "$FAILED"
[ "$FAILED" -eq 0 ]
