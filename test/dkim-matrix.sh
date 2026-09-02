#!/bin/bash
# What the live services do with the plugin's configuration.
#
# The unit tests in test/backend cover the record generators. This covers the
# part no generator can prove: which mail actually gets signed, which does not,
# and what a resolver sees.
#
# Run inside the Vagrant box, as root, with the plugin installed and enabled
# and DKIM, SPF and DMARC turned on for the test domain:
#
#   sudo /usr/local/src/imscp-postfix-auth/test/dkim-matrix.sh [domain]
#
# It creates one fixture mailbox in the test domain and leaves it in place.

set -u

DOMAIN="${1:-wpcache.test}"
FIXTURE_PASS='dkim-matrix-test'
HERE="$(cd "$(dirname "$0")" && pwd)"

PASSED=0
FAILED=0
SKIPPED=0

ok()   { PASSED=$((PASSED + 1)); printf '  ok    %s\n' "$1"; }
nok()  { FAILED=$((FAILED + 1)); printf '  FAIL  %s\n' "$1"; }
skip() { SKIPPED=$((SKIPPED + 1)); printf '  skip  %s -- %s\n' "$1" "$2"; }

[ "$(id -u)" -eq 0 ] || { echo "$0: must be run as root" >&2; exit 1; }

MTA_HOST="$(postconf -h myhostname)"
LAN_IP="$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -1)"

# A plain unix account, so that delivery lands in a file this script can read.
# Deliberately not root: /etc/aliases forwards root off the box, and a test
# that sends real mail to a real person is a test nobody runs twice.
LOCAL_USER=vagrant
MBOX="/var/mail/$LOCAL_USER"

if grep -qE "^$LOCAL_USER:" /etc/aliases 2>/dev/null; then
    echo "$0: $LOCAL_USER is aliased in /etc/aliases; mail would leave the box" >&2
    exit 1
fi

echo "domain=$DOMAIN mta=$MTA_HOST lan=$LAN_IP"

#
## Helpers
#

reset_mbox() {
    : > "$MBOX"
    chown "$LOCAL_USER" "$MBOX" 2>/dev/null
}

# Wait for a message with the given subject to be delivered, then say whether
# it carries a DKIM signature for the given domain.
#
# Returns 0 signed, 1 unsigned, 2 never arrived.
delivered_signature() {
    local subject="$1" want_domain="$2" i

    for i in $(seq 1 30); do
        grep -qF "Subject: $subject" "$MBOX" 2>/dev/null && break
        sleep 1
    done

    grep -qF "Subject: $subject" "$MBOX" 2>/dev/null || return 2

    # The signature is folded across several lines, so the d= tag is looked for
    # in the header block as a whole rather than on the DKIM-Signature line.
    if sed -n '/^DKIM-Signature:/,/^[^ \t]/p' "$MBOX" | grep -q "d=$want_domain"; then
        return 0
    fi

    return 1
}

send_local() {
    local sender="$1" subject="$2"

    printf 'From: %s\nTo: %s@%s\nSubject: %s\n\nbody\n' \
        "$sender" "$LOCAL_USER" "$MTA_HOST" "$subject" \
        | sendmail -f "$sender" "$LOCAL_USER@$MTA_HOST"
}

send_smtp() {
    python3 "$HERE/smtp-send.py" "$@"
}

#
## Fixture: one real mailbox, for the authenticated submission test
#

FIXTURE_ADDR="dkimtest@$DOMAIN"

ensure_fixture_mailbox() {
    local exists domain_id hash

    exists=$(mysql -N -B -e \
        "SELECT COUNT(*) FROM imscp.mail_users WHERE mail_addr = '$FIXTURE_ADDR'")
    [ "$exists" = "0" ] || return 0

    domain_id=$(mysql -N -B -e \
        "SELECT domain_id FROM imscp.domain WHERE domain_name = '$DOMAIN'")
    [ -n "$domain_id" ] || return 1

    # The same hash the panel writes: crypt() with a SHA-512 round count, which
    # is what courier-authlib is configured to verify against.
    # Single-quoted on the PHP side: in a double-quoted PHP string "$6" and
    # "$rounds" are variable interpolations, and the resulting salt is not the
    # one anything can verify against.
    hash=$(php -r 'echo crypt($argv[1], '"'"'$6$rounds=5000$'"'"' . bin2hex(random_bytes(8)));' \
        "$FIXTURE_PASS")

    mysql imscp -e "
        INSERT INTO mail_users (
            mail_acc, mail_pass, mail_forward, domain_id, mail_type, sub_id,
            status, po_active, mail_auto_respond, quota, mail_addr
        ) VALUES (
            'dkimtest', '$hash', NULL, $domain_id, 'normal_mail', 0,
            'toadd', 'yes', 0, 0, '$FIXTURE_ADDR'
        )"

    perl /var/www/imscp/engine/imscp-rqst-mngr >/dev/null 2>&1

    [ "$(mysql -N -B -e \
        "SELECT status FROM imscp.mail_users WHERE mail_addr = '$FIXTURE_ADDR'")" = 'ok' ]
}

#
## Signing decisions
#

echo
echo '# Which mail gets signed'

reset_mbox
send_local "app@$DOMAIN" 'sgw-local-pickup'
case "$(delivered_signature 'sgw-local-pickup' "$DOMAIN"; echo $?)" in
    0) ok   'mail submitted locally is signed' ;;
    1) nok  'mail submitted locally is NOT signed' ;;
    *) nok  'mail submitted locally never arrived' ;;
esac

reset_mbox
send_smtp 127.0.0.1 25 "app@$DOMAIN" "$LOCAL_USER@$MTA_HOST" 'sgw-loopback-25' >/dev/null
case "$(delivered_signature 'sgw-loopback-25' "$DOMAIN"; echo $?)" in
    0) ok   'mail from a local application over loopback is signed' ;;
    1) nok  'mail from a local application over loopback is NOT signed' ;;
    *) nok  'mail from a local application over loopback never arrived' ;;
esac

# The one that must never regress. A forged sender arriving on port 25 from an
# address that is not ours is exactly what an attacker sends to borrow our
# reputation; signing it would put our name on their mail.
reset_mbox
send_smtp "$LAN_IP" 25 "attacker@$DOMAIN" "$LOCAL_USER@$MTA_HOST" 'sgw-forged-25' >/dev/null
case "$(delivered_signature 'sgw-forged-25' "$DOMAIN"; echo $?)" in
    0) nok  'a forged sender arriving on port 25 IS SIGNED -- mail is being signed for anyone' ;;
    1) ok   'a forged sender arriving on port 25 is not signed' ;;
    *) nok  'a forged sender arriving on port 25 never arrived' ;;
esac

# Mail from a subdomain is signed with the parent zone's key, which is aligned
# for DMARC under relaxed alignment.
reset_mbox
send_local "app@blog.$DOMAIN" 'sgw-subdomain'
case "$(delivered_signature 'sgw-subdomain' "$DOMAIN"; echo $?)" in
    0) ok   "mail from a subdomain is signed with d=$DOMAIN" ;;
    1) nok  "mail from a subdomain is NOT signed with d=$DOMAIN" ;;
    *) nok  'mail from a subdomain never arrived' ;;
esac

echo
echo '# Authenticated submission'

if ensure_fixture_mailbox; then
    reset_mbox
    auth_error=$(send_smtp "$LAN_IP" 587 "$FIXTURE_ADDR" "$LOCAL_USER@$MTA_HOST" \
        'sgw-submission-auth' "$FIXTURE_ADDR" "$FIXTURE_PASS")

    if [ -n "$auth_error" ]; then
        skip 'authenticated submission is signed' "SMTP AUTH failed: $auth_error"
    else
        case "$(delivered_signature 'sgw-submission-auth' "$DOMAIN"; echo $?)" in
            0) ok   'mail from an authenticated remote client is signed' ;;
            1) nok  'mail from an authenticated remote client is NOT signed' ;;
            *) nok  'mail from an authenticated remote client never arrived' ;;
        esac
    fi
else
    skip 'authenticated submission is signed' 'could not create the fixture mailbox'
fi

#
## DNS
#

echo
echo '# What a resolver sees'

spf=$(dig +short TXT "$DOMAIN" @127.0.0.1 | tr -d '"')

if [ -z "$spf" ]; then
    nok 'the domain publishes an SPF record'
elif [ "$spf" = 'v=spf1 a mx -all' ]; then
    nok "the hard-coded i-MSCP SPF record is still being served ($spf)"
else
    ok "a custom SPF record has replaced the i-MSCP default ($spf)"
fi

dmarc=$(dig +short TXT "_dmarc.$DOMAIN" @127.0.0.1 | tr -d '"')
case "$dmarc" in
    v=DMARC1*) ok "a DMARC record is published ($dmarc)" ;;
    '')        nok 'no DMARC record is published' ;;
    *)         nok "the _dmarc record is not a DMARC record ($dmarc)" ;;
esac

selector=$(mysql -N -B -e "
    SELECT k.selector FROM imscp.postfix_auth_key AS k
    JOIN imscp.postfix_auth AS z USING(postfix_auth_id)
    WHERE z.domain_name = '$DOMAIN' AND k.retired_at = 0
    ORDER BY k.created_at DESC LIMIT 1")

if [ -z "$selector" ]; then
    nok 'the domain has an active DKIM key'
else
    dkim=$(dig +short TXT "$selector._domainkey.$DOMAIN" @127.0.0.1 | tr -d '" ')
    case "$dkim" in
        v=DKIM1*) ok "the DKIM public key is published at $selector._domainkey" ;;
        '')       nok "no DKIM record at $selector._domainkey.$DOMAIN" ;;
        *)        nok "the record at $selector._domainkey.$DOMAIN is not a DKIM key" ;;
    esac

    # The published key and the key being signed with have to be the same one,
    # which nothing else here checks: a stale record still parses.
    #
    # Compared directly rather than with opendkim-testkey, which resolves
    # through /etc/resolv.conf: the box points at its provider's resolver,
    # which knows nothing of a .test zone served here, so every check would
    # report "record not found" whatever the key said.
    published=$(dig +short TXT "$selector._domainkey.$DOMAIN" @127.0.0.1 \
        | tr -d '" ' | sed 's/.*p=//')
    derived=$(openssl rsa -in "/etc/opendkim/keys/$DOMAIN/$selector.private" \
        -pubout 2>/dev/null | grep -v -- '-----' | tr -d '\n')

    if [ -n "$published" ] && [ "$published" = "$derived" ]; then
        ok 'the published DKIM record matches the private key in use'
    else
        nok 'the published DKIM record does not match the private key'
    fi
fi

#
## Failure modes
#

echo
echo '# When the milter is not there'

# Postfix's own default for milter_default_action is 'shutdown', which turns a
# stopped milter into a total mail outage. This is the test that says the
# plugin did not leave that default in place.
systemctl stop opendkim
reset_mbox
send_local "app@$DOMAIN" 'sgw-milter-down'

case "$(delivered_signature 'sgw-milter-down' "$DOMAIN"; echo $?)" in
    0) nok  'mail was signed with the milter stopped, which cannot be right' ;;
    1) ok   'mail still flows, unsigned, when the milter is stopped' ;;
    *) nok  'mail stopped flowing when the milter was stopped -- milter_default_action' ;;
esac

systemctl start opendkim

echo
printf '%d passed, %d failed, %d skipped\n' "$PASSED" "$FAILED" "$SKIPPED"
[ "$FAILED" -eq 0 ]
