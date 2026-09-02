#!/bin/bash
# Render every page the plugin adds, as the user who is meant to see it.
#
# A template block that is defined but never parsed, or parsed but never
# defined, is the classic way an i-MSCP plugin page fails, and it fails at
# render time rather than at lint time. Nothing but actually fetching the page
# finds it.
#
# The panel passwords of the customer and reseller accounts are set to a known
# value for the duration of the run and restored afterwards.
#
#   sudo /usr/local/src/imscp-postfix-auth/test/pages.sh
#
# Run inside the Vagrant box, as root.

set -u

CUSTOMER="${1:-wpcache.test}"
RESELLER="${2:-reseller1}"
TEMP_PASS='pages-test-4vN2qz'

PASSED=0
FAILED=0

ok()  { PASSED=$((PASSED + 1)); printf '  ok    %s\n' "$1"; }
nok() { FAILED=$((FAILED + 1)); printf '  FAIL  %s\n' "$1"; }

[ "$(id -u)" -eq 0 ] || { echo "$0: must be run as root" >&2; exit 1; }

PANEL="https://$(grep -E '^BASE_SERVER_VHOST ' /etc/imscp/imscp.conf | awk '{print $3}')"
PORT="$(grep -E '^BASE_SERVER_VHOST_HTTPS_PORT ' /etc/imscp/imscp.conf | awk '{print $3}')"
PANEL="$PANEL:$PORT"

# The panel serves its own certificate for a hostname this box does not
# resolve, so the name is pinned to the loopback and verification is off. What
# is under test is the page, not the TLS.
CURL="curl -sk --resolve $(echo "$PANEL" | sed -E 's#https://([^:]+):([0-9]+)#\1:\2:127.0.0.1#')"

WORK=$(mktemp -d)
trap 'restore_passwords; rm -rf "$WORK"' EXIT

HASH=$(openssl passwd -apr1 "$TEMP_PASS")

save_passwords() {
    mysql -N -B -e "
        SELECT CONCAT(admin_name, '\t', admin_pass) FROM imscp.admin
        WHERE admin_name IN ('$CUSTOMER', '$RESELLER')" > "$WORK/passwords"
}

set_passwords() {
    mysql imscp -e "
        UPDATE admin SET admin_pass = '$HASH'
        WHERE admin_name IN ('$CUSTOMER', '$RESELLER')"
}

restore_passwords() {
    [ -s "$WORK/passwords" ] || return 0

    while IFS=$'\t' read -r name hash; do
        mysql imscp -e "UPDATE admin SET admin_pass = '$hash' WHERE admin_name = '$name'"
    done < "$WORK/passwords"
}

# Log in and leave the session cookie in $WORK/<user>.jar
login() {
    local user="$1" jar="$WORK/$1.jar"

    rm -f "$jar"
    $CURL -c "$jar" -b "$jar" "$PANEL/index.php" > /dev/null
    $CURL -c "$jar" -b "$jar" -L \
        -d 'action=login' --data-urlencode "uname=$user" \
        --data-urlencode "upass=$TEMP_PASS" \
        "$PANEL/index.php" > "$WORK/$1.login"

    grep -qiE 'logout|Overview' "$WORK/$1.login"
}

# Fetch one page and check it rendered rather than merely responded.
fetch() {
    local user="$1" path="$2" want="$3" label="$4"
    local body="$WORK/page.$$" code

    code=$($CURL -b "$WORK/$user.jar" -o "$body" -w '%{http_code}' "$PANEL$path")

    if [ "$code" != '200' ]; then
        nok "$label (HTTP $code)"
        return
    fi

    # The template engine reports an unresolved block by leaving its own
    # markers in the output, and PHP reports a fatal in the body; either means
    # the page did not really render.
    if grep -qiE 'Fatal error|Uncaught|BDP:|EDP:|\{[A-Z_]+\}' "$body"; then
        nok "$label (template or PHP error in the output)"
        grep -oiE 'Fatal error[^<]*|Uncaught[^<]*|\{[A-Z_]+\}' "$body" | head -3 | sed 's/^/        /'
        return
    fi

    if ! grep -qF "$want" "$body"; then
        nok "$label (expected content missing: $want)"
        return
    fi

    ok "$label"
}

save_passwords
set_passwords

echo "panel=$PANEL"
echo

if login "$CUSTOMER"; then
    ok "customer $CUSTOMER can log in"

    fetch "$CUSTOMER" '/client/postfix_auth.php' 'Email authentication' \
        'the customer zone list renders'
    fetch "$CUSTOMER" '/client/postfix_auth_edit.php?type=dmn&id=1' 'DMARC' \
        'the customer edit page renders'
    fetch "$CUSTOMER" '/client/postfix_auth_edit.php?type=dmn&id=1&action=check' 'In DNS' \
        'the edit page renders its published-record check'
else
    nok "customer $CUSTOMER can log in"
fi

if login "$RESELLER"; then
    ok "reseller $RESELLER can log in"

    fetch "$RESELLER" '/reseller/postfix_auth.php' 'Email authentication' \
        'the reseller customer list renders'
else
    nok "reseller $RESELLER can log in"
fi

echo
printf '%d passed, %d failed\n' "$PASSED" "$FAILED"
[ "$FAILED" -eq 0 ]
