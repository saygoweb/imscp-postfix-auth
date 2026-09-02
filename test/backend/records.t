use strict;
use warnings;
use Test::More;
use Cwd 'abs_path';

# The record generators are the part worth unit testing: everything downstream
# of them is what BIND, Postfix and OpenDKIM do with the result, which
# test/dkim-matrix.sh checks against the live services.
#
# Run as root: the module pulls in iMSCP::* from the engine, whose directory
# the panel keeps unreadable to other users.
#
#   cd test/backend && sudo perl all.t
use lib '/var/www/imscp/engine/PerlLib';

# The file is backend/SGW_PostfixAuth.pm but the package is
# Plugin::SGW_PostfixAuth, so it is loaded by path the way i-MSCP loads it.
require_ok(abs_path('../../backend/SGW_PostfixAuth.pm'))
    or BAIL_OUT('cannot load the plugin');

# The generators touch no state, so they can be called on an unblessed
# instance rather than booting the whole i-MSCP backend.
my $plugin = bless {}, 'Plugin::SGW_PostfixAuth';

my %spfBase = (
    spf_mode      => 'guided',
    spf_a         => 1,
    spf_mx        => 1,
    spf_hosts     => '',
    spf_includes  => '',
    spf_redirect  => '',
    spf_qualifier => '-all',
    spf_raw       => ''
);

my %dmarcBase = (
    dmarc_enabled => 1,
    dmarc_p       => 'none',
    dmarc_sp      => '',
    dmarc_pct     => 100,
    dmarc_rua     => '',
    dmarc_ruf     => '',
    dmarc_adkim   => 'r',
    dmarc_aspf    => 'r',
    dmarc_fo      => '0',
    dmarc_ri      => 86400
);

# --- SPF -------------------------------------------------------------------

is(
    $plugin->buildSpfRecord( { %spfBase, spf_mode => 'off' } ),
    undef,
    'a zone that keeps the server default gets no record of its own'
);

is(
    $plugin->buildSpfRecord( { %spfBase } ),
    'v=spf1 a mx -all',
    'the guided default reproduces the record i-MSCP hard-codes'
);

is(
    $plugin->buildSpfRecord( { %spfBase, spf_a => 0, spf_qualifier => '~all' } ),
    'v=spf1 mx ~all',
    'mechanisms and the qualifier are both switchable'
);

# A bare address is the common case and the one a customer is most likely to
# type, so the mechanism is inferred from its shape.
is(
    $plugin->buildSpfRecord( { %spfBase, spf_hosts => "192.0.2.1\n198.51.100.0/24" } ),
    'v=spf1 a mx ip4:192.0.2.1 ip4:198.51.100.0/24 -all',
    'bare IPv4 addresses become ip4: mechanisms'
);

is(
    $plugin->buildSpfRecord( { %spfBase, spf_hosts => '2001:db8::1' } ),
    'v=spf1 a mx ip6:2001:db8::1 -all',
    'bare IPv6 addresses become ip6: mechanisms'
);

is(
    $plugin->buildSpfRecord( { %spfBase, spf_hosts => 'ip4:192.0.2.1' } ),
    'v=spf1 a mx ip4:192.0.2.1 -all',
    'an address that already carries its mechanism is left alone'
);

is(
    $plugin->buildSpfRecord( {
        %spfBase, spf_includes => "spf.example.net\ninclude:mail.example.org"
    } ),
    'v=spf1 a mx include:spf.example.net include:mail.example.org -all',
    'includes are prefixed only when they need it'
);

# RFC 7208 s6.1: a redirect is ignored when the record also has an "all"
# mechanism, so emitting both would silently drop what the customer asked for.
is(
    $plugin->buildSpfRecord( { %spfBase, spf_redirect => 'example.net' } ),
    'v=spf1 a mx redirect=example.net',
    'a redirect replaces the all qualifier rather than joining it'
);

is(
    $plugin->buildSpfRecord( { %spfBase, spf_mode => 'raw', spf_raw => '  v=spf1 -all  ' } ),
    'v=spf1 -all',
    'a hand-written record is passed through, trimmed'
);

is(
    $plugin->buildSpfRecord( { %spfBase, spf_mode => 'raw', spf_raw => '   ' } ),
    undef,
    'an empty hand-written record is no record at all'
);

# --- The SPF lookup cap ----------------------------------------------------

is( $plugin->spfLookupCount( 'v=spf1 -all' ), 0, 'a record with no mechanisms costs nothing' );
is( $plugin->spfLookupCount( 'v=spf1 a mx -all' ), 2, 'a and mx each cost a lookup' );
is(
    $plugin->spfLookupCount( 'v=spf1 ip4:192.0.2.1 ip6:2001:db8::1 -all' ),
    0,
    'literal addresses are free'
);
is(
    $plugin->spfLookupCount( 'v=spf1 include:a include:b ~all' ),
    2,
    'each include costs a lookup'
);
is(
    $plugin->spfLookupCount( 'v=spf1 -include:a redirect=b exists:c ptr -all' ),
    4,
    'qualified terms, redirect, exists and ptr all count'
);

{
    my @includes = map { "spf$_.example.net" } 1 .. 9;
    my $record = $plugin->buildSpfRecord( {
        %spfBase, spf_includes => join( "\n", @includes )
    } );
    is(
        $plugin->spfLookupCount( $record ), 11,
        'nine includes on top of a and mx is over the cap'
    );
}

# --- DMARC -----------------------------------------------------------------

is(
    $plugin->buildDmarcRecord( { %dmarcBase, dmarc_enabled => 0 } ),
    undef,
    'a zone with DMARC off gets no record'
);

is(
    $plugin->buildDmarcRecord( { %dmarcBase } ),
    'v=DMARC1; p=none',
    'everything at its RFC default is left out, so the record stays readable'
);

is(
    $plugin->buildDmarcRecord( { %dmarcBase, dmarc_p => 'reject', dmarc_sp => 'quarantine' } ),
    'v=DMARC1; p=reject; sp=quarantine',
    'v and p lead, and the subdomain policy follows'
);

is(
    $plugin->buildDmarcRecord( { %dmarcBase, dmarc_rua => 'dmarc@example.com' } ),
    'v=DMARC1; p=none; rua=mailto:dmarc@example.com',
    'a bare report address is turned into a mailto: URI'
);

is(
    $plugin->buildDmarcRecord( {
        %dmarcBase, dmarc_rua => 'a@example.com, mailto:b@example.net'
    } ),
    'v=DMARC1; p=none; rua=mailto:a@example.com,mailto:b@example.net',
    'several addresses are comma joined, and one already a URI is left alone'
);

is(
    $plugin->buildDmarcRecord( {
        %dmarcBase, dmarc_adkim => 's', dmarc_aspf => 's', dmarc_pct => 50,
        dmarc_fo => '1', dmarc_ri => 3600
    } ),
    'v=DMARC1; p=none; adkim=s; aspf=s; pct=50; fo=1; ri=3600',
    'every non-default tag is emitted, in tag order'
);

# --- DKIM ------------------------------------------------------------------

is(
    $plugin->buildDkimRecord( 'MIIBIjANBgkq' ),
    'v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkq',
    'the DKIM record names the hash, the key type and the key'
);

# --- Record identity -------------------------------------------------------
#
# What comes back out of the database has been through Modules::CustomDNS,
# which quotes the RDATA and splits anything over 255 bytes into several
# <character-string>s. Without normalising that, every pass would see its own
# published record as a different one and republish it.

is(
    $plugin->_recordKey( 'example.com.', 'v=spf1 a mx -all' ),
    $plugin->_recordKey( 'example.com.', '"v=spf1 a mx -all"' ),
    'quoting does not change a record identity'
);

is(
    $plugin->_recordKey( 'sel._domainkey.example.com.', 'v=DKIM1; p=AAAABBBB' ),
    $plugin->_recordKey( 'sel._domainkey.example.com.', '"v=DKIM1; p=AAAA" "BBBB"' ),
    'a split long record has the same identity as the record it was split from'
);

isnt(
    $plugin->_recordKey( 'example.com.', 'v=spf1 a -all' ),
    $plugin->_recordKey( 'example.com.', 'v=spf1 mx -all' ),
    'two different records are still two different records'
);

done_testing();
