=head1 NAME

 Plugin::SGW_PostfixAuth

=cut

# i-MSCP SGW_PostfixAuth plugin
# Copyright (C) 2026 Cambell Prince <cambell.prince@gmail.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

package Plugin::SGW_PostfixAuth;

use strict;
use warnings;
use File::Temp;
use iMSCP::Database;
use iMSCP::Debug;
use iMSCP::Dir;
use iMSCP::EventManager;
use iMSCP::Execute;
use iMSCP::File;
use iMSCP::Service;
use Servers::mta;
use parent 'Common::SingletonClass';

=head1 DESCRIPTION

 Backend for the i-MSCP SGW_PostfixAuth plugin.

 Signs outbound mail with OpenDKIM, and publishes the DKIM, SPF and DMARC
 records for each zone through i-MSCP's own custom DNS machinery.

 Two things about the way this plugs into Postfix are worth knowing before
 reading the code.

 First, the milter is reached over a TCP socket rather than a unix one. i-MSCP
 runs smtpd and cleanup chrooted, so a socket under /run is simply not visible
 to them.

 Second, the Postfix settings are applied twice by two different routes, and
 both are needed. install()/enable() apply them directly, so that turning the
 plugin on takes effect without waiting for an installer run. And
 registerSetupListeners() re-applies them from within an i-MSCP installer run,
 which rebuilds main.cf from its template and would otherwise drop them. That
 listener registers at a priority below every third-party listener, and adds
 to smtpd_milters rather than replacing it, so it neither loses to nor
 clobbers a listener that is customising Postfix for other reasons.

=cut

# Where registerSetupListeners() looks for what to tell Postfix.
#
# It is a class method, called during an installer run with no plugin instance
# and therefore no access to config.php, so the milter it should point Postfix
# at has to be on disk. Written when the plugin is installed or enabled and
# removed when it is disabled or uninstalled, so the listener is inert exactly
# when the plugin is.
use constant STATE_FILE => '/etc/imscp/sgw_postfix_auth.milter';

# The Debian systemd unit runs a bare `/usr/sbin/opendkim` with no environment
# file - /etc/default/opendkim is legacy and unread - so everything, the socket
# and the pid file included, comes from this one file.
use constant OPENDKIM_CONF => '/etc/opendkim.conf';

use constant DNS_OWNER => 'SGW_PostfixAuth';

=head1 PUBLIC METHODS

=over 4

=item registerSetupListeners( $eventManager )

 Register listeners that must run inside an i-MSCP installer run.

 Called as a class method on every enabled plugin by the i-MSCP setup, before
 the servers are configured. See STATE_FILE above for why the milter is read
 from disk rather than from the plugin configuration.

 Return int 0 on success, other on failure

=cut

sub registerSetupListeners
{
    my ( $class, $eventManager ) = @_;

    my $milter = _readState() or return 0;

    # Keep the package through both an install and an uninstall pass: without
    # the latter, a pass that computes the package list afresh would offer to
    # remove the very milter Postfix is being pointed at.
    $eventManager->registerOne( 'beforeInstallPackages', sub {
        push @{ $_[0] }, 'opendkim', 'opendkim-tools';
        0;
    } );
    $eventManager->registerOne( 'beforeUninstallPackages', sub {
        @{ $_[0] } = grep { $_ ne 'opendkim' && $_ ne 'opendkim-tools' } @{ $_[0] };
        0;
    } );

    # -1000 rather than the -99 that third-party listeners conventionally use,
    # so that this runs last: the event manager pops the highest priority
    # first. Running last is what keeps our milter in main.cf when another
    # listener replaces neighbouring parameters wholesale.
    $eventManager->register(
        'afterMtaBuildConf', sub { _postconfApply( $milter ); }, -1000
    );
}

=item install( )

 Perform install tasks

 Return int 0 on success, other on failure

=cut

sub install
{
    my ( $self ) = @_;

    my $rs = $self->_installPackages();
    $rs ||= $self->_checkRequirements();
    $rs ||= $self->_writeOpendkimConf();
    return $rs if $rs;

    # Nothing is signed yet - no zone has asked for a key - but the tables have
    # to exist before opendkim will start at all.
    $rs = $self->_syncKeyTables();
    $rs ||= $self->_startOpendkim();
    return $rs if $rs;

    $rs = $self->_writeState();
    $rs ||= _postconfApply( $self->{'milter'} );
    $rs ||= $self->_reloadMta();
}

=item update( $fromVersion, $toVersion )

 Perform update tasks

 Return int 0 on success, other on failure

=cut

sub update
{
    my ( $self ) = @_;

    my $rs = $self->_installPackages();
    $rs ||= $self->_writeOpendkimConf();
    $rs ||= $self->_writeState();
    $rs ||= _postconfApply( $self->{'milter'} );
    $rs ||= $self->_reloadMta();
    return $rs if $rs;

    # Regenerate everything, so that a change to a record generator reaches
    # zones that are already configured.
    my $qrs = $self->{'db'}->doQuery(
        'u', "UPDATE postfix_auth SET status = 'tochange' WHERE status = 'ok'"
    );
    unless ( ref $qrs eq 'HASH' ) {
        error( $qrs );
        return 1;
    }

    # As in enable(): process them here, or they stay pending until some
    # unrelated backend request comes along.
    $self->run();
}

=item enable( )

 Perform enable tasks

 Return int 0 on success, other on failure

=cut

sub enable
{
    my ( $self ) = @_;

    my $rs = $self->_writeOpendkimConf();
    $rs ||= $self->_startOpendkim();
    $rs ||= $self->_writeState();
    $rs ||= _postconfApply( $self->{'milter'} );
    $rs ||= $self->_reloadMta();
    return $rs if $rs;

    my $qrs = $self->{'db'}->doQuery(
        'u', "UPDATE postfix_auth SET status = 'toenable' WHERE status = 'disabled'"
    );
    unless ( ref $qrs eq 'HASH' ) {
        error( $qrs );
        return 1;
    }

    # Process them here rather than leaving them queued: nothing else runs in
    # this pass, so the zones would otherwise stay pending until some unrelated
    # backend request came along.
    $self->run();
}

=item disable( )

 Perform disable tasks

 Every zone's key and records are withdrawn, but each row remembers whether it
 was enabled so that re-enabling the plugin restores the previous state.

 Return int 0 on success, other on failure

=cut

sub disable
{
    my ( $self ) = @_;

    my $qrs = $self->{'db'}->doQuery(
        'u', "UPDATE postfix_auth SET status = 'todisable' WHERE status <> 'disabled'"
    );
    unless ( ref $qrs eq 'HASH' ) {
        error( $qrs );
        return 1;
    }

    my $rs = $self->run();

    # Postfix stops pointing at the milter before the milter goes away, never
    # the other way round: a main.cf naming a milter that is not listening is
    # a mail outage, not a degraded feature.
    $rs ||= _postconfRemove( $self->{'milter'} );
    $rs ||= $self->_reloadMta();
    $rs ||= $self->_stopOpendkim();
    $rs ||= _removeState();
    $rs;
}

=item uninstall( )

 Perform uninstall tasks

 Return int 0 on success, other on failure

=cut

sub uninstall
{
    my ( $self ) = @_;

    # disable() has normally run already, but a plugin can be uninstalled from
    # any state, so do not assume it.
    my $rs = _postconfRemove( $self->{'milter'} );
    $rs ||= $self->_reloadMta();
    $rs ||= $self->_stopOpendkim();
    $rs ||= _removeState();
    return $rs if $rs;

    if ( -f OPENDKIM_CONF ) {
        $rs = iMSCP::File->new( filename => OPENDKIM_CONF )->delFile();
        return $rs if $rs;
    }

    # The whole directory: the key tables, the trusted host list and every
    # private key live under it and are all this plugin's to remove.
    if ( -d $self->{'confDir'} ) {
        eval { iMSCP::Dir->new( dirname => $self->{'confDir'} )->remove(); };
        if ( $@ ) {
            error( sprintf( "Couldn't remove %s: %s", $self->{'confDir'}, $@ ));
            return 1;
        }
    }

    0;
}

=item run( )

 Process pending zones

 Return int 0 on success, other on failure

=cut

sub run
{
    my ( $self ) = @_;

    my $rows = $self->{'db'}->doQuery(
        'postfix_auth_id',
        "
            SELECT * FROM postfix_auth
            WHERE status IN('toadd', 'tochange', 'toenable', 'todisable', 'todelete')
        "
    );
    unless ( ref $rows eq 'HASH' ) {
        error( $rows );
        return 1;
    }

    return 0 unless %{ $rows };

    my $ret = 0;
    my $changed = 0;

    for my $row ( values %{ $rows } ) {
        my $status = $row->{'status'};
        my ( $rs, @sql );

        if ( $status eq 'todelete' ) {
            $rs = $self->_removeZone( $row );
            @sql = $rs
                ? ( 'UPDATE postfix_auth SET status = ? WHERE postfix_auth_id = ?',
                    ( scalar getMessageByType( 'error' ) || 'Unknown error' ),
                    $row->{'postfix_auth_id'} )
                : ( 'DELETE FROM postfix_auth WHERE postfix_auth_id = ?',
                    $row->{'postfix_auth_id'} );
        } elsif ( $status eq 'todisable' ) {
            $rs = $self->_removeZone( $row, 'keep' );
            @sql = (
                'UPDATE postfix_auth SET status = ?, state = ? WHERE postfix_auth_id = ?',
                ( $rs ? ( scalar getMessageByType( 'error' ) || 'Unknown error' ) : 'disabled' ),
                '', $row->{'postfix_auth_id'}
            );
        } else {
            $rs = $self->_writeZone( $row );
            @sql = (
                'UPDATE postfix_auth SET status = ?, state = ? WHERE postfix_auth_id = ?',
                ( $rs ? ( scalar getMessageByType( 'error' ) || 'Unknown error' ) : 'ok' ),
                '', $row->{'postfix_auth_id'}
            );
        }

        $ret ||= $rs;
        $changed = 1;

        my $qrs = $self->{'db'}->doQuery( 'dummy', @sql );
        unless ( ref $qrs eq 'HASH' ) {
            error( $qrs );
            return 1;
        }
    }

    if ( $changed ) {
        $ret ||= $self->_syncKeyTables();
        $ret ||= $self->_reloadOpendkim();
    }

    $ret;
}

=back

=head1 PRIVATE METHODS

=over 4

=item _init( )

 Initialize plugin

 Return Plugin::SGW_PostfixAuth

=cut

sub _init
{
    my ( $self ) = @_;

    $self->{'db'} = iMSCP::Database->factory();

    $self->{'confDir'} = $self->{'config'}->{'opendkim_conf_dir'} || '/etc/opendkim';
    $self->{'keysDir'} = "$self->{'confDir'}/keys";
    $self->{'keyTable'} = "$self->{'confDir'}/KeyTable";
    $self->{'signingTable'} = "$self->{'confDir'}/SigningTable";
    $self->{'trustedHosts'} = "$self->{'confDir'}/TrustedHosts";

    my $host = $self->{'config'}->{'milter_host'} || '127.0.0.1';
    my $port = $self->{'config'}->{'milter_port'} || 8891;
    # Postfix and opendkim spell the same socket differently.
    $self->{'milter'} = "inet:$host:$port";
    $self->{'opendkimSocket'} = "inet:$port\@$host";

    $self->{'keySize'} = $self->{'config'}->{'default_key_size'} || 2048;
    $self->{'ttl'} = $self->{'config'}->{'dns_ttl'} || 3600;

    $self;
}

=item _writeZone( \%row )

 Bring one zone's key, key files and DNS records into line with its settings

 Return int 0 on success, other on failure

=cut

sub _writeZone
{
    my ( $self, $row ) = @_;

    if ( $row->{'dkim_enabled'} ) {
        my $key = $self->_activeKey( $row ) || $self->_createKey( $row );
        return 1 unless $key;

        my $rs = $self->_writeKeyFile( $row, $key );
        return $rs if $rs;
    } else {
        # The key material goes, but the row in postfix_auth_key stays: a
        # customer who turns DKIM off and on again in the same afternoon
        # should not have to republish a new public key.
        my $rs = $self->_removeKeyFiles( $row );
        return $rs if $rs;
    }

    my $records = $self->_desiredRecords( $row );

    # Refused rather than published. An over-limit SPF record is a permerror,
    # not a partially applied policy: receivers stop evaluating it altogether,
    # so publishing one would quietly turn SPF off for the domain.
    for my $record ( @{ $records } ) {
        next unless $record->{'kind'} eq 'spf';

        my $lookups = $self->spfLookupCount( $record->{'rdata'} );
        next if $lookups <= 10;

        error( sprintf(
            'The SPF record for %s needs %d DNS lookups and the limit is 10; it has not been published.',
            $row->{'domain_name'}, $lookups
        ));
        return 1;
    }

    my $rs = $self->_storeRecords( $row, $records );
    $rs ||= $self->_syncDns( $row, $records );
    $rs;
}

=item _storeRecords( \%row, \@records )

 Remember what was composed for the zone, so that the panel can show it.

 Stored whether or not the zone publishes its own DNS: for a zone served by
 somebody else's nameservers this is the only place the customer can read the
 records they have to publish by hand.

 Return int 0 on success, other on failure

=cut

sub _storeRecords
{
    my ( $self, $row, $records ) = @_;

    my %byKind = map { $_->{'kind'} => $_->{'rdata'} } @{ $records };

    my $qrs = $self->{'db'}->doQuery(
        'u',
        '
            UPDATE postfix_auth
            SET dkim_record = ?, spf_record = ?, dmarc_record = ?
            WHERE postfix_auth_id = ?
        ',
        $byKind{'dkim'}, $byKind{'spf'}, $byKind{'dmarc'},
        $row->{'postfix_auth_id'}
    );
    unless ( ref $qrs eq 'HASH' ) {
        error( $qrs );
        return 1;
    }

    0;
}

=item _removeZone( \%row [, $keepKeyRows = false ] )

 Withdraw a zone's key material and DNS records

 Param bool $keepKeyRows Keep the rows in postfix_auth_key, so that re-enabling
  the plugin republishes the same public key rather than a new one.
 Return int 0 on success, other on failure

=cut

sub _removeZone
{
    my ( $self, $row, $keepKeyRows ) = @_;

    my $rs = $self->_removeKeyFiles( $row );
    $rs ||= $self->_storeRecords( $row, [] );
    $rs ||= $self->_syncDns( $row, [] );
    return $rs if $rs;

    unless ( $keepKeyRows ) {
        my $qrs = $self->{'db'}->doQuery(
            'd', 'DELETE FROM postfix_auth_key WHERE postfix_auth_id = ?',
            $row->{'postfix_auth_id'}
        );
        unless ( ref $qrs eq 'HASH' ) {
            error( $qrs );
            return 1;
        }
    }

    0;
}

=item _activeKey( \%row )

 Return hashref of the zone's active DKIM key, or undef if it has none

=cut

sub _activeKey
{
    my ( $self, $row ) = @_;

    my $keys = $self->{'db'}->doQuery(
        'postfix_auth_key_id',
        'SELECT * FROM postfix_auth_key WHERE postfix_auth_id = ? AND retired_at = 0',
        $row->{'postfix_auth_id'}
    );
    unless ( ref $keys eq 'HASH' ) {
        error( $keys );
        return undef;
    }

    return undef unless %{ $keys };

    # A zone has one active key. If a botched rotation ever left two, the
    # newest is the one being signed with.
    ( sort { $b->{'created_at'} <=> $a->{'created_at'} } values %{ $keys } )[0];
}

=item _createKey( \%row )

 Generate and store a DKIM key pair for a zone

 Return hashref of the new key, or undef on failure

=cut

sub _createKey
{
    my ( $self, $row ) = @_;

    my $size = $row->{'dkim_key_size'} || $self->{'keySize'};
    my $selector = $self->_freeSelector( $row );
    return undef unless defined $selector;

    my ( $private, $public ) = $self->_generateKeyPair( $size );
    return undef unless defined $private;

    my $qrs = $self->{'db'}->doQuery(
        'i',
        '
            INSERT INTO postfix_auth_key (
                postfix_auth_id, selector, key_size, private_key, public_key,
                created_at, retired_at
            ) VALUES (?, ?, ?, ?, ?, ?, 0)
        ',
        $row->{'postfix_auth_id'}, $selector, $size, $private, $public, time()
    );
    unless ( ref $qrs eq 'HASH' ) {
        error( $qrs );
        return undef;
    }

    {
        selector    => $selector,
        key_size    => $size,
        private_key => $private,
        public_key  => $public
    };
}

=item _freeSelector( \%row )

 Pick a selector for a new key.

 Date-shaped, so that an operator reading a signature can tell at a glance how
 old the key is, with a suffix if that selector is already taken - which is
 what happens when a customer regenerates a key in the same month.

 Return string selector, or undef on failure

=cut

sub _freeSelector
{
    my ( $self, $row ) = @_;

    my $taken = $self->{'db'}->doQuery(
        'selector',
        'SELECT selector FROM postfix_auth_key WHERE postfix_auth_id = ?',
        $row->{'postfix_auth_id'}
    );
    unless ( ref $taken eq 'HASH' ) {
        error( $taken );
        return undef;
    }

    my ( undef, undef, undef, undef, $mon, $year ) = localtime( time());
    my $base = sprintf( '%04d%02d', $year+1900, $mon+1 );

    return $base unless exists $taken->{$base};

    for my $n ( 2 .. 99 ) {
        my $candidate = "$base-$n";
        return $candidate unless exists $taken->{$candidate};
    }

    error( sprintf( "Couldn't find a free DKIM selector for %s", $row->{'domain_name'} ));
    undef;
}

=item _generateKeyPair( $size )

 Generate an RSA key pair

 Return list ( private PEM, public key base64 ), or an empty list on failure

=cut

sub _generateKeyPair
{
    my ( $self, $size ) = @_;

    my $tmp = File::Temp->new( UNLINK => 1 );
    $tmp->close();

    my $rs = execute(
        [ 'openssl', 'genrsa', '-out', $tmp->filename(), $size ],
        \my $stdout, \my $stderr
    );
    debug( $stdout ) if length $stdout;
    if ( $rs ) {
        error( sprintf( "Couldn't generate a %d bit DKIM key: %s", $size, $stderr || 'unknown error' ));
        return ();
    }

    my $private = iMSCP::File->new( filename => $tmp->filename())->get();
    unless ( defined $private ) {
        error( "Couldn't read back the generated DKIM key" );
        return ();
    }

    $rs = execute(
        [ 'openssl', 'rsa', '-in', $tmp->filename(), '-pubout' ],
        \my $pem, \$stderr
    );
    if ( $rs ) {
        error( sprintf( "Couldn't derive the DKIM public key: %s", $stderr || 'unknown error' ));
        return ();
    }

    # The DNS record carries the base64 body only, with the PEM banner lines
    # and every line break taken out.
    ( my $public = $pem ) =~ s/-----[^\n]*-----//g;
    $public =~ s/\s+//g;

    unless ( length $public ) {
        error( 'The derived DKIM public key was empty' );
        return ();
    }

    ( $private, $public );
}

=item _writeKeyFile( \%row, \%key )

 Install a zone's private key where opendkim can read it

 Return int 0 on success, other on failure

=cut

sub _writeKeyFile
{
    my ( $self, $row, $key ) = @_;

    my $dir = "$self->{'keysDir'}/$row->{'domain_name'}";

    eval {
        # Rebuilt rather than added to: the zone signs with exactly one key, so
        # anything else in here is a key that has been replaced, and leaving a
        # retired private key on disk serves no purpose.
        iMSCP::Dir->new( dirname => $dir )->remove() if -d $dir;
        iMSCP::Dir->new( dirname => $dir )->make( {
            mode => 0750, user => 'opendkim', group => 'opendkim'
        } );
    };
    if ( $@ ) {
        error( sprintf( "Couldn't create %s: %s", $dir, $@ ));
        return 1;
    }

    my $file = iMSCP::File->new( filename => "$dir/$key->{'selector'}.private" );
    $file->set( $key->{'private_key'} );
    my $rs = $file->save();
    $rs ||= $file->mode( 0600 );
    $rs ||= $file->owner( 'opendkim', 'opendkim' );
    $rs;
}

=item _removeKeyFiles( \%row )

 Remove a zone's key directory

 Return int 0 on success, other on failure

=cut

sub _removeKeyFiles
{
    my ( $self, $row ) = @_;

    my $dir = "$self->{'keysDir'}/$row->{'domain_name'}";
    return 0 unless -d $dir;

    eval { iMSCP::Dir->new( dirname => $dir )->remove(); };
    if ( $@ ) {
        error( sprintf( "Couldn't remove %s: %s", $dir, $@ ));
        return 1;
    }

    0;
}

=item _syncKeyTables( )

 Regenerate KeyTable and SigningTable from the database

 Both files are written in full every time rather than edited, so that they
 cannot drift from what the database says.

 Return int 0 on success, other on failure

=cut

sub _syncKeyTables
{
    my ( $self ) = @_;

    my $rows = $self->{'db'}->doQuery(
        'postfix_auth_id',
        "
            SELECT z.postfix_auth_id, z.domain_name, k.selector
            FROM postfix_auth AS z
            JOIN postfix_auth_key AS k
                ON k.postfix_auth_id = z.postfix_auth_id AND k.retired_at = 0
            WHERE z.dkim_enabled = 1 AND z.status NOT IN('todisable', 'todelete', 'disabled')
        "
    );
    unless ( ref $rows eq 'HASH' ) {
        error( $rows );
        return 1;
    }

    my ( $keyTable, $signingTable ) = ( '', '' );

    for my $row ( sort { $a->{'domain_name'} cmp $b->{'domain_name'} } values %{ $rows } ) {
        my $zone = $row->{'domain_name'};
        my $selector = $row->{'selector'};

        $keyTable .= sprintf(
            "%s %s:%s:%s/%s/%s.private\n",
            $zone, $zone, $selector, $self->{'keysDir'}, $zone, $selector
        );

        # Mail from a subdomain is signed with the parent zone's key, so the
        # signature carries d=<zone> while the From: header says
        # user@sub.zone. That is aligned for DMARC under relaxed alignment,
        # which is the default; the panel warns before a customer selects
        # strict alignment on a zone that has mail-enabled subdomains.
        $signingTable .= "*\@$zone $zone\n*\@*.$zone $zone\n";
    }

    my $rs = $self->_writeConfFile( $self->{'keyTable'}, $keyTable );
    $rs ||= $self->_writeConfFile( $self->{'signingTable'}, $signingTable );
    $rs;
}

=item _syncDns( \%row, \@records )

 Bring the zone's plugin-owned DNS records into line with its settings.

 Declarative rather than incremental: the desired set is compared against the
 records this plugin already owns for the zone, and the difference is queued.
 Nothing is tracked between runs, so a half-applied change from an earlier
 failure heals itself on the next pass.

 Return int 0 on success, other on failure

=cut

sub _syncDns
{
    my ( $self, $row, $records ) = @_;

    # A zone whose DNS is served elsewhere gets nothing written here; the panel
    # shows the customer what to publish by hand instead.
    my @desired = $row->{'publish_dns'} ? @{ $records } : ();

    my ( $domainId, $aliasId ) = $row->{'domain_type'} eq 'als'
        ? ( $row->{'main_domain_id'}, $row->{'domain_id'} )
        : ( $row->{'domain_id'}, 0 );

    # Every TXT record in the zone, not only the ones this plugin owns. The
    # unique key on domain_dns covers the record itself and not its owner, so
    # an identical record belonging to someone else - a customer who added
    # their own SPF record by hand, say - would turn an insert here into a
    # duplicate key error and leave the zone stuck reporting a raw DBI message.
    my $existing = $self->{'db'}->doQuery(
        'domain_dns_id',
        "
            SELECT domain_dns_id, domain_dns, domain_text, domain_dns_status, owned_by
            FROM domain_dns
            WHERE domain_id = ? AND alias_id = ? AND domain_type = 'TXT'
        ",
        $domainId, $aliasId
    );
    unless ( ref $existing eq 'HASH' ) {
        error( $existing );
        return 1;
    }

    my %want = map { $self->_recordKey( $_->{'name'}, $_->{'rdata'} ) => $_ } @desired;
    my %have;

    for my $rec ( values %{ $existing } ) {
        # domain_dns holds "<name>\t<ttl>"; only the name identifies a record.
        my ( $name ) = split /\t/, $rec->{'domain_dns'}, 2;
        $have{ $self->_recordKey( $name, $rec->{'domain_text'} ) } = $rec;
    }

    # Withdraw what is no longer wanted. Only ever our own rows: a record the
    # customer added is theirs to remove.
    for my $key ( keys %have ) {
        my $rec = $have{$key};

        next if exists $want{$key};
        next unless $rec->{'owned_by'} eq DNS_OWNER;
        next if $rec->{'domain_dns_status'} eq 'todelete';

        my $qrs = $self->{'db'}->doQuery(
            'u',
            "UPDATE domain_dns SET domain_dns_status = 'todelete' WHERE domain_dns_id = ?",
            $rec->{'domain_dns_id'}
        );
        unless ( ref $qrs eq 'HASH' ) {
            error( $qrs );
            return 1;
        }
    }

    for my $key ( keys %want ) {
        my $rec = $want{$key};
        my $found = $have{$key};

        if ( $found ) {
            # An identical record is already there. If it is one of ours on its
            # way out - a disable and a re-enable inside the same pass, before
            # Modules::CustomDNS has had a chance to remove it - bring it back
            # rather than inserting a second copy the unique key would refuse.
            next unless $found->{'owned_by'} eq DNS_OWNER
                && $found->{'domain_dns_status'} eq 'todelete';

            my $qrs = $self->{'db'}->doQuery(
                'u',
                "UPDATE domain_dns SET domain_dns_status = 'toadd' WHERE domain_dns_id = ?",
                $found->{'domain_dns_id'}
            );
            unless ( ref $qrs eq 'HASH' ) {
                error( $qrs );
                return 1;
            }

            next;
        }

        my $qrs = $self->{'db'}->doQuery(
            'i',
            "
                INSERT INTO domain_dns (
                    domain_id, alias_id, domain_dns, domain_class, domain_type,
                    domain_text, owned_by, domain_dns_status
                ) VALUES (?, ?, ?, 'IN', 'TXT', ?, ?, 'toadd')
            ",
            $domainId, $aliasId, "$rec->{'name'}\t$self->{'ttl'}",
            $rec->{'rdata'}, DNS_OWNER
        );
        unless ( ref $qrs eq 'HASH' ) {
            error( $qrs );
            return 1;
        }
    }

    0;
}

=item _recordKey( $name, $rdata )

 Identity of a DNS record for comparison purposes

 Return string

=cut

sub _recordKey
{
    my ( undef, $name, $rdata ) = @_;

    # The stored RDATA has been through Modules::CustomDNS, which quotes it and
    # may have split it into several <character-string>s. Compare on the text
    # itself so that a record already published is not queued a second time.
    ( my $normalised = $rdata ) =~ s/"\s*"//g;
    $normalised =~ s/^"|"$//g;
    $normalised =~ s/\s+/ /g;
    $normalised =~ s/^\s+|\s+$//g;

    lc( $name ) . "\0" . $normalised;
}

=item _desiredRecords( \%row )

 The DNS records a zone's settings call for, whether or not it publishes its
 own DNS.

 Return arrayref of { kind, name, rdata }

=cut

sub _desiredRecords
{
    my ( $self, $row ) = @_;

    my $zone = $row->{'domain_name'};
    my @records;

    if ( $row->{'dkim_enabled'} ) {
        my $key = $self->_activeKey( $row );
        if ( $key ) {
            push @records, {
                kind  => 'dkim',
                name  => "$key->{'selector'}._domainkey.$zone.",
                rdata => $self->buildDkimRecord( $key->{'public_key'} )
            };
        }
    }

    if ( my $spf = $self->buildSpfRecord( $row ) ) {
        push @records, { kind => 'spf', name => "$zone.", rdata => $spf };
    }

    if ( my $dmarc = $self->buildDmarcRecord( $row ) ) {
        push @records, { kind => 'dmarc', name => "_dmarc.$zone.", rdata => $dmarc };
    }

    \@records;
}

=item buildDkimRecord( $publicKey )

 Build the RDATA of a DKIM public key record

 Return string

=cut

sub buildDkimRecord
{
    my ( undef, $publicKey ) = @_;

    "v=DKIM1; h=sha256; k=rsa; p=$publicKey";
}

=item buildSpfRecord( \%row )

 Build the RDATA of a zone's SPF record, or undef when the zone keeps i-MSCP's
 own hard-coded record.

 Return string or undef

=cut

sub buildSpfRecord
{
    my ( $self, $row ) = @_;

    return undef if $row->{'spf_mode'} eq 'off';

    if ( $row->{'spf_mode'} eq 'raw' ) {
        my $raw = _trim( $row->{'spf_raw'} );
        return length $raw ? $raw : undef;
    }

    my @terms = ( 'v=spf1' );
    push @terms, 'a' if $row->{'spf_a'};
    push @terms, 'mx' if $row->{'spf_mx'};

    for my $host ( _splitList( $row->{'spf_hosts'} ) ) {
        # A bare address is the common case and the one a customer is most
        # likely to type, so infer the mechanism from its shape; anything
        # already carrying a mechanism is passed through untouched.
        #
        # Matched against the named mechanisms rather than "word, then colon":
        # an IPv6 address is full of colons and would otherwise look like a
        # mechanism it has no prefix for.
        push @terms, ( $host =~ /^[+\-~?]?(?:ip4|ip6|a|mx|include|exists|ptr|redirect|exp)[:=]/i )
            ? $host
            : ( ( index( $host, ':' ) != -1 ) ? "ip6:$host" : "ip4:$host" );
    }

    for my $include ( _splitList( $row->{'spf_includes'} ) ) {
        push @terms, ( $include =~ /^include:/i ) ? $include : "include:$include";
    }

    my $redirect = _trim( $row->{'spf_redirect'} );

    if ( length $redirect ) {
        # RFC 7208 s6.1: a redirect modifier is ignored when the record also
        # has an "all" mechanism, so emitting both would silently drop the
        # redirect the customer asked for.
        push @terms, ( $redirect =~ /^redirect=/i ) ? $redirect : "redirect=$redirect";
    } else {
        push @terms, $row->{'spf_qualifier'} || '-all';
    }

    join ' ', @terms;
}

=item spfLookupCount( $record )

 How many DNS lookups an SPF record costs.

 RFC 7208 s4.6.4 caps this at ten. The cap is not a soft one: a record over it
 is a permerror, which a receiver treats as no usable SPF policy at all.

 Return int

=cut

sub spfLookupCount
{
    my ( undef, $record ) = @_;

    my $count = 0;

    for my $term ( split /\s+/, ( $record // '' ) ) {
        $count++ if $term =~ /^[+\-~?]?(?:include|a|mx|ptr|exists|redirect)(?:[:=]|$)/i;
    }

    $count;
}

=item buildDmarcRecord( \%row )

 Build the RDATA of a zone's DMARC record, or undef when it has none

 Return string or undef

=cut

sub buildDmarcRecord
{
    my ( undef, $row ) = @_;

    return undef unless $row->{'dmarc_enabled'};

    # v and p must come first, in that order; everything after is optional and
    # omitted when it matches the RFC default, to keep the record readable.
    my @tags = ( 'v=DMARC1', "p=$row->{'dmarc_p'}" );

    push @tags, "sp=$row->{'dmarc_sp'}" if length( $row->{'dmarc_sp'} || '' );

    my $rua = _trim( $row->{'dmarc_rua'} );
    my $ruf = _trim( $row->{'dmarc_ruf'} );
    push @tags, 'rua=' . _mailtoList( $rua ) if length $rua;
    push @tags, 'ruf=' . _mailtoList( $ruf ) if length $ruf;

    push @tags, "adkim=$row->{'dmarc_adkim'}" if ( $row->{'dmarc_adkim'} || 'r' ) ne 'r';
    push @tags, "aspf=$row->{'dmarc_aspf'}" if ( $row->{'dmarc_aspf'} || 'r' ) ne 'r';
    push @tags, "pct=$row->{'dmarc_pct'}" if ( $row->{'dmarc_pct'} // 100 ) != 100;
    push @tags, "fo=$row->{'dmarc_fo'}" if ( $row->{'dmarc_fo'} || '0' ) ne '0';
    push @tags, "ri=$row->{'dmarc_ri'}" if ( $row->{'dmarc_ri'} // 86400 ) != 86400;

    join '; ', @tags;
}

=item _mailtoList( $addresses )

 Turn a comma separated list of report addresses into DMARC URIs

 Return string

=cut

sub _mailtoList
{
    my ( $addresses ) = @_;

    join ',', map { /^[a-z][a-z0-9+.-]*:/i ? $_ : "mailto:$_" }
        grep { length } map { _trim( $_ ) } split /,/, $addresses;
}

=item _writeOpendkimConf( )

 Write opendkim.conf and its trusted host list

 Return int 0 on success, other on failure

=cut

sub _writeOpendkimConf
{
    my ( $self ) = @_;

    eval {
        iMSCP::Dir->new( dirname => $self->{'confDir'} )->make( { mode => 0755 } );
        iMSCP::Dir->new( dirname => $self->{'keysDir'} )->make( {
            mode => 0750, user => 'opendkim', group => 'opendkim'
        } );
    };
    if ( $@ ) {
        error( sprintf( "Couldn't create %s: %s", $self->{'confDir'}, $@ ));
        return 1;
    }

    my $rs = $self->_writeConfFile( $self->{'trustedHosts'}, <<'EOF' );
# Hosts whose mail this server signs rather than verifies.
#
# Generated by the i-MSCP SGW_PostfixAuth plugin; edits are lost on update.
127.0.0.1
::1
localhost
EOF
    return $rs if $rs;

    $self->_writeConfFile( OPENDKIM_CONF, <<"EOF" );
# OPENDKIM(8) configuration file
#     Generated by the i-MSCP SGW_PostfixAuth plugin.
#     DO NOT EDIT THIS FILE BY HAND -- YOUR CHANGES WILL BE OVERWRITTEN

Syslog                  yes
SyslogSuccess           yes
UMask                   007
UserID                  opendkim

# A TCP socket, not a unix one: i-MSCP runs smtpd and cleanup chrooted, and a
# socket under /run is not reachable from inside that chroot.
Socket                  $self->{'opendkimSocket'}
PidFile                 /run/opendkim/opendkim.pid

# Sign and verify. Verification is annotation only - every On-* action is left
# at its permissive default - so no mail is ever refused on our account.
Mode                    sv
Canonicalization        relaxed/simple
OversignHeaders         From

KeyTable                $self->{'keyTable'}
SigningTable            refile:$self->{'signingTable'}
InternalHosts           $self->{'trustedHosts'}

# Sign a message that arrived over SMTP only when the sender authenticated.
# Without this, a message reaching port 25 from anywhere on the internet with
# a forged From: in one of our own domains would be signed by us.
MacroList               {auth_authen}

TrustAnchorFile         /usr/share/dns/root.key
EOF
}

=item _writeConfFile( $path, $content )

 Write a configuration file, root owned and world readable

 Return int 0 on success, other on failure

=cut

sub _writeConfFile
{
    my ( undef, $path, $content ) = @_;

    my $file = iMSCP::File->new( filename => $path );
    $file->set( $content );
    my $rs = $file->save();
    $rs ||= $file->mode( 0644 );
    $rs ||= $file->owner( 'root', 'root' );
    $rs;
}

=item _installPackages( )

 Install the packages this plugin depends on

 The i-MSCP installer is not running when a plugin is installed from the panel,
 so the beforeInstallPackages listener registered by registerSetupListeners()
 is not enough on its own.

 Return int 0 on success, other on failure

=cut

sub _installPackages
{
    my ( $self ) = @_;

    return 0 if -x '/usr/sbin/opendkim' && -x '/usr/bin/opendkim-genkey';

    my $rs = execute(
        [ 'apt-get', '--assume-yes', '--no-install-recommends', 'install',
            'opendkim', 'opendkim-tools' ],
        \my $stdout, \my $stderr
    );
    debug( $stdout ) if length $stdout;
    if ( $rs ) {
        error( sprintf( "Couldn't install opendkim: %s", $stderr || 'unknown error' ));
        return $rs;
    }

    0;
}

=item _checkRequirements( )

 Check that what this plugin needs is present

 Return int 0 if all requirements are met, other otherwise

=cut

sub _checkRequirements
{
    my ( $self ) = @_;

    my $ret = 0;

    unless ( -x '/usr/sbin/opendkim' ) {
        error( 'opendkim was not found; install the opendkim package' );
        $ret ||= 1;
    }

    unless ( getpwnam( 'opendkim' ) ) {
        error( 'The opendkim system user does not exist' );
        $ret ||= 1;
    }

    unless ( -x '/usr/bin/openssl' ) {
        error( 'openssl was not found; install the openssl package' );
        $ret ||= 1;
    }

    $ret;
}

=item _startOpendkim( ), _reloadOpendkim( ), _stopOpendkim( )

 Service control. Starting also enables the unit, so that signing survives a
 reboot; stopping also disables it.

 Return int 0 on success, other on failure

=cut

sub _startOpendkim
{
    my ( $self ) = @_;

    eval {
        my $service = iMSCP::Service->getInstance();
        $service->enable( 'opendkim' );
        $service->restart( 'opendkim' );
    };
    if ( $@ ) {
        error( sprintf( "Couldn't start opendkim: %s", $@ ));
        return 1;
    }

    0;
}

sub _reloadOpendkim
{
    my ( $self ) = @_;

    # Nothing to reload if the plugin has been disabled and the daemon stopped.
    return 0 unless -f STATE_FILE;

    eval { iMSCP::Service->getInstance()->restart( 'opendkim' ); };
    if ( $@ ) {
        error( sprintf( "Couldn't restart opendkim: %s", $@ ));
        return 1;
    }

    0;
}

sub _stopOpendkim
{
    my ( $self ) = @_;

    eval {
        my $service = iMSCP::Service->getInstance();
        $service->stop( 'opendkim' );
        $service->disable( 'opendkim' );
    };
    if ( $@ ) {
        # Not fatal: the daemon may already be gone, and Postfix has by this
        # point already stopped pointing at it.
        debug( sprintf( "Couldn't stop opendkim: %s", $@ ));
    }

    0;
}

=item _reloadMta( )

 Reload Postfix

 Return int 0 on success, other on failure

=cut

sub _reloadMta
{
    my ( $self ) = @_;

    my $rs = Servers::mta->factory()->reload();
    return $rs if $rs;

    0;
}

=item _writeState( ), _readState( ), _removeState( )

 The milter spec that registerSetupListeners() reads. See STATE_FILE.

=cut

sub _writeState
{
    my ( $self ) = @_;

    my $file = iMSCP::File->new( filename => STATE_FILE );
    $file->set( <<"EOF" );
# Written by the i-MSCP SGW_PostfixAuth plugin.
#
# Read during an i-MSCP installer run to decide what to add to smtpd_milters.
# Its absence means the plugin is disabled and Postfix should be left alone.
milter = $self->{'milter'}
EOF
    my $rs = $file->save();
    $rs ||= $file->mode( 0644 );
    $rs;
}

sub _readState
{
    return undef unless -f STATE_FILE;

    my $content = iMSCP::File->new( filename => STATE_FILE )->get();
    return undef unless defined $content;

    return $1 if $content =~ /^\s*milter\s*=\s*(\S+)\s*$/m;

    error( sprintf( '%s carries no milter setting', STATE_FILE ));
    undef;
}

sub _removeState
{
    return 0 unless -f STATE_FILE;

    iMSCP::File->new( filename => STATE_FILE )->delFile();
}

=item _postconfApply( $milter ), _postconfRemove( $milter )

 Point Postfix at the milter, or stop pointing at it.

 'add' rather than 'replace' for the milter lists, so that a third-party
 listener which has put its own milter there keeps it.

 Return int 0 on success, other on failure

=cut

sub _postconfApply
{
    my ( $milter ) = @_;

    Servers::mta->factory()->postconf(
        smtpd_milters         => { action => 'add', values => [ $milter ] },
        non_smtpd_milters     => { action => 'add', values => [ $milter ] },
        milter_protocol       => { action => 'replace', values => [ '6' ] },
        # Postfix's own default here is 'shutdown', which turns a stopped
        # milter into a total mail outage. Nothing this plugin offers is worth
        # that, so a milter that cannot be reached is passed by instead.
        milter_default_action => { action => 'replace', values => [ 'accept' ] }
    );
}

sub _postconfRemove
{
    my ( $milter ) = @_;

    my $rs = Servers::mta->factory()->postconf(
        smtpd_milters     => { action => 'remove', values => [ $milter ] },
        non_smtpd_milters => { action => 'remove', values => [ $milter ] }
    );
    return $rs if $rs;

    # The milter-wide settings are ours only for as long as we are the reason
    # there is a milter at all. Leave them in place if something else is still
    # using one.
    return 0 if _hasMilters();

    Servers::mta->factory()->postconf(
        milter_protocol       => { action => 'remove', values => [ qr/.*/ ] },
        milter_default_action => { action => 'remove', values => [ qr/.*/ ] }
    );
}

=item _hasMilters( )

 Is Postfix still configured with any milter at all?

 Return bool

=cut

sub _hasMilters
{
    for my $param ( qw/ smtpd_milters non_smtpd_milters / ) {
        my $rs = execute( [ 'postconf', '-h', $param ], \my $stdout, \my $stderr );
        if ( $rs ) {
            # Unreadable rather than empty: say yes, so that a setting is left
            # alone rather than removed on a guess.
            error( $stderr ) if length $stderr;
            return 1;
        }

        $stdout //= '';
        $stdout =~ s/^\s+|\s+$//g;
        return 1 if length $stdout;
    }

    0;
}

=item _splitList( $text ), _trim( $text )

 Split a newline or comma separated customer supplied list into trimmed
 entries, and trim a single value.

=cut

sub _splitList
{
    my ( $text ) = @_;

    return () unless defined $text && $text ne '';

    grep { length } map { s/^\s+|\s+$//gr } split /[\r\n,]+/, $text;
}

sub _trim
{
    my ( $text ) = @_;

    return '' unless defined $text;

    $text =~ s/^\s+|\s+$//gr;
}

=back

=head1 AUTHORS

 Cambell Prince <cambell.prince@gmail.com>

=cut

1;
__END__
