######################################################################
# Test suite for OAuth::Cmdline cache layer hardening
######################################################################
use warnings;
use strict;
use Test::More;
use File::Temp qw( tempdir );
use YAML qw( DumpFile );
use OAuth::Cmdline;

my $tmpdir = tempdir( CLEANUP => 1 );

# -- cache_read: missing file
{
    my $oauth = OAuth::Cmdline->new(
        site    => "test-cache",
        homedir => "$tmpdir/nonexistent",
    );

    eval { $oauth->cache_read() };
    like $@, qr/not found/, "cache_read dies on missing file";
}

# -- cache_read: corrupted YAML (not a hash)
{
    my $cache_file = "$tmpdir/.test-corrupt.yml";
    open my $fh, '>', $cache_file or die "Cannot write $cache_file: $!";
    print $fh "- just\n- a\n- list\n";
    close $fh;

    my $oauth = OAuth::Cmdline->new(
        site    => "test-corrupt",
        homedir => $tmpdir,
    );

    eval { $oauth->cache_read() };
    like $@, qr/corrupted/, "cache_read dies on non-hash YAML";
}

# -- cache_read: empty file
{
    my $cache_file = "$tmpdir/.test-empty.yml";
    open my $fh, '>', $cache_file or die "Cannot write $cache_file: $!";
    close $fh;

    my $oauth = OAuth::Cmdline->new(
        site    => "test-empty",
        homedir => $tmpdir,
    );

    eval { $oauth->cache_read() };
    like $@, qr/corrupted|Failed to read/,
      "cache_read dies on empty file";
}

# -- cache_read: valid YAML hash
{
    my $cache_file = "$tmpdir/.test-valid.yml";
    DumpFile( $cache_file, { access_token => "tok123", expires => time() + 3600 } );

    my $oauth = OAuth::Cmdline->new(
        site    => "test-valid",
        homedir => $tmpdir,
    );

    my $data = $oauth->cache_read();
    is ref $data,            "HASH",   "cache_read returns a hashref";
    is $data->{access_token}, "tok123", "cache_read preserves data";
}

# -- cache_write: writes with restricted permissions
{
    my $oauth = OAuth::Cmdline->new(
        site    => "test-write",
        homedir => $tmpdir,
    );

    my $cache = {
        access_token => "abc",
        expires      => time() + 3600,
    };

    ok $oauth->cache_write($cache), "cache_write returns true";
    ok -f $oauth->cache_file_path,  "cache file created";

    my $mode = ( stat $oauth->cache_file_path )[2] & 07777;
    is sprintf( "%04o", $mode ), "0600",
      "cache file has restricted permissions (0600)";

    my $read_back = $oauth->cache_read();
    is $read_back->{access_token}, "abc", "round-trip preserves data";
}

# -- cache_write: umask restored on failure
{
    my $oauth = OAuth::Cmdline->new(
        site    => "test-umask",
        homedir => "$tmpdir/no-such-dir",
    );

    my $before_umask = umask();

    eval {
        $oauth->cache_write( { access_token => "x" } );
    };

    my $after_umask = umask();
    is $after_umask, $before_umask,
      "umask restored after cache_write failure";
    like $@, qr/Failed to write/,
      "cache_write dies with descriptive error on failure";
}

done_testing;
