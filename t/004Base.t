######################################################################
# Test suite for OAuth::Cmdline base class
######################################################################
use warnings;
use strict;
use Test2::Bundle::Extended;
use Test2::Plugin::NoWarnings;
use File::Temp qw( tempdir );
use OAuth::Cmdline;

# Test default attribute values
{
    my $oauth = OAuth::Cmdline->new( site => "test-site" );

    is $oauth->site,       "test-site",            "site attribute";
    is $oauth->local_uri,  "http://localhost:8082", "default local_uri";
    is $oauth->ua_timeout, 30,                      "default ua_timeout is 30s";

    like $oauth->redirect_uri, qr{/callback$}, "redirect_uri ends with /callback";
    like $oauth->cache_file_path, qr{/\.test-site\.yml$},
      "cache_file_path based on site";
}

# Test ua_timeout can be customized
{
    my $oauth = OAuth::Cmdline->new( site => "t", ua_timeout => 60 );
    is $oauth->ua_timeout, 60, "custom ua_timeout";

    $oauth->ua_timeout(0);
    is $oauth->ua_timeout, 0, "ua_timeout can be set to 0";
}

# Test cache_write and cache_read roundtrip
{
    my $dir   = tempdir( CLEANUP => 1 );
    my $oauth = OAuth::Cmdline->new( site => "roundtrip", homedir => $dir );

    my $cache = {
        access_token  => "test_access",
        refresh_token => "test_refresh",
        client_id     => "test_id",
        client_secret => "test_secret",
        expires       => time() + 3600,
        token_uri     => "https://example.com/token",
    };

    $oauth->cache_write($cache);
    ok -f $oauth->cache_file_path, "cache file created";

    # Verify restrictive permissions (owner read/write only)
    my $mode = ( stat $oauth->cache_file_path )[2] & 07777;
    is $mode, 0600, "cache file has restrictive permissions";

    my $loaded = $oauth->cache_read();
    is $loaded->{access_token},  "test_access",  "access_token roundtrip";
    is $loaded->{refresh_token}, "test_refresh",  "refresh_token roundtrip";
    is $loaded->{client_id},     "test_id",       "client_id roundtrip";
    is $loaded->{client_secret}, "test_secret",   "client_secret roundtrip";
    is $loaded->{token_uri}, "https://example.com/token", "token_uri roundtrip";
}

# Test cache_read dies when file missing
{
    my $dir   = tempdir( CLEANUP => 1 );
    my $oauth = OAuth::Cmdline->new( site => "missing", homedir => $dir );

    like dies { $oauth->cache_read() }, qr/Cache file.*not found/,
      "cache_read dies with useful message when file missing";
}

# Test token_expired
{
    my $dir   = tempdir( CLEANUP => 1 );
    my $oauth = OAuth::Cmdline->new( site => "expiry", homedir => $dir );

    # Token expires in 1 hour — not expired
    $oauth->cache_write( { expires => time() + 3600 } );
    is $oauth->token_expired(), 0, "token not expired when 1h remaining";

    # Token expires in 100 seconds — within 300s threshold, so expired
    $oauth->cache_write( { expires => time() + 100 } );
    is $oauth->token_expired(), 1, "token expired when <300s remaining";

    # Token already expired
    $oauth->cache_write( { expires => time() - 60 } );
    is $oauth->token_expired(), 1, "token expired when in the past";
}

# Test token_expire forces expiration
{
    my $dir   = tempdir( CLEANUP => 1 );
    my $oauth = OAuth::Cmdline->new( site => "force", homedir => $dir );

    $oauth->cache_write( { expires => time() + 7200 } );
    is $oauth->token_expired(), 0, "token initially valid";

    $oauth->token_expire();
    is $oauth->token_expired(), 1, "token expired after token_expire()";
}

# Test full_login_uri construction
{
    my $oauth = OAuth::Cmdline->new(
        site      => "t",
        client_id => "my_id",
        login_uri => "https://example.com/auth",
        scope     => "read write",
    );

    my $uri = $oauth->full_login_uri();
    like "$uri", qr{client_id=my_id},     "login URI includes client_id";
    like "$uri", qr{response_type=code},   "login URI includes response_type";
    like "$uri", qr{redirect_uri=},        "login URI includes redirect_uri";
    like "$uri", qr{scope=read},           "login URI includes scope";
}

# Test client_init_conf_check
{
    my $dir   = tempdir( CLEANUP => 1 );
    my $oauth = OAuth::Cmdline->new( site => "initcheck", homedir => $dir );

    # No cache file — should die
    like dies { $oauth->client_init_conf_check("https://example.com") },
      qr/client_id.*client_secret/,
      "client_init_conf_check dies without credentials";

    # Write a cache with credentials
    $oauth->cache_write(
        { client_id => "cid", client_secret => "csec" }
    );

    ok $oauth->client_init_conf_check("https://example.com"),
      "client_init_conf_check succeeds with credentials";
    is $oauth->client_id,     "cid",  "client_id loaded from cache";
    is $oauth->client_secret, "csec", "client_secret loaded from cache";
}

done_testing;
