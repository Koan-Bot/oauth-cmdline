######################################################################
# Unit tests for OAuth::Cmdline base class
######################################################################
use warnings;
use strict;
use Test::More;
use File::Temp qw( tempdir );
use YAML qw( DumpFile LoadFile );
use OAuth::Cmdline;

my $tmpdir = tempdir( CLEANUP => 1 );

# --- Constructor and defaults ---

{
    my $oauth = OAuth::Cmdline->new( site => "test-site", homedir => $tmpdir );
    isa_ok $oauth, "OAuth::Cmdline", "constructor returns correct class";
    is $oauth->site,      "test-site",              "site attribute";
    is $oauth->local_uri, "http://localhost:8082",   "default local_uri";
    is $oauth->homedir,   $tmpdir,                   "homedir attribute";
    ok !defined $oauth->client_id,                   "client_id undef by default";
    ok !defined $oauth->client_secret,               "client_secret undef by default";
    ok !defined $oauth->base_uri,                    "base_uri undef by default";
    ok !defined $oauth->login_uri,                   "login_uri undef by default";
    ok !defined $oauth->scope,                       "scope undef by default";
}

# --- redirect_uri ---

{
    my $oauth = OAuth::Cmdline->new( site => "test", homedir => $tmpdir );
    is $oauth->redirect_uri, "http://localhost:8082/callback", "redirect_uri built from local_uri";

    $oauth->local_uri("http://example.com:9999");
    is $oauth->redirect_uri, "http://example.com:9999/callback", "redirect_uri updates with local_uri";
}

# --- cache_file_path ---

{
    my $oauth = OAuth::Cmdline->new( site => "mysite", homedir => "/home/user" );
    is $oauth->cache_file_path, "/home/user/.mysite.yml", "cache_file_path pattern";
}

# --- cache_write / cache_read round-trip ---

{
    my $oauth = OAuth::Cmdline->new( site => "cachetest", homedir => $tmpdir );
    my $data  = {
        access_token  => "tok_abc123",
        refresh_token => "ref_xyz789",
        client_id     => "cid",
        client_secret => "csec",
        expires       => time() + 3600,
        token_uri     => "https://example.com/token",
    };

    ok $oauth->cache_write($data), "cache_write returns true";
    ok -f $oauth->cache_file_path, "cache file created";

    my $read = $oauth->cache_read();
    is $read->{access_token},  "tok_abc123", "cache round-trip: access_token";
    is $read->{refresh_token}, "ref_xyz789", "cache round-trip: refresh_token";
    is $read->{client_id},     "cid",        "cache round-trip: client_id";
    is $read->{client_secret}, "csec",       "cache round-trip: client_secret";
    is $read->{token_uri},     "https://example.com/token", "cache round-trip: token_uri";
}

# --- cache_read dies on missing file ---

{
    my $oauth = OAuth::Cmdline->new( site => "nonexistent", homedir => $tmpdir );
    eval { $oauth->cache_read() };
    like $@, qr/Cache file.*not found/, "cache_read dies when file missing";
}

# --- cache_write file permissions ---

{
    my $oauth = OAuth::Cmdline->new( site => "permtest", homedir => $tmpdir );
    $oauth->cache_write( { access_token => "x" } );
    my $mode = ( stat( $oauth->cache_file_path ) )[2] & 07777;
    is $mode, 0600, "cache file has restrictive permissions (0600)";
}

# --- token_expired ---

{
    my $oauth = OAuth::Cmdline->new( site => "exptest", homedir => $tmpdir );

    # Token valid for 1 hour
    $oauth->cache_write( { expires => time() + 3600 } );
    ok !$oauth->token_expired(), "token not expired (1h remaining)";

    # Token expires in 299 seconds (below 300s threshold)
    $oauth->cache_write( { expires => time() + 299 } );
    ok $oauth->token_expired(), "token expired (299s remaining, below 300s threshold)";

    # Token expires in exactly 300 seconds (at boundary, < 300 is false)
    $oauth->cache_write( { expires => time() + 300 } );
    ok !$oauth->token_expired(), "token not expired (300s remaining, at strict boundary)";

    # Token expires in 301 seconds (just above threshold)
    $oauth->cache_write( { expires => time() + 301 } );
    ok !$oauth->token_expired(), "token not expired (301s remaining)";

    # Token already expired
    $oauth->cache_write( { expires => time() - 100 } );
    ok $oauth->token_expired(), "token expired (already past)";
}

# --- token_expire ---

{
    my $oauth = OAuth::Cmdline->new( site => "forceexp", homedir => $tmpdir );
    $oauth->cache_write( { expires => time() + 7200 } );
    ok !$oauth->token_expired(), "token initially valid";

    $oauth->token_expire();
    ok $oauth->token_expired(), "token_expire forces expiration";

    my $cache = $oauth->cache_read();
    ok $cache->{expires} < time(), "expires set to past after token_expire";
}

# --- full_login_uri ---

{
    my $oauth = OAuth::Cmdline->new(
        site      => "logintest",
        homedir   => $tmpdir,
        client_id => "my_client_id",
        login_uri => "https://auth.example.com/authorize",
        scope     => "read write",
    );

    my $uri = $oauth->full_login_uri();
    isa_ok $uri, "URI", "full_login_uri returns URI object";

    my $str = "$uri";
    like $str, qr{^https://auth\.example\.com/authorize\?}, "base URI correct";
    like $str, qr{client_id=my_client_id},                  "client_id in query";
    like $str, qr{response_type=code},                       "response_type=code";
    like $str, qr{redirect_uri=},                            "redirect_uri present";
    like $str, qr{scope=read},                               "scope present";
}

# --- full_login_uri without access_type ---

{
    my $oauth = OAuth::Cmdline->new(
        site      => "noaccess",
        homedir   => $tmpdir,
        client_id => "cid",
        login_uri => "https://auth.example.com/auth",
        scope     => "basic",
    );
    my $str = $oauth->full_login_uri() . "";
    unlike $str, qr{access_type=}, "no access_type when not set";
}

# --- full_login_uri with access_type ---

{
    my $oauth = OAuth::Cmdline->new(
        site        => "withaccess",
        homedir     => $tmpdir,
        client_id   => "cid",
        login_uri   => "https://auth.example.com/auth",
        scope       => "basic",
        access_type => "offline",
    );
    my $str = $oauth->full_login_uri() . "";
    like $str, qr{access_type=offline}, "access_type included when set";
}

# --- authorization_headers format ---
# We need a valid cache with non-expired token to test this
# Mock by creating a cache with future expiry
{
    my $oauth = OAuth::Cmdline->new( site => "authhead", homedir => $tmpdir );
    $oauth->cache_write(
        {
            access_token  => "bearer_test_token",
            refresh_token => "ref",
            client_id     => "cid",
            client_secret => "csec",
            expires       => time() + 7200,
            token_uri     => "https://example.com/token",
        }
    );

    my @headers = $oauth->authorization_headers();
    is scalar @headers, 2,                        "authorization_headers returns pair";
    is $headers[0],     "Authorization",           "header name is Authorization";
    is $headers[1],     "Bearer bearer_test_token", "header value is Bearer + token";
}

# --- token_refresh_authorization_header (base class returns empty) ---

{
    my $oauth = OAuth::Cmdline->new( site => "test", homedir => $tmpdir );
    my @headers = $oauth->token_refresh_authorization_header();
    is scalar @headers, 0, "base class token_refresh_authorization_header returns empty list";
}

# --- update_refresh_token (base class is passthrough) ---

{
    my $oauth = OAuth::Cmdline->new( site => "test", homedir => $tmpdir );
    my $cache = { refresh_token => "old" };
    my $data  = { refresh_token => "new" };
    my ( $c, $d ) = $oauth->update_refresh_token( $cache, $data );
    is $c->{refresh_token}, "old", "base class update_refresh_token does not modify cache";
    is $d->{refresh_token}, "new", "base class update_refresh_token does not modify data";
}

# --- tokens_get_additional_params (base class is passthrough) ---

{
    my $oauth  = OAuth::Cmdline->new( site => "test", homedir => $tmpdir );
    my $params = [ code => "abc", grant_type => "authorization_code" ];
    my $result = $oauth->tokens_get_additional_params($params);
    is_deeply $result, $params, "base class tokens_get_additional_params is passthrough";
}

# --- client_init_conf_check ---

{
    my $oauth = OAuth::Cmdline->new( site => "confcheck", homedir => $tmpdir );

    # No cache file yet — should die
    eval { $oauth->client_init_conf_check("https://example.com") };
    like $@, qr/client_id/, "client_init_conf_check dies without cache file";

    # Cache without client_id/secret — should die
    $oauth->cache_write( { access_token => "tok" } );
    eval { $oauth->client_init_conf_check("https://example.com") };
    like $@, qr/client_id/, "client_init_conf_check dies without client_id in cache";

    # Valid cache — should succeed
    $oauth->cache_write( { client_id => "cid", client_secret => "csec" } );
    ok $oauth->client_init_conf_check("https://example.com"), "client_init_conf_check succeeds with valid cache";
    is $oauth->client_id,     "cid",  "client_id populated from cache";
    is $oauth->client_secret, "csec", "client_secret populated from cache";
}

# --- Moo attribute setters ---

{
    my $oauth = OAuth::Cmdline->new( site => "test", homedir => $tmpdir );
    $oauth->client_id("new_id");
    is $oauth->client_id, "new_id", "client_id is read-write";

    $oauth->base_uri("https://api.example.com");
    is $oauth->base_uri, "https://api.example.com", "base_uri is read-write";

    $oauth->raise_error(1);
    is $oauth->raise_error, 1, "raise_error is read-write";
}

done_testing;
