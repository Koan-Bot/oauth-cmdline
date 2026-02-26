######################################################################
# Unit tests for OAuth::Cmdline subclasses
######################################################################
use warnings;
use strict;
use Test::More;
use File::Temp qw( tempdir );
use YAML qw( DumpFile );
use MIME::Base64;

my $tmpdir = tempdir( CLEANUP => 1 );

# Helper: write a minimal cache file for a given site
sub write_cache {
    my ( $dir, $site, $extra ) = @_;
    my $cache = {
        access_token  => "tok_test",
        refresh_token => "ref_test",
        client_id     => "test_client_id",
        client_secret => "test_client_secret",
        expires       => time() + 7200,
        token_uri     => "https://example.com/token",
        %{ $extra || {} },
    };
    DumpFile( "$dir/.$site.yml", $cache );
    return $cache;
}

# ============================================================
# GoogleDrive
# ============================================================

use_ok "OAuth::Cmdline::GoogleDrive";

{
    my $oauth = OAuth::Cmdline::GoogleDrive->new( homedir => $tmpdir );
    isa_ok $oauth, "OAuth::Cmdline::GoogleDrive";
    isa_ok $oauth, "OAuth::Cmdline", "inherits from base class";
    is $oauth->site, "google-drive", "GoogleDrive site name";
    is $oauth->cache_file_path, "$tmpdir/.google-drive.yml", "GoogleDrive cache path";
}

# ============================================================
# Youtube
# ============================================================

use_ok "OAuth::Cmdline::Youtube";

{
    my $oauth = OAuth::Cmdline::Youtube->new( homedir => $tmpdir );
    isa_ok $oauth, "OAuth::Cmdline::Youtube";
    isa_ok $oauth, "OAuth::Cmdline", "inherits from base class";
    is $oauth->site, "youtube", "Youtube site name";
    is $oauth->cache_file_path, "$tmpdir/.youtube.yml", "Youtube cache path";
}

# ============================================================
# Automatic
# ============================================================

use_ok "OAuth::Cmdline::Automatic";

{
    my $oauth = OAuth::Cmdline::Automatic->new( homedir => $tmpdir );
    isa_ok $oauth, "OAuth::Cmdline::Automatic";
    isa_ok $oauth, "OAuth::Cmdline", "inherits from base class";
    is $oauth->site,         "automatic", "Automatic site name";
    is $oauth->redirect_uri, undef,       "Automatic redirect_uri is undef (no redirect support)";
    is $oauth->cache_file_path, "$tmpdir/.automatic.yml", "Automatic cache path";
}

# Automatic: full_login_uri omits redirect_uri when it returns undef
{
    my $oauth = OAuth::Cmdline::Automatic->new(
        homedir   => $tmpdir,
        client_id => "auto_cid",
        login_uri => "https://accounts.automatic.com/oauth/authorize",
        scope     => "scope:trip",
    );
    my $uri = $oauth->full_login_uri() . "";
    unlike $uri, qr{redirect_uri=}, "Automatic full_login_uri has no redirect_uri param";
    like $uri,   qr{client_id=auto_cid}, "Automatic full_login_uri has client_id";
}

# ============================================================
# CustomFile
# ============================================================

use_ok "OAuth::Cmdline::CustomFile";

{
    my $custom_path = "$tmpdir/my-custom-tokens.yml";
    my $oauth = OAuth::Cmdline::CustomFile->new( custom_file => $custom_path );
    isa_ok $oauth, "OAuth::Cmdline::CustomFile";
    isa_ok $oauth, "OAuth::Cmdline", "inherits from base class";
    is $oauth->site,            "custom-file",  "CustomFile site name";
    is $oauth->cache_file_path, $custom_path,   "CustomFile uses custom_file as cache path";
}

# CustomFile: cache_write + cache_read with custom path
{
    my $custom_path = "$tmpdir/custom-oauth-cache.yml";
    my $oauth = OAuth::Cmdline::CustomFile->new( custom_file => $custom_path );
    my $data = { access_token => "custom_tok", expires => time() + 3600 };
    $oauth->cache_write($data);
    ok -f $custom_path, "custom cache file created";

    my $read = $oauth->cache_read();
    is $read->{access_token}, "custom_tok", "custom cache round-trip works";
}

# ============================================================
# Spotify
# ============================================================

use_ok "OAuth::Cmdline::Spotify";

{
    my $oauth = OAuth::Cmdline::Spotify->new( homedir => $tmpdir );
    isa_ok $oauth, "OAuth::Cmdline::Spotify";
    isa_ok $oauth, "OAuth::Cmdline", "inherits from base class";
    is $oauth->site, "spotify", "Spotify site name";
}

# Spotify: token_refresh_authorization_header produces correct Basic auth
{
    write_cache( $tmpdir, "spotify" );
    my $oauth = OAuth::Cmdline::Spotify->new( homedir => $tmpdir );

    my @headers = $oauth->token_refresh_authorization_header();
    is scalar @headers, 2,              "Spotify refresh header returns pair";
    is $headers[0],     "Authorization", "header name is Authorization";

    my $expected = "Basic " . encode_base64( "test_client_id:test_client_secret", "" );
    is $headers[1], $expected, "Spotify refresh header is Base64-encoded client_id:client_secret";

    # Verify no newline in encoded value
    unlike $headers[1], qr/\n/, "no newline in Base64-encoded header";
}

# ============================================================
# MicrosoftOnline
# ============================================================

use_ok "OAuth::Cmdline::MicrosoftOnline";

# MicrosoftOnline: resource is required
{
    eval { OAuth::Cmdline::MicrosoftOnline->new( homedir => $tmpdir ) };
    like $@, qr/resource/, "MicrosoftOnline dies without required resource attribute";
}

{
    my $oauth = OAuth::Cmdline::MicrosoftOnline->new(
        homedir  => $tmpdir,
        resource => "https://graph.microsoft.com",
    );
    isa_ok $oauth, "OAuth::Cmdline::MicrosoftOnline";
    isa_ok $oauth, "OAuth::Cmdline", "inherits from base class";
    is $oauth->site,     "microsoft-online",            "MicrosoftOnline site name";
    is $oauth->resource, "https://graph.microsoft.com", "resource attribute set";
}

# MicrosoftOnline: tokens_get_additional_params adds resource
{
    my $oauth = OAuth::Cmdline::MicrosoftOnline->new(
        homedir  => $tmpdir,
        resource => "https://graph.microsoft.com",
    );
    my $params = [ code => "abc", grant_type => "authorization_code" ];
    my $result = $oauth->tokens_get_additional_params($params);

    # Should have appended resource => value
    my %h = @$result;
    is $h{resource}, "https://graph.microsoft.com", "tokens_get_additional_params adds resource";
    is $h{code},     "abc",                          "original params preserved";
}

# MicrosoftOnline: update_refresh_token rotates the token
{
    my $oauth = OAuth::Cmdline::MicrosoftOnline->new(
        homedir  => $tmpdir,
        resource => "https://graph.microsoft.com",
    );
    my $cache = { refresh_token => "old_refresh" };
    my $data  = { refresh_token => "new_refresh", access_token => "new_access" };

    my ( $c, $d ) = $oauth->update_refresh_token( $cache, $data );
    is $c->{refresh_token}, "new_refresh", "MicrosoftOnline rotates refresh_token in cache";
    is $d->{refresh_token}, "new_refresh", "data unchanged";
}

# ============================================================
# Smartthings
# ============================================================

use_ok "OAuth::Cmdline::Smartthings";

# Smartthings: BUILD sets URIs and checks config
{
    write_cache( $tmpdir, "smartthings" );
    my $oauth = OAuth::Cmdline::Smartthings->new( homedir => $tmpdir );
    isa_ok $oauth, "OAuth::Cmdline::Smartthings";
    isa_ok $oauth, "OAuth::Cmdline", "inherits from base class";
    is $oauth->site, "smartthings", "Smartthings site name";

    is $oauth->base_uri, "https://graph-na02-useast1.api.smartthings.com",
        "Smartthings default base_uri (US)";
    is $oauth->login_uri,
        "https://graph-na02-useast1.api.smartthings.com/oauth/authorize",
        "login_uri derived from base_uri";
    is $oauth->token_uri,
        "https://graph-na02-useast1.api.smartthings.com/oauth/token",
        "token_uri derived from base_uri";
}

# Smartthings: custom base_uri
{
    write_cache( $tmpdir, "smartthings" );
    my $oauth = OAuth::Cmdline::Smartthings->new(
        homedir  => $tmpdir,
        base_uri => "https://graph-eu01-euwest1.api.smartthings.com",
    );
    is $oauth->base_uri, "https://graph-eu01-euwest1.api.smartthings.com",
        "Smartthings custom base_uri (UK)";
    is $oauth->login_uri,
        "https://graph-eu01-euwest1.api.smartthings.com/oauth/authorize",
        "login_uri derived from custom base_uri";
    is $oauth->token_uri,
        "https://graph-eu01-euwest1.api.smartthings.com/oauth/token",
        "token_uri derived from custom base_uri";
}

# Smartthings: BUILD dies without client config
{
    # No cache file for smartthings-noconf
    my $noconf_dir = tempdir( CLEANUP => 1 );
    eval { OAuth::Cmdline::Smartthings->new( homedir => $noconf_dir ) };
    like $@, qr/client_id|client_secret|register/i,
        "Smartthings BUILD dies without client config in cache";
}

# Smartthings: BUILD populates client_id/secret from cache
{
    write_cache( $tmpdir, "smartthings" );
    my $oauth = OAuth::Cmdline::Smartthings->new( homedir => $tmpdir );
    is $oauth->client_id,     "test_client_id",     "client_id loaded from cache";
    is $oauth->client_secret, "test_client_secret",  "client_secret loaded from cache";
}

done_testing;
