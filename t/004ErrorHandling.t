######################################################################
# Test suite for OAuth::Cmdline error handling
######################################################################
use warnings;
use strict;
use Test::More;
use File::Temp qw(tempdir);
use YAML qw(DumpFile LoadFile);
use JSON qw(to_json);

use OAuth::Cmdline;

plan tests => 7;

my $tmpdir = tempdir( CLEANUP => 1 );

######################################################################
# Helper: create a minimal OAuth::Cmdline with a temp cache
######################################################################
sub make_oauth {
    my (%extra) = @_;
    return OAuth::Cmdline->new(
        site          => "test-error",
        homedir       => $tmpdir,
        client_id     => "test_id",
        client_secret => "test_secret",
        token_uri     => "https://example.com/token",
        %extra,
    );
}

######################################################################
# Test: tokens_collect dies when tokens_get returns undef
######################################################################
{
    my $oauth = make_oauth();

    # Mock tokens_get to return undef (simulating API failure)
    no warnings 'redefine';
    local *OAuth::Cmdline::tokens_get = sub { return (undef, undef, undef) };
    use warnings 'redefine';

    eval { $oauth->tokens_collect("fake_code") };
    like $@, qr/no access_token/,
        "tokens_collect dies when tokens_get returns no access_token";
}

######################################################################
# Test: tokens_collect uses default expiry when expires_in is missing
######################################################################
{
    my $oauth = make_oauth();

    no warnings 'redefine';
    local *OAuth::Cmdline::tokens_get = sub {
        return ("access_123", "refresh_456", undef);
    };
    use warnings 'redefine';

    $oauth->tokens_collect("fake_code");

    my $cache = LoadFile("$tmpdir/.test-error.yml");
    ok $cache->{access_token} eq "access_123",
        "tokens_collect stores access_token";
    ok $cache->{expires} > time(),
        "tokens_collect uses default expiry when expires_in is undef";
}

######################################################################
# Test: token_refresh handles malformed JSON gracefully
######################################################################
{
    my $oauth = make_oauth();

    # Write a cache file with a refresh token
    DumpFile("$tmpdir/.test-error.yml", {
        access_token  => "old_access",
        refresh_token => "old_refresh",
        client_id     => "test_id",
        client_secret => "test_secret",
        token_uri     => "https://example.com/token",
        expires       => time() - 1,
    });

    # Mock LWP to return success with garbage body
    no warnings 'redefine';
    local *LWP::UserAgent::request = sub {
        return HTTP::Response->new(200, "OK", ['Content-Type' => 'text/plain'], "not json at all");
    };
    use warnings 'redefine';

    my $result = $oauth->token_refresh();
    ok !defined $result,
        "token_refresh returns undef on malformed JSON response";
}

######################################################################
# Test: token_refresh handles response missing access_token
######################################################################
{
    my $oauth = make_oauth();

    DumpFile("$tmpdir/.test-error.yml", {
        access_token  => "old_access",
        refresh_token => "old_refresh",
        client_id     => "test_id",
        client_secret => "test_secret",
        token_uri     => "https://example.com/token",
        expires       => time() - 1,
    });

    no warnings 'redefine';
    local *LWP::UserAgent::request = sub {
        my $body = to_json({ error => "invalid_grant" });
        return HTTP::Response->new(200, "OK", ['Content-Type' => 'application/json'], $body);
    };
    use warnings 'redefine';

    my $result = $oauth->token_refresh();
    ok !defined $result,
        "token_refresh returns undef when response has no access_token";
}

######################################################################
# Test: token_refresh succeeds with valid JSON response
######################################################################
{
    my $oauth = make_oauth();

    DumpFile("$tmpdir/.test-error.yml", {
        access_token  => "old_access",
        refresh_token => "old_refresh",
        client_id     => "test_id",
        client_secret => "test_secret",
        token_uri     => "https://example.com/token",
        expires       => time() - 1,
    });

    no warnings 'redefine';
    local *LWP::UserAgent::request = sub {
        my $body = to_json({
            access_token => "new_access",
            expires_in   => 3600,
        });
        return HTTP::Response->new(200, "OK", ['Content-Type' => 'application/json'], $body);
    };
    use warnings 'redefine';

    my $result = $oauth->token_refresh();
    ok $result, "token_refresh succeeds with valid response";

    my $cache = LoadFile("$tmpdir/.test-error.yml");
    is $cache->{access_token}, "new_access",
        "token_refresh updates access_token in cache";
}
