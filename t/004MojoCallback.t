######################################################################
# Test suite for OAuth::Cmdline::Mojo callback error handling
######################################################################
use strict;
use warnings;

use Test2::Bundle::Extended;
use Test2::Tools::Explain;
use Test::Mojo;

use OAuth::Cmdline::Spotify;

# Build a minimal OAuth object for testing
my $oauth = OAuth::Cmdline::Spotify->new(
    client_id     => "test_id",
    client_secret => "test_secret",
    login_uri     => "https://example.com/auth",
    token_uri     => "https://example.com/token",
    scope         => "test-scope",
);

# Load the Mojo app
use OAuth::Cmdline::Mojo;
my $t = Test::Mojo->new('OAuth::Cmdline::Mojo');
$t->app->{oauth} = $oauth;

# Test: callback with OAuth error param returns 400
$t->get_ok('/callback?error=access_denied&error_description=User+denied+access')
    ->status_is(400)
    ->content_like(qr/OAuth error: User denied access/);

# Test: callback with error param but no description uses error as fallback
$t->get_ok('/callback?error=server_error')
    ->status_is(400)
    ->content_like(qr/OAuth error: server_error/);

# Test: callback with no code param returns 400
$t->get_ok('/callback')
    ->status_is(400)
    ->content_like(qr/OAuth error/);

# Test: callback with empty code param returns 400
$t->get_ok('/callback?code=')
    ->status_is(400)
    ->content_like(qr/OAuth error/);

# Test: callback with code but token exchange fails returns 500
# tokens_collect will fail because there's no real token endpoint
$t->get_ok('/callback?code=fake_auth_code')
    ->status_is(500)
    ->content_like(qr/Token exchange failed/);

done_testing();
