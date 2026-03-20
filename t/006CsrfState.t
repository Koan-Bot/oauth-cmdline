######################################################################
# Test suite for OAuth::Cmdline CSRF state parameter
######################################################################
use warnings;
use strict;
use Test::More;
use File::Temp qw( tempdir );

plan tests => 14;

use OAuth::Cmdline;

# Create a minimal OAuth object for testing
my $tmpdir = tempdir( CLEANUP => 1 );
my $oauth = OAuth::Cmdline->new(
    site          => "test-csrf",
    homedir       => $tmpdir,
    client_id     => "test-client-id",
    client_secret => "test-client-secret",
    login_uri     => "https://example.com/oauth/authorize",
    token_uri     => "https://example.com/oauth/token",
    scope         => "read",
);

# Test 1: generate_csrf_state returns a value
my $state = $oauth->generate_csrf_state();
ok defined $state, "generate_csrf_state returns a defined value";

# Test 2: state is non-empty
ok length($state) > 0, "state token is non-empty";

# Test 3: state is stored in the object
is $oauth->csrf_state(), $state, "state stored in csrf_state attribute";

# Test 4: state looks like a hex string (at least 16 chars)
like $state, qr/^[0-9a-f]{16,}$/i, "state is a hex string of sufficient length";

# Test 5: consecutive calls produce different states
my $state2 = $oauth->generate_csrf_state();
isnt $state, $state2, "consecutive calls produce different state tokens";

# Test 6: full_login_uri includes state parameter
my $login_uri = $oauth->full_login_uri();
like $login_uri, qr/[?&]state=/, "full_login_uri includes state parameter";

# Test 7: the state in the URI matches the stored csrf_state
my $current_state = $oauth->csrf_state();
like $login_uri, qr/[?&]state=\Q$current_state\E(?:&|$)/,
    "state in URI matches csrf_state attribute";

# Test 8: full_login_uri still includes other required params
like $login_uri, qr/client_id=test-client-id/, "login URI has client_id";
like $login_uri, qr/response_type=code/,       "login URI has response_type";
like $login_uri, qr/scope=read/,               "login URI has scope";

# Test 9: calling full_login_uri again generates a new state
my $uri1       = $oauth->full_login_uri();
my $state_after = $oauth->csrf_state();
isnt $current_state, $state_after,
    "each full_login_uri call generates a fresh state";

# Test 10: csrf_state can be set manually (for testing/custom flows)
$oauth->csrf_state("custom-state-value");
is $oauth->csrf_state(), "custom-state-value",
    "csrf_state can be set manually";

######################################################################
# Test Mojo callback state validation
######################################################################

SKIP: {
    eval { require Test::Mojo; 1 }
        or skip "Test::Mojo not available", 2;

    require OAuth::Cmdline::Mojo;

    # Create a fresh oauth object for Mojo tests
    my $mojo_oauth = OAuth::Cmdline->new(
        site          => "test-mojo-csrf",
        homedir       => $tmpdir,
        client_id     => "test-client-id",
        client_secret => "test-client-secret",
        login_uri     => "https://example.com/oauth/authorize",
        token_uri     => "https://example.com/oauth/token",
        scope         => "read",
    );

    # Generate a state so csrf_state is populated
    $mojo_oauth->generate_csrf_state();
    my $expected_state = $mojo_oauth->csrf_state();

    my $app = OAuth::Cmdline::Mojo->new();
    $app->{oauth} = $mojo_oauth;

    my $t = Test::Mojo->new($app);

    # Test: callback with wrong state returns 403
    $t->get_ok("/callback?code=testcode&state=wrong-state")
        ->status_is(403);
}
