######################################################################
# Test suite for OAuth::Cmdline PKCE (RFC 7636)
######################################################################
use warnings;
use strict;
use Test::More;
use File::Temp qw( tempfile );
use YAML qw( DumpFile );
use Digest::SHA qw( sha256 );
use MIME::Base64;
use URI;

use OAuth::Cmdline;

plan tests => 16;

# Helper: base64url-encode (for verification)
sub base64url_encode {
    my ($data) = @_;
    my $encoded = encode_base64( $data, "" );
    $encoded =~ tr{+/}{-_};
    $encoded =~ s/=+$//;
    return $encoded;
}

# --- Test 1-2: PKCE attribute defaults ---

my $oauth_no_pkce = OAuth::Cmdline->new(
    site      => "test-no-pkce",
    login_uri => "https://example.com/auth",
    token_uri => "https://example.com/token",
    client_id => "test-id",
    scope     => "read",
);

ok !$oauth_no_pkce->pkce, "PKCE is off by default";
is $oauth_no_pkce->_code_verifier, undef,
  "no code_verifier when PKCE is off";

# --- Test 3: full_login_uri without PKCE has no challenge params ---

my $uri_no_pkce = URI->new( $oauth_no_pkce->full_login_uri );
my %params_no_pkce = $uri_no_pkce->query_form;

ok !exists $params_no_pkce{code_challenge},
  "no code_challenge param without PKCE";
ok !exists $params_no_pkce{code_challenge_method},
  "no code_challenge_method param without PKCE";

# --- Test 4-9: PKCE enabled ---

my $oauth_pkce = OAuth::Cmdline->new(
    site      => "test-pkce",
    login_uri => "https://example.com/auth",
    token_uri => "https://example.com/token",
    client_id => "test-id",
    scope     => "read",
    pkce      => 1,
);

ok $oauth_pkce->pkce, "PKCE is enabled when set";

my $login_uri = $oauth_pkce->full_login_uri;
my $uri_pkce  = URI->new($login_uri);
my %params    = $uri_pkce->query_form;

ok exists $params{code_challenge},        "code_challenge present in URI";
ok exists $params{code_challenge_method}, "code_challenge_method present in URI";
is $params{code_challenge_method}, "S256", "challenge method is S256";

# Verify the code_verifier was stored
my $verifier = $oauth_pkce->_code_verifier;
ok defined $verifier && length($verifier) >= 43,
  "code_verifier is stored and has sufficient length (got "
  . length( $verifier // '' ) . ")";

# --- Test 10: Verify challenge matches verifier ---

my $expected_challenge = base64url_encode( sha256($verifier) );
is $params{code_challenge}, $expected_challenge,
  "code_challenge = BASE64URL(SHA256(code_verifier))";

# --- Test 11-12: code_verifier format (RFC 7636 section 4.1) ---

# code_verifier must be 43-128 chars from [A-Za-z0-9-._~]
like $verifier, qr/^[A-Za-z0-9\-._~]+$/,
  "code_verifier uses only unreserved characters";
cmp_ok length($verifier), '>=', 43,
  "code_verifier length >= 43 chars";

# --- Test 13: Each call generates a new verifier ---

my $first_verifier = $oauth_pkce->_code_verifier;
$oauth_pkce->full_login_uri;
my $second_verifier = $oauth_pkce->_code_verifier;

isnt $first_verifier, $second_verifier,
  "each full_login_uri call generates a fresh verifier";

# --- Test 14-16: base64url encoding correctness ---

# Verify no padding, no + or /
like $params{code_challenge}, qr/^[A-Za-z0-9\-_]+$/,
  "code_challenge uses base64url alphabet (no +, /, or =)";

# Test with a known SHA-256 value
my $known_verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
my $known_challenge = base64url_encode( sha256($known_verifier) );
my $computed        = $oauth_pkce->_generate_code_challenge($known_verifier);
is $computed, $known_challenge,
  "challenge computation matches independent calculation";

# RFC 7636 Appendix B test vector
my $rfc_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
my $rfc_expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
my $rfc_computed = $oauth_pkce->_generate_code_challenge($rfc_verifier);
is $rfc_computed, $rfc_expected,
  "matches RFC 7636 Appendix B test vector";
