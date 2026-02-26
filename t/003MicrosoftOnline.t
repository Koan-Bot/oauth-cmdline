######################################################################
# Live integration test for OAuth::Cmdline::MicrosoftOnline
# Requires LIVE_TESTS=1 and a pre-initialized ~/.microsoft-online.yml
######################################################################
use warnings;
use strict;
use Test::More;
use JSON qw( from_json );
use OAuth::Cmdline::MicrosoftOnline;

SKIP: {
    skip "Set LIVE_TESTS=1 to run MicrosoftOnline integration tests", 2
        unless $ENV{"LIVE_TESTS"};

    my $msonline = OAuth::Cmdline::MicrosoftOnline->new(
        resource => "https://graph.microsoft.com",
    );

    skip "Cache file " . $msonline->cache_file_path . " not found", 2
        unless -f $msonline->cache_file_path;

    my $ua = LWP::UserAgent->new();
    $ua->default_header( $msonline->authorization_headers );

    my $resp = $ua->get('https://graph.microsoft.com/v1.0/users?$top=1');
    ok $resp->is_success, "Fetching user list";

    my $data = from_json( $resp->content() );
    is ref $data->{value}, "ARRAY", "got an array of items";
}

done_testing;
