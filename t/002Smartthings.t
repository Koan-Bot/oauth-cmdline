######################################################################
# Live integration test for OAuth::Cmdline::Smartthings
# Requires LIVE_TESTS=1 and a pre-initialized ~/.smartthings.yml
######################################################################
use warnings;
use strict;
use Test::More;
use JSON qw( from_json );
use OAuth::Cmdline::Smartthings;

SKIP: {
    skip "Set LIVE_TESTS=1 to run Smartthings integration tests", 1
        unless $ENV{"LIVE_TESTS"};

    my $oauth = OAuth::Cmdline::Smartthings->new;

    my $json = $oauth->http_get( $oauth->base_uri . "/api/smartapps/endpoints" );
    skip "Can't get endpoints", 1
        unless defined $json;

    my $uri  = from_json($json)->[0]->{uri} . "/switches";
    my $data = $oauth->http_get($uri);
    is $data, q/[{"name":"Outlet","value":"on"}]/, "report on switches";
}

done_testing;
