######################################################################
# Live integration test for OAuth::Cmdline::Spotify
# Requires LIVE_TESTS=1 and a pre-initialized ~/.spotify.yml
######################################################################
use warnings;
use strict;
use Test::More;
use JSON qw( from_json );
use OAuth::Cmdline::Spotify;

SKIP: {
    skip "Set LIVE_TESTS=1 to run Spotify integration tests", 2
        unless $ENV{"LIVE_TESTS"};

    my $spotify = OAuth::Cmdline::Spotify->new();

    skip "Cache file " . $spotify->cache_file_path . " not found", 2
        unless -f $spotify->cache_file_path;

    my $user = $spotify->cache_read->{user};
    skip "Add 'user:' field to " . $spotify->cache_file_path, 2
        unless defined $user;

    my $ua = LWP::UserAgent->new();
    $ua->default_header( $spotify->authorization_headers );

    my $resp = $ua->get("https://api.spotify.com/v1/users/$user/playlists");
    ok $resp->is_success, "Fetching user playlists";

    my $data = from_json( $resp->content() );
    is ref $data->{items}, "ARRAY", "got an array of items";
}

done_testing;
