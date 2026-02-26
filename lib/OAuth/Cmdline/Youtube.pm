###########################################
package OAuth::Cmdline::Youtube;
###########################################
use strict;
use warnings;
use Moo;

extends 'OAuth::Cmdline';

# VERSION
# ABSTRACT: Youtube-specific settings for OAuth::Cmdline

###########################################
sub site {
###########################################
    return "youtube";
}

1;

__END__

=head1 SYNOPSIS

    my $oauth = OAuth::Cmdline::Youtube->new( );
    $oauth->access_token();

=head1 DESCRIPTION

This class overrides methods of C<OAuth::Cmdline> if Youtube's Web API 
requires it.
