###########################################
package OAuth::Cmdline::Mojo;
###########################################
use strict;
use warnings;
use Mojo::Base 'Mojolicious';

# VERSION
# ABSTRACT: Run a standalone token collector

###########################################
sub startup {
###########################################
    my ($self) = @_;

    my $renderer = $self->renderer();
    push @{ $renderer->paths }, $self->template_path();

    $self->routes->get('/')->to('main#root');
    $self->routes->get('/callback')->to('main#callback');
}

###########################################
sub template_path {
###########################################
    my ($self) = @_;

    # point renderer to where our .html.ep
    # templates are installed
    my $dir = $INC{'OAuth/Cmdline.pm'};
    $dir =~ s/\.pm//;
    $dir .= "/templates";

    return $dir;
}

###########################################
package OAuth::Cmdline::Mojo::Main;
###########################################
use Mojo::Base 'Mojolicious::Controller';

###########################################
sub root {
###########################################
    my ($self) = @_;

    $self->stash->{login_url} = $self->app->{oauth}->full_login_uri();
    $self->stash->{site}      = $self->app->{oauth}->site();

    $self->render("main");
}

###########################################
sub callback {
###########################################
    my ($self) = @_;

    # Validate CSRF state parameter (RFC 6749 Section 10.12)
    my $expected_state = $self->app->{oauth}->csrf_state();
    my $received_state = $self->param("state");

    if ( defined $expected_state ) {
        if ( !defined $received_state
            || $received_state ne $expected_state )
        {
            $self->render(
                text   => "OAuth error: state parameter mismatch "
                  . "(possible CSRF attack)",
                status => 403,
                layout => 'default'
            );
            return;
        }
    }

    if ( my $error = $self->param("error") ) {
        my $desc = $self->param("error_description") // $error;
        $self->render(
            text   => "OAuth authorization failed: $desc",
            status => 400,
            layout => 'default'
        );
        return;
    }

    my $code = $self->param("code");

    if ( !defined $code || $code eq '' ) {
        $self->render(
            text   => "OAuth callback missing 'code' parameter",
            status => 400,
            layout => 'default'
        );
        return;
    }

    eval { $self->app->{oauth}->tokens_collect($code); };

    if ($@) {
        my $err = $@;
        $err =~ s/ at \S+ line \d+.*//s;    # strip file/line noise
        $self->render(
            text   => "Token exchange failed: $err",
            status => 500,
            layout => 'default'
        );
        return;
    }

    $self->render(
        text   => "Tokens saved in " . $self->app->{oauth}->cache_file_path,
        layout => 'default'
    );
}

1;

__END__

=head1 SYNOPSIS

    use OAuth::Cmdline::Mojo;
    app->start();

=head1 DESCRIPTION

OAuth::Cmdline::Mojo starts a web server, to which you should
point your browser, in order to go through the OAuth rigamarole and
collect the tokens for later use in command line scripts.
