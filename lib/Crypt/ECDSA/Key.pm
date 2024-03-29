package Crypt::ECDSA::Key;

our $VERSION = '0.067';

use strict;
no warnings;

use Carp 'croak';

use Crypt::ECDSA::Curve::Prime;
use Crypt::ECDSA::Curve::Koblitz;
use Crypt::ECDSA::Util qw( bint hex_bint random_bits );
use Crypt::ECDSA::PEM;

our $standard_curve = $Crypt::ECDSA::Curve::named_curve;

use warnings;

sub new {
    my ( $class, %args ) = @_;
    my $self = {};
    bless $self, $class;

    # if G(x,y) specified use specified values (X, Y)
    my $x = bint( $args{X} || 0 );
    my $y = bint( $args{Y} || 0 );
    if( $args{PEM} ) {
        #read parameters from a PEM file
        my $pem         = Crypt::ECDSA::PEM->new( 
          filename => $args{PEM}, password => $args{password} );
        if( exists $pem->{private_pem_tree}->{standard} ) {
            $args{standard} = $pem->{private_pem_tree}->{standard};
            $args{Q}        = $pem->{private_pem_tree}->{Q};
            $args{d}        = $pem->{private_pem_tree}->{d};
            $args{order}    = $pem->{private_pem_tree}->{order};
        }
    }
    if ( $args{standard} ) {
        # using a NIST or other standard curve (good idea)
        $self->{standard} = $args{standard};
        if ( $standard_curve->{ $self->{standard} } ) {
            my $named_curve = $Crypt::ECDSA::Curve::named_curve;
            my $alg         = $named_curve->{ $self->{standard} }->{algorithm};
            if ( $alg eq 'Prime' ) {
                $self->{curve} =
                  Crypt::ECDSA::Curve::Prime->new(
                    standard => $self->{standard} );
            }
            elsif ( $alg eq 'Koblitz' ) {
                $self->{curve} =
                  Crypt::ECDSA::Curve::Koblitz->new(
                    standard => $self->{standard} );
            }
            $x = $self->{curve}->{G_x} if $self->{curve}->{G_x};
            $y = $self->{curve}->{G_y} if $self->{curve}->{G_y};
        }
        else {
            croak(  "ECDSA->new: standard curve type "
                  . $self->{standard}
                  . "not found" );
        }
    }
    else {

        # we need to have been given a curve if no standard curve given
        if ( $args{curve} ) {
            $self->{curve} = $args{curve};
        }
        else {
            croak(
"A curve must be specified for ECDSA signature : specified was ",
                values %args
            );
        }
    }

    # the point's order must be specified and be positive
    my $order = $args{order} || $self->{curve}->{point_order};
    croak("Point G(x,y) must have positive order")
      unless $order and $order > 0;
    croak(  "point (G_x "
          . $x->as_hex
          . ", G_y "
          . $y->as_hex
          . ") not on the curve, cannot create ECDSA" )
      unless $self->{curve}->is_on_curve( $x, $y );

    # ok we now should have the parameters for a point G
    $self->{G} = Crypt::ECDSA::Point->new(
        X     => $x,
        Y     => $y,
        curve => $self->{curve},
        order => $order
    );
    # if given a Q public point, set this, otherwise need to create this
    $self->{d} = bint( $args{d} ) if defined $args{d};
    $self->new_secret_value() unless defined $self->{d} and $self->{d} > 0;
    $self->{Q} = $args{Q} if defined $args{Q};
    $self->{Q} = $self->{G} * $self->{d} unless defined $self->{Q};
    $self->{Q}->{curve} = $self->{G}->{curve};
    return $self;
}

sub curve { return shift->{curve} }

sub Q { return shift->{Q} }

sub Qx { return shift->{Q}->{X} }

sub Qy { return shift->{Q}->{Y} }

sub order { return shift->{G}->{order} }

sub secret { return shift->{d} }

sub G { return shift->{G} }

sub set_public_Q {
    my ( $self, $pub_x, $pub_y ) = @_;
    my $new_Q = Crypt::ECDSA::Point->new(
        X           => $pub_x,
        Y           => $pub_y,
        curve       => $self->curve,
        order       => $self->order,
        is_infinity => 0,
    );
    $self->{Q} = $new_Q;
    $self->{d} = undef;
    return $new_Q;
}

sub new_key_values {
    my ($self) = @_;
    $self->new_secret_value();
    $self->{Q} = $self->{G} * $self->{d};
    return ( bint( $self->{d} ), bint( $self->{Q}->{X} ),
        bint( $self->{Q}->{Y} ) );
}

# see FIPS 186-3 draft, p. 64
sub new_secret_value {
    my ($self) = @_;
    my $n      = $self->{G}->{order};
    my $len    = length( $n->as_hex ) - 2;
    $self->{d} =
      ( random_bits( ($len + 8) * 16 ) % ( $n - 1 ) ) + 1;
    return $self->{d};
}

# check a public key provided for validity, given our known curve
# a valid key is on the curve and yields infinity when multiplied
# by the order of the base point G for that curve
sub verify_public_key {
    my ( $self, $Qx, $Qy ) = @_;
    my $q = $self->curve->q;
    return if $Qx < 0 or $Qx >= $q or $Qy < 0 or $Qy >= $q;
    return unless $self->curve->is_on_curve( $Qx, $Qy );
    # valid key if rQ == point at infinity
    my $Q = Crypt::ECDSA::Point->new(
        X           => $Qx,
        Y           => $Qy,
        curve       => $self->curve,
        order       => $self->order,
        is_infinity => 0,
    );
    my $r = $self->curve->{point_order};
    return unless $r;
    my $product = $Q * $r;
    return unless $product->is_point_at_infinity;
    return 1;
}

sub read_PEM {
    my( $self, %args ) = @_;
    if($args{filename} and $args{private}) {
        my $pem         = Crypt::ECDSA::PEM->new( 
          filename => $args{filename}, password => $args{password} );
        $self->{Q}        = $pem->{private_pem_tree}->{Q};
        $self->{d}        = $pem->{private_pem_tree}->{d};
        $self->{order}    = $pem->{private_pem_tree}->{order};
        $self->{curve}    = $pem->{private_pem_tree}->{curve};
        $self->{G} = Crypt::ECDSA::Point->new(
            X     => $self->{curve}->{Gx},
            Y     => $self->{curve}->{Gy},
            curve => $self->{curve},
            order => $self->{curve}->{order},
        );
    }
    return $self;
}

sub write_PEM {
    my( $self, %args ) = @_;
    if( $args{filename} and $args{private} ) {
        my $pem = Crypt::ECDSA::PEM->new();      
        my %pem_args;
        $pem_args{key} = $self;
        $pem_args{filename} = $args{filename};
        $pem_args{private}  = 1;
        $pem_args{password} = $args{password} if $args{password};
        return $pem->write_PEM( %pem_args );
    }
    return;
}

=head1 NAME

Crypt::ECDSA::Key -- ECDSA Key object package for elliptic key DSA cryptography

=head1 DESCRIPTION

  These are for use with Crypt::ECDSA and require Math::BigInt::GMP.

=head1 METHODS

=over 4

=item B<new>

  Constructor.  Takes the following named pair arguments:
  
  
  curve => curve or a 'standard' named curve (this may be the best choice)
  if not a standard curve, will need X => integer, Y => integer, order => integer,
  G_x => base point x coordinate,  G_y => base point y coordinate
  d => secret key, a integer secret multiplier.  If secret not specified, 
  the object will generate a random secret key.

  If a PEM file is specified, new will read the key parameters from that file:
  
  my $key_from_PEM = Crypt::ECDSA::Key->new( PEM => $pem_filename );

=item B<curve>

  Returns or sets the key's curve, a Crypt::ECDSA::Curve derived object 
  
=item B<Q>

  Returns or sets the key's Q public point

=item B<Qx>

  returns the x coordinate of the public key
  
=item B<Qy>

  returns the y coordinate of the public key
  
=item B<order>

  Returns the order of the curve's base point, if known

=item B<secret> 

  returns the secret scalar private key (stored internally as scalar $d)

=item B<set_public_Q>

  Used to set a public key for use when the private key is unknown
  
=item B<new_key_values>

sub new_key_values {
 
  my( $d, $Qx, $Qy ) = $key->new_secret_value();

  Regenerate a new private and public key and return the scalars
  ( secret value d, public point x coordinate, public point y coordinate )
  Be careful!  The old and new secret keys are not stored permanently by the module.
  
=item B<verify_public_key>

  if( $key->verify_public_key { $Qx, $Qy ) ) {
    print "Public key verified ok";
  }

  Verify a provided public key when the curve, but not the private key are known

=item B<read_PEM>

  $key->read_pem( filename =>$pem_filename, private => 1 );
  
  Read a key from a PEM file.  private => $n , if present and nonzero, means to
  read the secret key from the file, otherwise only the public key may be read.

=item B<write_PEM>

  $bytes_written = $key->write_PEM( filename => $file, private => 1 );
  
  Write the key to a PEM file.  Private key is written if the 'private' 
  argument is nonzero. A password => "password" argument is permitted.

=back

=head2 Class Internal Functions

=over 4

=item B<G>

=item B<new_secret_value>

=back

=head1 AUTHOR 

   William Herrera B<wherrera@skylightview.com>. 

=head1 SUPPORT 

Questions, feature requests and bug reports should go to 
<wherrera@skylightview.com>.

=head1 COPYRIGHT 

=over 4

Copyright (c) 2007 William Herrera. All rights reserved.  
This program is free software; you can redistribute it and/or modify 
it under the same terms as Perl itself.


=cut


1;
