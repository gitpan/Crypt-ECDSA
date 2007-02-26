package Crypt::ECDSA::Point;

our $VERSION = '0.04';

use strict;
use warnings;
use Math::GMPz qw( :mpz );
use Carp qw( carp croak );
use Crypt::ECDSA::Util qw( bint );

our $WARN_IF_NEW_POINT_INVALID = 0;

sub new {
    my ( $class, %args ) = @_;
    my $self = {};
    $self->{X}     = bint( $args{X} );
    $self->{Y}     = bint( $args{Y} );
    $self->{curve} = $args{curve}
      or croak "Must have curve for a point on curve";
    $self->{order} =
      $args{order} ? bint( $args{order} ) : $self->{curve}->{order};
    $self->{is_infinity} = ( $args{is_infinity} ? 1 : 0 );
    
    carp "New Point ( $self->{X}  , $self->{Y}  ) is not on curve"
      if $WARN_IF_NEW_POINT_INVALID and 
        !$self->{curve}->is_on_curve( $self->{X}, $self->{Y} );
    
    bless $self, $class;
    return $self;
}

sub X {
    my ( $self, $new_X ) = @_;
    $self->{X} = $new_X if $new_X;
    return $self->{X};
}

sub Y {
    my ( $self, $new_Y ) = @_;
    $self->{Y} = $new_Y if $new_Y;
    return $self->{Y};
}

sub curve {
    my ( $self, $new_curve ) = @_;
    $self->{curve} = $new_curve if $new_curve;
    return $self->{curve};
}

sub order {
    my ( $self, $new_order ) = @_;
    $self->{order} = $new_order if $new_order;
    return $self->{order};
}

sub deep_copy {
    my ($self) = @_;
    my $point = Crypt::ECDSA::Point->new(
        X           => $self->{X},
        Y           => $self->{Y},
        order       => $self->{order},
        curve       => $self->{curve},
        is_infinity => $self->{is_infinity},
    );
    return $point;
}

sub is_point_at_infinity() {
    my $self = shift;
    return $self->{is_infinity};
}

sub add {
    my ( $p1, $p2 ) = @_;

    # handle point at infinity cases
    return $p1 if $p2->{is_infinity};
    return $p2 if $p1->{is_infinity};

    croak("Cannot add points on two different curves")
      if $p1->{curve} != $p2->{curve};

    return $p1->{curve}
      ->add_on_curve( $p1->{X}, $p1->{Y}, $p2->{X}, $p2->{Y}, $p1->{order} );

}

sub inverse {
    my ($self) = @_;
    return $self->{curve}
      ->inverse_on_curve( $self->{X}, $self->{Y}, $self->{order} );
}

sub double {
    my ($self) = @_;
    return $self->{curve}
      ->double_on_curve( $self->{X}, $self->{Y}, $self->{order} );
}

sub multiply {
    my ( $self, $scalar ) = @_;
    $scalar = bint($scalar);
    return $self->{curve}
      ->multiply_on_curve( $self->{X}, $self->{Y}, $scalar, $self->{order} );
}

sub is_equal_to {
    my ( $p1, $p2 ) = @_;
    return 1 unless $p1->{X} or $p1->{Y} or $p2->{X} or $p2->{Y};
    if ( $p1->{is_infinity} ) {
        return ( $p2->{is_infinity} ) ? 1 : 0;
    }
    if ( $p2->{is_infinity} ) {
        return ( $p1->{is_infinity} ) ? 1 : 0;
    }
    return ( $p1->{X} == $p2->{X} and $p1->{Y} == $p2->{Y} ) ? 1 : 0;
}

sub is_on_curve {
    my $p = shift;
    return $p->curve->is_on_curve( $p->X, $p->Y );
}

use overload
  '='  => sub { $_[0]->deep_copy( $_[1] ) },
  '+'  => sub { $_[0]->add( $_[1] ) },
  '-'  => sub { $_[0]->add( $_[1]->inverse ) },
  '*'  => sub { $_[0]->multiply( $_[1] ) },
  '==' => sub { $_[0]->is_equal_to( $_[1] ) },
  '!=' => sub { !$_[0]->is_equal_to( $_[1] ) };

=head1 NAME

Crypt::ECDSA::Point -- Elliptic curve points for EC cryptography

=head1 DESCRIPTION

These are for use with Crypt::ECDSA, a Math::BigInt based cryptography module.
These routines work most efficiently if the GMP math library is installed, and
in particular the point multiply function may be quite tedious without the 
GMP math library, which enables Math::BigInt::GMP.

=head1 METHODS

=over 4

=item B<new>

  Constructor.  Takes the following named pair arguments:
  
  X           => x coordinate,
  Y           => y coordinate,
  curve       => Crypt::ECDSA::Curve derived curve,
  order       => point order,
  is_infinity => set to 1 if this is to be the point at infinity  (optional)

=item B<X>

  Returns or sets the point's x coordinate 
  
=item B<Y>

  Returns or sets the point's y coordinate 

=item B<order>

  returns or sets the point order, if known
  
=item B<order>

  Returns or sets the Crypt::ECDSA::Curve upon which the point exists

=item B<is_point_at_infinity>

  Returns 1 if the point is the point at infinity for the EC curve, 
  otherwise undef.
  
=item B<deep_copy>

  Overloaded to '='
  Returns a new point that copies the internals of the point (a cloned copy 
  rather than just a reference).
  
=item B<add>

  my $P3 = $P1 + $P2;

  Overloaded to '+'
  Returns the point that is the sum of two points on the curve

=item B<double>

  my $double = $p->double(); 

  returns a point that is the point's double on the curve.

=item B<multiply>

  my $Q = $G * $d;

  Multiply a point by a scalar (not a point by a point!)

  Overloaded to '*'
  Note: in order to be sure the proper multiply is done, I suggest that a mutiply
  of point $P by scalar $k be written $P * $k, not $k * $P.

=item B<is_equal_to>

  if( $p1 == $p2) { ; }

  Overloaded to '=='
  Returns 1 if the points are equal (on the same curve as well).

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
