package Crypt::ECDSA::Curve::Koblitz;

our $VERSION = '0.041';

use base Crypt::ECDSA::Curve;

use strict;
use warnings;
use Carp qw( croak );
use Math::GMPz qw( :mpz );

use Crypt::ECDSA;
use Crypt::ECDSA::Curve;
use Crypt::ECDSA::Point;
use Crypt::ECDSA::Util qw( bint two_pow );

our $MULTIPLY_DEBUG = 0;

our $named_curve = $Crypt::ECDSA::Curve::named_curve;

sub multiply_koblitz {
    my ( $self, $x, $y ) = @_;
    return bint(0) unless $x and $y;
    return $x if $y == 1;
    return $y if $x == 1;
    $y = bint($y) unless ref $y;
    $x = bint($x) unless ref $x;
    my $mod = bint( $self->{irreducible} );

    my $retval = Crypt::ECDSA::multiply_F2m( $x, $y, $mod );
    return $retval;
}

sub invert_koblitz {
    my ( $self, $x ) = @_;
    $x = bint($x) unless ref $x;
    my $mod = bint( $self->{irreducible} );

    my $retval = Crypt::ECDSA::invert_F2m( $x, $mod );
    return $retval;
}

sub is_on_curve {
    my ( $self, $x, $y ) = @_;
    my $lhs = $self->multiply_koblitz( $y, $y );
    $lhs ^= $self->multiply_koblitz( $y, $x );
    my $xsq = $self->multiply_koblitz( $x, $x );
    my $rhs = $self->multiply_koblitz( $xsq, $x );
    $rhs ^= $xsq if $self->{a};
    $rhs ^= 1;
    return 1 if $lhs == $rhs;
    return;
}

sub add_on_curve {
    my ( $self, $x1, $y1, $x2, $y2, $order ) = @_;
    return $self->double_on_curve( $x1, $y1, $order )
      if $x1 == $x2 and $y1 == $y2;
    return $self->infinity if $x1 == $x2 and ( $x1 == 0 or $y1 != $y2 );
    $x1 = bint($x1) unless ref $x1;
    $y1 = bint($y1) unless ref $y1;
    $y2 = bint($x2) unless ref $x2;
    $y2 = bint($y2) unless ref $y2;

    my $s = $self->multiply_koblitz( $y1 ^ $y2 , 
      $self->invert_koblitz( $x1 ^ $x2 ) );

    my $x_sum = $self->multiply_koblitz( $s, $s );
    $x_sum ^= $self->{a} if $self->{a};
    $x_sum ^= $s;
    $x_sum ^= $x1;
    $x_sum ^= $x2;

    my $y_sum = $self->multiply_koblitz( $s, $x2 ^ $x_sum );
    $y_sum ^= $x_sum;
    $y_sum ^= $y2;

    return Crypt::ECDSA::Point->new(
        X     => $x_sum,
        Y     => $y_sum,
        order => $order,
        curve => $self
    );
}

sub subtract_on_curve { add_on_curve(@_) }

sub double_on_curve {
    my ( $self, $x, $y, $order ) = @_;
    return $self->infinity if $x == 0;
    my $mod = bint( $self->{irreducible} );
    
    my $s = $self->multiply_koblitz( $y, $self->invert_koblitz($x) );
    $s ^= $x;

    my $x_sum = $self->multiply_koblitz( $s, $s );
    $x_sum ^= $s;
    $x_sum ^= $self->{a} if $self->{a};

    my $y_sum = $self->multiply_koblitz( $s, $x ^ $x_sum );
    $y_sum ^= $x_sum;
    $y_sum ^= $y;

    return Crypt::ECDSA::Point->new(
        X     => $x_sum,
        Y     => $y_sum,
        order => $order,
        curve => $self
    );
}

sub inverse_on_curve {
    my ( $self, $x, $y, $order ) = @_;
    return Crypt::ECDSA::Point->new(
        X     => $x,
        Y     => $y ^ $x,
        order => $order,
        curve => $self
    );
}

sub multiply_on_curve {
    my ( $self, $x, $y, $scalar, $order ) = @_;
    $scalar = bint($scalar) unless ref $scalar;
    return $self->infinity unless $scalar;

    my $Q = Crypt::ECDSA::Point->new(
        X     => $x,
        Y     => $y,
        order => $order,
        curve => $self
    );
    return $Q if $scalar == 1;
    if ( $scalar < 0 ) {
        $scalar = -$scalar;
        $Q      = -Q;
    }
    my $S = Crypt::ECDSA::Point->new(
        X     => 0,
        Y     => 0,
        order => $order,
        curve => $self
    );
    for ( my $i = length( Rmpz_get_str( $scalar, 2 ) ) - 1 ; $i >= 0 ; --$i ) {
        $S += $S;
        $S += $Q if $scalar & two_pow($i);
    }
    return $S;
}

sub is_weak_curve {
    my ($self) = @_;
    return 1 if $self->{a} == 0 and $self->{b} == 0;
    return 0;
}


#############  non-method helper functions  ##########

sub equation {
    'y * y + x * y = x * x * x + a * x * x + 1, finite field math, '
      . 'with a = 0 or 1 and polynomial reduction';
}


=head1 NAME

Crypt::ECDSA::Curve::Koblitz -- binary (F(2**N)) curves for EC cryptography

=head1 DESCRIPTION

  These are for use with Crypt::ECDSA, a Math::GMPz based cryptography module.

=head1 METHODS

=over 4

=item B<new>

  Delegated to base class Crypt::ECDSA::Curve


=item B<reduce_F2m>

  Special binary field function--reduce the result of addition or multiplication on
  the curve by the 'irreducible' basis polynomial.  Akin to modular addition, but slower :(.

=item B<multiply_F2m>

  Binary field multiplication

=item B<invert_F2m>
  
  Binary field inversion: used for binary field division, so that
    $x * $y             becomes 
    $x * invert_F2m($y)

=item B<is_on_curve>

  return 1 if (x, y) is on the curve, otherwise undef.

=item B<add_on_curve>

 Add a point on the curve to itself or another

=item B<subtract_on_curve>

 Subtract a point on the curve.  Same as addition.

=item B<double_on_curve>

  Double a point on the curve.   
  Returns a new point, does NOT change the original.

=item B<inverse_on_curve>

  get a point's additive inverse

=item B<multiply_on_curve>

  my $Q = $G * n;

  Multiply a curve point by a scalar.  
  Note this should always be Point * scalar, not scalar * Point.

=item B<is_weak_curve>
    
  tests for known weak curve parameters


=item B<tau_point_multiply>

  Koblitz curve binary field point multiply algorithm from draft FIPS 186-3, pages 111-114  

=back

=item FUNCTIONS

=over 4

=item B<equation>

  Return ascii string representation of the field equation

=back

=head1 BUGS

  Windows compatibility needs work. Some of this is the GMP library.

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
