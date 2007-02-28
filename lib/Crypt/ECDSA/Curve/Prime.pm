package Crypt::ECDSA::Curve::Prime;

our $VERSION = '0.041';

use base Crypt::ECDSA::Curve;

use strict;
use warnings;
use Carp 'croak';
use Math::GMPz qw( :mpz );

use Crypt::ECDSA::Point;
use Crypt::ECDSA::Util qw( bint );

sub equation { 'y * y = x * x * x + a * x + b, mod p, with a = -3' }

sub is_on_curve {
    my ( $self, $x, $y ) = @_;
    return if $x == 0 and $y == 0;
    return 1
      if ( $y * $y - ( $x * $x * $x + $self->{a} * $x + $self->{b} ) ) %
      $self->{p} == 0;
    return;
}

sub add_on_curve {
    my ( $self, $x1, $y1, $x2, $y2, $order ) = @_;
    my $p     = bint( $self->{p} );
    my $dy2y1 = bint( $y2 - $y1 );
    my $dx2x1 = bint( $x2 - $x1 );
    if ( $x1 == $x2 ) {
        return $self->infinity if ( $y1 + $y2 ) % $p == 0;
        return $self->double_on_curve( $x1, $y1, $order );
    }
    Rmpz_invert( $dx2x1, $dx2x1, $p );
    my $lm    = bint( $dy2y1 * $dx2x1 % $p );
    my $x_sum = bint( ( $lm * $lm - $x1 - $x2 ) % $p );
    my $y_sum = bint( ( $lm * ( $x1 - $x_sum ) - $y1 ) % $p );
    return Crypt::ECDSA::Point->new(
        X     => $x_sum,
        Y     => $y_sum,
        order => $order,
        curve => $self
    );
}

sub subtract_on_curve {
    my ( $self, $x1, $y1, $x2, $y2, $order ) = @_;
    return $self->add_on_curve( $self, $x1, $y1, $x2, ( -$y2 ) % $self->{p},
        $order );
}

sub double_on_curve {
    my ( $self, $x, $y, $order ) = @_;
    my $p        = $self->{p};
    my $a        = $self->{a};
    my $double_y = bint( $y * 2 );
    Rmpz_invert( $double_y, $double_y, $p );
    my $lm =
      ( ( 3 * $x * $x + $a ) * $double_y ) % $p;
    my $x_sum = ( $lm * $lm - 2 * $x ) % $p;
    my $y_sum = ( $lm * ( $x - $x_sum ) - $y ) % $p;

    return Crypt::ECDSA::Point->new(
        X     => $x_sum,
        Y     => $y_sum,
        order => $order,
        curve => $self
    );
}

sub inverse_on_curve {
    my ( $self, $x, $y, $order ) = @_;
    my $p = $self->{p};
    return Crypt::ECDSA::Point->new(
        X     => $x,
        Y     => ( -$y ) % $p,
        order => $order,
        curve => $self
    );
}

sub multiply_on_curve {
    my ( $self, $x, $y, $scalar, $order ) = @_;
    croak("cannot multiply by a negative number") if $scalar < 0;
    return $self->infinity unless $scalar;
    my $base_point = Crypt::ECDSA::Point->new(
        X     => $x,
        Y     => $y,
        order => $order,
        curve => $self
    );
    return $base_point if $scalar == 1;
    my $product        = $base_point;
    my $inverse_y_self = Crypt::ECDSA::Point->new(
        X     => $x,
        Y     => -$y,
        order => $order,
        curve => $self
    );
    my $tripled   = bint( $scalar * 3 );
    my $pivot_bit = bint(1);
    do { $pivot_bit *= 2 } while ( $pivot_bit <= $tripled );
    $pivot_bit /= 4;

    while ( $pivot_bit > 1 ) {
        $product = $product->double();
        my $test_tripled = $tripled & $pivot_bit;
        my $test_scalar  = $scalar & $pivot_bit;
        $product += $base_point     if $test_tripled and !$test_scalar;
        $product += $inverse_y_self if $test_scalar  and !$test_tripled;
        $pivot_bit /= 2;
    }
    return $product;
}

sub is_weak_curve {
    my ($self) = @_;
    my $n      = $self->{N};
    my $r      = $self->{prime_group_order};
    my $b = 29;    # we want perl 6's given/when switch here...
    if    ( $n <= 142 ) { $b = 6 }
    elsif ( $n <= 165 ) { $b = 7 }
    elsif ( $n <= 186 ) { $b = 8 }
    elsif ( $n <= 206 ) { $b = 9 }
    elsif ( $n <= 226 ) { $b = 10 }
    elsif ( $n <= 244 ) { $b = 11 }
    elsif ( $n <= 262 ) { $b = 12 }
    elsif ( $n <= 280 ) { $b = 13 }
    elsif ( $n <= 297 ) { $b = 14 }
    elsif ( $n <= 313 ) { $b = 15 }
    elsif ( $n <= 330 ) { $b = 16 }
    elsif ( $n <= 346 ) { $b = 17 }
    elsif ( $n <= 361 ) { $b = 18 }
    elsif ( $n <= 376 ) { $b = 19 }
    elsif ( $n <= 391 ) { $b = 20 }
    elsif ( $n <= 406 ) { $b = 21 }
    elsif ( $n <= 420 ) { $b = 22 }
    elsif ( $n <= 434 ) { $b = 23 }
    elsif ( $n <= 448 ) { $b = 24 }
    elsif ( $n <= 462 ) { $b = 25 }
    elsif ( $n <= 475 ) { $b = 26 }
    elsif ( $n <= 488 ) { $b = 27 }
    elsif ( $n <= 501 ) { $b = 28 }
    $n = bint($n);
    my $test_val = bint(1);
    my $q        = 2**$n;

    # test for the MOV condition
    for my $i ( 1 .. $b ) {
        $test_val *= $q;
        $test_val %= $r;
        return 1 if $test_val == 1;
    }
    return;
}

=head1 NAME

Crypt::ECDSA::Curve::Prime -- Elliptic curves ove F(q), with q prime, for EC cryptography

=head1 DESCRIPTION

  These are for use with Crypt::ECDSA, a Math::GMPz based cryptography module.

=over 4

=item B<new>

  Delegated to base class Crypt::ECDSA::Curve

=item B<is_on_curve>

  return 1 if (x, y) is on the curve, otherwise undef.

=item B<add_on_curve>

 Add a point on the curve to itself or another

=item B<subtract_on_curve>

 Subtract a point on the curve.  Addition of an additive inverse.
 
=item B<double_on_curve>

  Double a point on the curve.   
  Returns a new point.  Note this does NOT change the original point.

=item B<inverse_on_curve>

  get a point's additive inverse on the curve: (x, y) becomes (x, -y)

=item B<multiply_on_curve>

  my $Q = $G * n;

  Multiply a curve point by a scalar.  
  Note this should always be Point * scalar, not scalar * Point.

=item B<is_weak_curve>
    
  tests for known weak curve parameters

=back

=item FUNCTIONS

=over 4

=item B<equation>

  Return ascii string representation of the field equation

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
