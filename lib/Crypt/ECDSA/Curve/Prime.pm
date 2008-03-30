package Crypt::ECDSA::Curve::Prime;

our $VERSION = '0.060';

use base Crypt::ECDSA::Curve;

use strict;
use warnings;
use Carp  qw( carp croak );
use POSIX qw( ceil );

use Crypt::ECDSA::Point;
use Crypt::ECDSA::Util qw( bint hex_bint );

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
    $dx2x1->bmodinv($p);
    my $lm    = bint( $dy2y1 * $dx2x1 % $p );
    my $x_sum = bint( ( $lm * $lm - $x1 - $x2 ) % $p );
    my $y_sum = bint( ( $lm * ( $x1 - $x_sum ) - $y1 ) % $p );
    return $self->infinity if $x_sum->is_nan or $y_sum->is_nan;
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
    $double_y->bmodinv($p);
    my $lm    = ( ( 3 * $x * $x + $a ) * $double_y ) % $p;
    my $x_sum = ( $lm * $lm - 2 * $x ) % $p;
    my $y_sum = ( $lm * ( $x - $x_sum ) - $y ) % $p;
    return $self->infinity if $x_sum->is_nan or $y_sum->is_nan;
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

sub to_octet {
    my ( $self, $x, $y, $compress ) = @_;
    my $octet;
    my $x_octet = pack 'H*', substr( $x->as_hex, 2 );
    if ($compress) {
        my $first_byte = $y % 2 ? "\x03" : "\x02";
        return $first_byte . $x_octet;
    }
    else {
        my $y_octet = pack 'H*', substr( $y->as_hex, 2 );
        return "\x04" . $x_octet . $y_octet;
    }
}

sub from_octet {
    my ( $self, $octet ) = @_;
    my $q_bytes       = ceil( ( length( $self->{q}->as_bin ) - 2 ) / 8 );
    my $oct_len       = length $octet;
    my $invalid_point = 1;
    my $x = bint();
    my $y = bint();
    if ( $oct_len == $q_bytes + 1 ) {    # compressed point
        my $y_byte = substr( $octet, 0, 1 );
        my $y_test;
        $y_test = 0 if $y_byte eq "\x02";
        $y_test = 1 if $y_byte eq "\x03";
        my $x   = hex_bint( unpack( 'H*', substr( $octet, 1 ) ) );
        if ( $x >= 0 and $x < $self->{p} and defined $y_test ) {
            my $alpha = bint();
            $alpha =
              ( $x * $x * $x + $self->{a} * $x + $self->{b} ) % $self->{p};
            $alpha->bsqrt();
            if ( ( $alpha & 1 ) == $y_test ) {
                $y = bint( $alpha );
            }
            else {
                $y = bint( $self->{p} - $alpha );
            }
            $invalid_point = 0 if $y >= 0 and $y < $self->{p};
        }
    }
    elsif ( $oct_len == 2 * $q_bytes + 1 ) {    # non-compressed point
        my $m_byte = substr $octet, 0, 1;
        if ( $m_byte eq "\x04" ) {
            my $x_bytes = substr $octet, 1, $q_bytes;
            my $y_bytes = substr $octet, 1 + $q_bytes, $q_bytes;
            $x = hex_bint( unpack( "H*", $x_bytes ) );
            $y = hex_bint( unpack( "H*", $y_bytes ) );
            $invalid_point = 0
              if $y >= 0
              and $y < $self->{p}
              and $x >= 0
              and $x < $self->{p}
              and $self->is_on_curve($x, $y);              
        }
    }
    if ($invalid_point) {
        $x = 0;
        $y = 0;
        carp("invalid octet source bytes for this point type");
    }
    return ( $x, $y );
}

=head1 NAME

Crypt::ECDSA::Curve::Prime -- Elliptic curves ove F(q), with q prime, for EC cryptography

=head1 DESCRIPTION

  These are for use with Crypt::ECDSA and require Math::BigInt::GMP.

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


=item B<from_octet>

  Constructs a Point from an ASN.1 DER coded octet (compressed or uncompressed formats)  

=item B<to_octet>
  
  Converts the Point into an ASN.1 DER encoded octet format

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
