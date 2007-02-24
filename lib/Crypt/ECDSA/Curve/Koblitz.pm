package Crypt::ECDSA::Curve::Koblitz;

our $VERSION = 0.02;

use base Crypt::ECDSA::Curve;

use strict;
use warnings;
use Carp qw( croak );
use Math::BigInt lib => 'GMP';
use Math::GMP;

use Crypt::ECDSA::Curve;
use Crypt::ECDSA::Point;
use Crypt::ECDSA::Util
  qw( bint two_pow  );

our $MULTIPLY_DEBUG = 0;

our $named_curve = $Crypt::ECDSA::Curve::named_curve;

sub reduce_F2m {
    my ( $self, $x ) = @_;
    my $mod = bint( $self->{irreducible} );
    return $x unless $x and $mod;
    $x = bint($x) unless ref $x;
    croak "Illegal modulus zero in binary field" if $mod == 0;
    return $x                                    if $x < $mod;
    return 0                                     if $x == $mod;

    while (1) {
        my $diff = size_in_bits($x) - size_in_bits($mod);
        last if $diff < 0;
        $x->bxor( $mod << $diff );
    }
    return $x;
}

sub multiply_F2m {
    my ( $self, $x, $y ) = @_;
    return bint(0) unless $x and $y;
    return $x if $y == 1;
    return $y if $x == 1;
    $y = bint($y) unless ref $y;
    $x = bint($x) unless ref $x;

    my $accum = bint(0);
    my $yval  = $y->copy;
    my $r     = size_in_bits($x);
    for ( my $i = 0 ; $i < $r ; ++$i ) {
        $accum->bxor($yval) if test_bit( $x, $i );
        $yval->blsft(1);
    }
    return $self->reduce_F2m($accum);
}

sub invert_F2m {
    my ( $self, $x ) = @_;
    my $a = bint( $x );
    my $u = bint( $x );
    my $b = bint( 1 );
    my $v = bint( $self->{irreducible} );
    my $c = bint( 0 );
    while ( ( my $k = size_in_bits( $u ) ) > 1 ) {
        my $j = $k - size_in_bits( $v );
        if ( $j < 0 ) {
            my $temp = $u->copy;
            $u    = $v;
            $v    = $temp;
            $temp = $c->copy;
            $c    = $b;
            $b    = $temp;
            $j    = -$j;
        }
        my $vj = $v->copy->blsft( $j );
        $u->bxor( $vj );
        my $cj = $c->copy->blsft( $j );
        $b->bxor( $cj );
    }
    return $b;
}

sub is_on_curve {
    my ( $self, $x, $y ) = @_;
    my $lhs = $self->multiply_F2m( $y,   $y )->bxor( $self->multiply_F2m( $y, $x ) );
    my $xsq = $self->multiply_F2m( $x,   $x );
    my $rhs = $self->multiply_F2m( $xsq, $x );
    $rhs->bxor($xsq) if $self->{a};
    $rhs->bxor(1);
    return 1 unless $lhs->bcmp( $rhs );
    return;
}

sub add_on_curve {
    my ( $self, $x1, $y1, $x2, $y2, $order ) = @_;
    return $self->double_on_curve( $x1, $y1, $order )
      if $x1 == $x2 and $y1 == $y2;
    return $self->infinity if $x1 == $x2 and ( $x1 == 0 or $y1 != $y2 );
    $x1 = bint( $x1 ) unless ref $x1;
    $y1 = bint( $y1 ) unless ref $y1;
    $y2 = bint( $x2 ) unless ref $x2;
    $y2 = bint( $y2 ) unless ref $y2;

    my $s = $self->multiply_F2m( $y1->copy->bxor($y2),
        $self->invert_F2m( $x1->copy->bxor($x2) ) );

    my $x_sum = $self->multiply_F2m( $s, $s );
    $x_sum->bxor( $self->{a} );
    $x_sum->bxor($s);
    $x_sum->bxor($x1);
    $x_sum->bxor($x2);

    my $y_sum = $self->multiply_F2m( $s, ( $x2->copy->bxor($x_sum) ) );
    $y_sum->bxor($x_sum);
    $y_sum->bxor($y2);

    return Crypt::ECDSA::Point->new(
        X     => $x_sum,
        Y     => $y_sum,
        order => $order,
        curve => $self
    );
}

sub subtract_on_curve { add_on_curve( @_ ) }

sub double_on_curve {
    my ( $self, $x, $y, $order ) = @_;
    return $self->infinity if $x == 0;

    my $s = $self->multiply_F2m( $y, $self->invert_F2m($x) );
    $s->bxor($x);

    my $x_sum = $self->multiply_F2m( $s, $s );
    $x_sum->bxor($s);
    $x_sum->bxor( $self->{a} );

    my $y_sum = $self->multiply_F2m( $s, ( $x->copy->bxor($x_sum) ) );
    $y_sum->bxor($x_sum);
    $y_sum->bxor($y);

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
        Y     => $y->bxor($x),
        order => $order,
        curve => $self
    );
}

sub multiply_on_curve {
    my ( $self, $x, $y, $scalar, $order ) = @_;
    $scalar = bint($scalar) unless ref $scalar;
#    $scalar->bmod($order) if $order;
    return $self->infinity unless $scalar;
#    return tau_point_multiply ( 
#        $self, $scalar, $x, $y, $order, $self->{a}, $self->{tau_s0}, 
#        $self->{tau_s1}, $self->{tau_V}, $self->{N}
#    ) if $self->{tau_s0};
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
    for ( my $i = size_in_bits($scalar) - 1 ; $i >= 0 ; --$i ) {
        $S += $S;
        $S += $Q if test_bit( $scalar, $i );
    }
    return $S;
}

sub is_weak_curve { 
    my ($self) = @_;
    return 1 if $self->{a} == 0 and $self->{b} == 0;
    return 0;
}

# from draft FIPS 186-3, pages 111-114
sub tau_point_multiply {
    my( $self, $n, $x, $y, $order, $a, $s0, $s1,  $V, $N ) = @_;
    return 0 unless $n;
    $n =  bint ( $n )  unless ref $n;
#    $n->bmod( $order ) if $order;
    $x =  bint ( $x )  unless ref $x;
    $y =  bint ( $y)   unless ref $y;
    $a = bint( $a ) unless ref $a;
    $s0 = bint( $s0 ) unless ref $s0;
    $s1 = bint( $s1 ) unless ref $s1;
    $V =  bint ( $V )  unless ref $V;    
    my $m = $N;
    my $mu = ( -1 ) ** (1 - $a );
    my $C = 6;
    # FIXME: needs to be a BigRat not a BigInt quotient here
    my $np = bint( $n / two_pow( ($m - 9)/2 + $a - $C ) );
    my $gp0 = bint( $s0 * $np );
    my $gp1 = bint( $s1 * $np );
    my $tpm = two_pow( $m );
    my $h0 = bint( $gp0 / $tpm );
    my $h1 = bint( $gp0 / $tpm );
    my $jp0 = bint( $h0 * $V );
    my $jp1 = bint( $h1 * $V );
    $tpm = two_pow( ( $m + 5 ) / 2 );
    my $lp0 = rounded_div( $gp0 + $jp0, $tpm );
    my $lp1 = rounded_div( $gp1 + $jp1, $tpm );
    $tpm = two_pow( -$C );
    my $lam0 = bint($lp0 * $tpm );
    my $lam1 = bint($lp1 * $tpm );
    my $f0 = round $lam0;
    my $f1 = round $lam1;
    my $eta0 = bint( $lam0 - $f0 );
    my $eta1 = bint( $lam1 - $f1 );
    $h0 = 0;
    $h1 = 0;
    
    my $eta = bint( 2 * $eta0 + $mu * $eta1 );
    
    if($eta >= 1) {
        if($eta0 - 3 * $mu * $eta1 < -1) {
            $h1 = $mu;
        }
        else {
            $h0 = 1;
        }
    }
    elsif($eta0 + 4 * $mu * $eta1 >= 2 ) {
        $h1 = $mu;
    }
    if($eta < -1 ) {
        if( $eta0 - 3 * $mu * $eta1 >= 1 ) {
            $h1 = -$mu;
        }
        elsif( $eta0 + 4 * $mu * $eta1 < -2) {
            $h1 = -$mu;
        }
    }
    my $q0 = bint( $f0 + $h0 );
    my $q1 = bint( $f1 + $h1 );
    my $r0 = bint( $n - ($s0 + $mu * $s1 ) * $q0 - 2 * $s1 * $q1 );
    my $r1 = bint( $s1 * $q0 - $s0 * $q1 );
    my $Q = Crypt::ECDSA::Point(
        X => 0,
        Y => 0,
        order => $order,
        curve => $self
    );
    my $P0 = Crypt::ECDSA::Point(
        X => $x,
        Y => $y,
        order => $order,
        curve => $self
    );
    while($r0 != 0 or $r1 != 0) {
        if($r0->is_odd) {
            my $u = 2 - ($r0 - (2 * $r1) % 4);
            $r0->bsub($u);
            $Q += $P0 if $u == 1;
            $Q += $P0 if $u == -1;
        }
        $P0->{X} = $P0->{X} * $P0->{X};
        $P0->{Y} = $P0->{Y} * $P0->{Y};
        $r0 = $r1 + $mu * $r0 / 2;
        $r1 = -$r0 / 2;
    }
    
    return $Q;
}


#############  non-method helper functions  ##########

sub equation {
    'y * y + x * y = x * x * x + a * x * x + 1, finite field math, '
      . 'with a = 0 or 1 and polynomial reduction';
}

##  functions that use the use Math::GMPz library

sub rounded_div {
    my( $a, $b ) = @_;
    my $quot = bint( $a / $b );
    my $remain = bint( $a % $b );
    my $half_divisor = bint( $b / 2 );
    ++$quot if $remain >= $half_divisor;
    return $quot;
}

sub test_bit {
    my ( $n, $posit ) = @_;
    return Math::GMP::gmp_tstbit( Math::GMP->new($n), $posit );
}

sub size_in_bits {
    my ($n) = @_;
    return Math::GMP::sizeinbase_gmp( Math::GMP->new($n), 2 );
}


=head1 NAME

Crypt::ECDSA::Curve::Koblitz -- binary (F(2**N) curves for EC cryptography

=head1 DESCRIPTION

These are for use with Crypt::ECDSA, a Math::BigInt based cryptography module.
These routines work most efficiently if the GMP math library is installed, and
in particular the point multiply function may be quite tedious without the 
GMP math library, which enables Math::BigInt::GMP.

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

=item B<rounded_div>

   division with rounding

=item b<test_bit>
 
  test if a bit in an integer is set

=item B<size_in_bits>

  binary size in bits of an integer

=back

=head1 BUGS

  Too slow for routine use with secure sizes at present.  This will likely be fixed
  with XS code in a future release.  Use prime curves instead for now.

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
