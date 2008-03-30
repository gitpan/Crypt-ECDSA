package Crypt::ECDSA::Curve::Koblitz;

our $VERSION = '0.060';

use base Crypt::ECDSA::Curve;

use strict;
use warnings;
use Carp qw( croak );

use Math::BigInt::GMP;
use Math::BigInt lib => 'GMP';

use Crypt::ECDSA;
use Crypt::ECDSA::Curve;
use Crypt::ECDSA::Point;
use Crypt::ECDSA::Util qw( bint two_pow );

our $MULTIPLY_DEBUG = 0;

our $named_curve = $Crypt::ECDSA::Curve::named_curve;

sub equation {
    'y * y + x * y = x * x * x + a * x * x + 1, finite field math, '
      . 'with a = 0 or 1 and polynomial reduction';
}

sub multiply_koblitz {
    my ( $self, $x, $y ) = @_;
    return bint() unless $x and $y;
    $x = bint($x) unless ref $x;
    $y = bint($y) unless ref $y;
    my $mod = bint( $self->{irreducible} );
    my $retval = bint(1);
    $retval->{value} = 
      Crypt::ECDSA::multiply_F2m( $x->{value}, $y->{value}, $mod->{value} );
    return $retval;
}

sub invert_koblitz {
    my ( $self, $x ) = @_;
    $x = bint($x) unless ref $x;
    my $mod = bint( $self->{irreducible} );

    my $retval = bint(1);
    $retval->{value} = Crypt::ECDSA::invert_F2m( $x->{value}, $mod->{value} );
    return $retval;
}

sub is_on_curve {
    my ( $self, $x, $y ) = @_;
    my $lhs = $self->multiply_koblitz( $y, $y );
    $lhs ^= $self->multiply_koblitz( $y, $x );
    my $xsq = $self->multiply_koblitz( $x,   $x );
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

    my $s =
      $self->multiply_koblitz( $y1 ^ $y2, $self->invert_koblitz( $x1 ^ $x2 ) );

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
    for ( my $i = length( $scalar->as_bin ) - 3 ; $i >= 0 ; --$i ) {
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

sub to_octet {
    my ( $self, $x, $y, $compress ) = @_;
    my $octet;
    my $x_octet = pack "C", split( '', substr( $x->as_hex, 2 ) );
    if ($compress) {
        my $first_byte;
        if ( $x == 0 ) {
            $first_byte = "\x02";
        }
        else {
            my $z = $y * $self->invert_koblitz($x);
            $first_byte = ( $z & 1 ) ? "\x03" : "\x02";
        }
        return $first_byte . $x_octet;
    }
    else {
        my $y_octet = pack "C", split( '', substr( $y->as_hex, 2 ) );
        return "\x04" . $x_octet . $y_octet;
    }
}

sub from_octet {
    my ( $self, $octet ) = @_;
    my $q_bytes       = ceil( ( length( $self->{q}->as_bin ) - 2 ) / 8 );
    my $oct_len       = length $octet;
    my $mod           = bint( $self->{irreducible} );
    my $invalid_point = 1;
    my ( $x, $y );
    if ( $oct_len == $q_bytes + 1 ) {    # compressed point
        my $y_byte = substr( $octet, 0, 1 );
        my $y_test;
        $y_test = 0 if $y_byte eq "\x02";
        $y_test = 1 if $y_byte eq "\x03";
        my $x = hex_bint( pack( "X*", unpack "C*", substr( $octet, 1 ) ) );
        if ( $x >= 0 and $x < $mod and defined $y_test ) {
            if ( $x == 0 ) {
                $y             = bint( $self->{b} )**( 2 * $self->{N} + 1 );
                $invalid_point = 0;
            }
            else {
                my $alpha = bint();
                $alpha =
                  $x + $self->{a} + $self->multiply_koblitz( $self->{b},
                    $self->invert_koblitz( $x * $x ) );
                if ( $self->{N} & 1 ) {    # N is odd otherwise we have an error
                    my $htr   = bint($alpha);
                    my $count = ( $self->{N} - 1 ) / 2;
                    for ( my $i = 1 ; $i <= $count ; ++$i ) {
                        $htr = $self->multiply_koblitz( $htr, $htr ) ^ $alpha;
                    }
                    if ( ( $htr & 1 ) == $y_test ) {
                        $y = $self->multiply_koblitz( $x, $htr );
                    }
                    else {
                        $y = $self->multiply_koblitz( $x, ( $htr ^ 1 ) );
                    }
                }
                $invalid_point = 0
                  if defined($y)
                  and $y >= 0
                  and $y < $self->{p};
            }
        }
    }
    elsif ( $oct_len == 2 * $q_bytes + 1 ) {    # non-compressed point
        my $m_byte = substr $octet, 0, 1;
        if ( $m_byte eq "\x04" ) {
            my $x_bytes = substr $octet, 1, $q_bytes;
            my $y_bytes = substr $octet, 1 + $q_bytes, $q_bytes;
            $x = hex_bint( pack( "X*", unpack "C*", $x_bytes ) );
            $y = hex_bint( pack( "X*", unpack "C*", $y_bytes ) );
            $invalid_point = 0
              if $y >= 0
              and $y < $mod
              and $x >= 0
              and $x < $mod
              and $self->is_on_curve( $x, $y );
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

Crypt::ECDSA::Curve::Koblitz -- binary (F(2**N)) curves for EC cryptography

=head1 DESCRIPTION

  These are for use with Crypt::ECDSA and require Math::BigInt::GMP.


=head1 METHODS

=over 4

=item B<new>

  Delegated to base class Crypt::ECDSA::Curve

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


=item B<from_octet>

  Constructs a Point from an ASN.1 octet (compressed or uncompressed formats)  

=item B<to_octet>
  
  Converts the Point into an ASN.1 octet format

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
