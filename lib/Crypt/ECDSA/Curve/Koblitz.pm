package Crypt::ECDSA::Curve::Koblitz;

our $VERSION = '0.065';

use base Crypt::ECDSA::Curve;

use strict;
use warnings;
use Carp qw( croak );

use Math::BigInt::GMP;
use Math::BigInt lib => 'GMP';

use Crypt::ECDSA qw( multiply_F2m invert_F2m );
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
    Crypt::ECDSA::multiply_F2m( 
      $retval->{value}, $x->{value}, $y->{value}, $mod->{value} );
    return $retval;
}

sub invert_koblitz {
    my ( $self, $x ) = @_;
    $x = bint($x) unless ref $x;
    my $mod = bint( $self->{irreducible} );
    my $retval = bint(1);
    Crypt::ECDSA::invert_F2m( $retval->{value}, $x->{value}, $mod->{value} );
    return $retval;
}

sub is_on_curve {
    my ( $self, $x, $y ) = @_;
    
    # point at infinity is defined to be on curve and is (0,0) here
    return 1 if $x == 0 and $y == 0;
    
    my $mod = bint( $self->{irreducible} );
    my $a = bint( $self->{a} );
    
    return Crypt::ECDSA::is_F2m_point_on_curve( 
      $x->{value}, $y->{value}, $mod->{value}, $a->{value} ); 
}

sub double_on_curve {
    my ( $self, $x, $y, $order ) = @_;
    return $self->infinity if $x == 0;
    
    my $x_sum = bint($x);
    my $y_sum = bint($y);
    my $mod = bint( $self->{irreducible} ); 
    my $a = bint( $self->{a} );
    
    # we cannot pass the sign easily to XS so $a_neg passes the sign of a
    my $a_neg = ( $a < 0 ) ? 1 : 0;

    Crypt::ECDSA::double_F2m_point( 
      $x_sum->{value}, $y_sum->{value},
      $mod->{value}, $a->{value}, $a_neg
    );
    return $self->infinity if $x_sum == 0 and $y_sum == 0;    
    return Crypt::ECDSA::Point->new(
        X     => $x_sum,
        Y     => $y_sum,
        order => $order,
        curve => $self
    );
}

sub add_on_curve {
    my ( $self, $x1, $y1, $x2, $y2, $order ) = @_;
    return $self->double_on_curve( $x1, $y1, $order )
      if $x1 == $x2 and $y1 == $y2;
    return $self->infinity if $x1 == $x2 and ( $x1 == 0 or $y1 != $y2 );

    $x1 = bint($x1) unless ref $x1;
    $y1 = bint($y1) unless ref $y1;
    $x2 = bint($x2) unless ref $x2;
    $y2 = bint($y2) unless ref $y2;

    my $x_sum = bint($x1);
    my $y_sum = bint($y1);
    my $mod = bint( $self->{irreducible} );    
    my $a = bint( $self->{a} );
    my $a_neg = ( $a < 0 ) ? 1 : 0;

    Crypt::ECDSA::add_F2m_point( 
      $x_sum->{value}, $y_sum->{value},$x2->{value}, $y2->{value},
      $mod->{value}, $a->{value}, $a_neg
    );
    return $self->infinity if $x_sum == 0 and $y_sum == 0;
    return Crypt::ECDSA::Point->new(
        X     => $x_sum,
        Y     => $y_sum,
        order => $order,
        curve => $self
    );
}

sub subtract_on_curve { add_on_curve(@_) }

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

    my $x_product = bint($x);
    my $y_product = bint($y);
    my $mod = bint( $self->{irreducible} );    
    my $a = bint( $self->{a} );
    my $a_neg = ( $a < 0 ) ? 1 : 0;

    if( $scalar == 1 ) {
        return Crypt::ECDSA::Point->new(
            X     => $x_product,
            Y     => $y_product,
            order => $order,
            curve => $self
        );
    }
    elsif( $scalar == -1 ) {
        return Crypt::ECDSA::Point->new(
            X     => $x_product,
            Y     => $y_product ^ $x_product,
            order => $order,
            curve => $self
        );
    }
    else {
        if( $scalar < 0 ) {
            $scalar->bneg;
            $y_product = $y_product ^ $x_product;
        }
        Crypt::ECDSA::multiply_F2m_point(
          $x_product->{value}, $y_product->{value}, $scalar->{value}, 
          $mod->{value}, $a->{value}, $a_neg
        );
        return $self->infinity if $x_product == 0 and $y_product == 0;
        return Crypt::ECDSA::Point->new(
            X     => $x_product,
            Y     => $y_product,
            order => $order,
            curve => $self
        );
    }
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

=head2 FUNCTIONS

=over 4

=item B<equation>

  Return ascii string representation of the field equation

=back

=head2 Class Internal Functions

=over 4

=item B<invert_koblitz>

=item B<multiply_koblitz>

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
