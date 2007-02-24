package Crypt::ECDSA::Util;

our $VERSION = 0.02;

use strict;
use warnings;
require Exporter;
our @ISA    = qw(Exporter);
our @EXPORT = qw( make_pq_seed_counter_new make_seed_and_pq_with_sha1
  validate_pq_seed_counter_sha1 is_probably_prime bint two_pow 
  bigint_from_coeff );
use Carp qw(carp croak);
use POSIX qw(ceil);
use Math::BigInt lib => 'GMP';
use Math::BigInt::Random;
use Digest::SHA;

sub bint    { Math::BigInt->new(shift) }
sub two_pow { Math::BigInt->new(2)->bpow(shift) }


# returns a bigint given a list of exponents for a
#polynomial of base 2, so [ 3 1 0 ] = 2**3 + 2**1 + 2**0 = 8 + 2 + 1
sub bigint_from_coeff {
    my $arrayref = shift;
    my $n        = bint(0);
    for my $t (@$arrayref) { $n += two_pow($t) }
    return $n;
}

sub make_pq_seed_counter_new {
    my ( $L, $N, $seedlen ) = @_;

    # get the alogorithm and output bit size of the hash func
    my ( $alg, $outlen ) = _check_L_N_pair( $L, $N );
    unless ($outlen) {
        carp("Bad (L,N) pair ( $L, $N )");
        return;
    }
    if ( $seedlen < $N ) {
        carp("Seed length $seedlen is less than N of $N");
        return;
    }
    my $n        = ceil( $L / $outlen ) - 1;
    my $b        = $L - 1 - ( $n * $outlen );
    my $twopowS  = two_pow($seedlen);
    my $twopowN  = two_pow($N);
    my $twopowN1 = two_pow( $N - 1 );
    my $twopowL1 = two_pow( $L - 1 );
    my $q        = 0;
    my $p        = 0;

    while (1) {
        my $seed = random_bigint( length_bin => 1, length => $seedlen )
          or die "cannot make random domain seed: $!";
        my $seed_digest = $alg->add_bits( substr( $seed->as_bin, 2 ) );
        my $U = bint( "0x" . $seed_digest->hexdigest )->bmod($twopowN);
        my $q = $U->bior($twopowN1)->bior(1);
        next unless is_probably_prime($q);
        my $offset = 1;
        for ( my $counter = 0 ; $counter < 4096 ; ++$counter ) {
            my @v = ();
            for my $j ( 0 .. $n ) {
                $alg->reset;
                $alg->add_bits(
                    substr(
                        bint( $seed + $offset + $j )->bmod($twopowS)->as_bin, 2
                    )
                );
                push @v, bint( '0x' . $alg->hexdigest );
            }
            my $W = Math::BigInt->bzero;
            for ( my $i = 0 ; $i < $n ; ++$i ) {
                $W->badd( $v[$i] * two_pow( $outlen * $i ) );
            }
            $W->badd(
                ( $v[$n] )->bmod( two_pow($b) ) * two_pow( $n * $outlen ) );
            my $X = bint( $W + two_pow( $L - 1 ) );
            my $c = bint( $X->copy()->bmod( $q * 2 ) );
            $p = bint( $X - ( $c - 1 ) );
            if ( $p >= $twopowL1 and is_probably_prime($p) ) {
                return ( $p, $q, $seed, $counter );
            }
            $offset += $n;
            ++$offset;
        }
    }
}

sub make_seed_and_pq_with_sha1 {
    my ( $L, $g ) = @_;
    croak "seed length should be > 160" unless $g >= 160;
    my $n        = int( ( $L - 1 ) / 160 );
    my $b        = $L - 1 - $n * 160;
    my $twopowG  = two_pow($g);
    my $twopowL1 = two_pow( $L - 1 );
    my $q        = 0;
    my $p        = 0;

    while (1) {
        my $seed = random_bigint( length_bin => 1, length => $g )
          or die "cannot make random domain seed: $!";
        my $alg = Digest::SHA->new(1);
        $alg->add_bits( substr( $seed->as_bin, 2 ) );
        my $seed_digest = bint( '0x' . $alg->hexdigest );
        $alg->reset;
        $alg->add_bits(
            substr( bint( $seed + 1 )->bmod( two_pow($g) )->as_bin, 2 ) );
        my $U = bint( $seed_digest->bxor( bint( '0x' . $alg->hexdigest ) ) );
        $q = $U->bior( two_pow(159) )->bior(1);
        next unless is_probably_prime($q);
        my $offset = 2;

        for ( my $counter = 0 ; $counter < 4096 ; ++$counter ) {
            my @v = ();
            for my $k ( 0 .. $n ) {
                $alg->reset;
                $alg->add_bits(
                    substr(
                        bint( $seed + $offset + $k )->bmod($twopowG)->as_bin, 2
                    )
                );
                push @v, bint( '0x' . $alg->hexdigest );
            }
            my $W = Math::BigInt->bzero;
            for ( my $i = 0 ; $i < $n ; ++$i ) {
                $W->badd( $v[$i] * two_pow( $i * 160 ) );
            }
            $W->badd( ( $v[$n] )->bmod( two_pow($b) ) * two_pow( $n * 160 ) );
            my $X = bint( $W + two_pow( $L - 1 ) );
            my $c = bint( $X->copy()->bmod( $q * 2 ) );
            $p = bint( $X - ( $c - 1 ) );
            if ( $p >= $twopowL1 and is_probably_prime($p) ) {
                return ( $p, $q, $seed, $counter );
            }
            $offset += $n;
            ++$offset;
        }
    }
}

sub _check_L_N_pair {
    my ( $L, $N ) = @_;
    my $key = $L . '.' . $N;
    my $L_N = {
        1024.160 => 1,
        2048.224 => 256,
        2048.256 => 256,
        3072.256 => 512,
    };
    my $func_param = $L_N->{$key};
    return ( Digest::SHA->new($func_param),
        $func_param == 1 ? 160 : $func_param );
}

sub is_probably_prime {
    my ($w) = @_;
    return unless $w;
    $w = bint($w) unless ref $w and ref $w =~ /BigInt/;
    return unless $w > 1;
    return 1 if $w < 4;

    # Knuth's Algorithm P (originally by Miller and Rabin)
    # FIPS 182-2, page 13
    my $checks = 50;
    my $a      = 0;
    my $m      = $w - 1;
    while ( $m->is_even ) {
        $m->bdiv(2);
        ++$a;
    }

    # we now have w = 2^a * m + 1
    for ( 0 .. $checks ) {    # 51 tries
        my $b = random_bigint( min => 2, max => $w - 2 );
        my $z = $b->bmodpow( $m, $w );
        next if $z == 1 or $z == $w - 1;
        for ( my $j = 1 ; $j < $a ; ++$j ) {
            $z->bmul($z)->bmod($w);
            return if $z == 1;
            last   if $z == $w - 1;
        }
    }
    return 1;
}

=head1 NAME

Crypt::ECDSA::Util -- Utility functions for Crypt::ECDSA

=head1 DESCRIPTION

These are for use with Crypt::ECDSA, a Math::BigInt based cryptography module

These routines work most efficiently if the GMP math library is installed.  
Otherwise, they may be too slow for comfort on most current hardware.

=head1 METHODS

=over 4

=item B<bint>

  bint( $scalar );
  A shortcut for Math::BigInt->new( ).
  Makes a new Math::BigInt from a scalar argument,

=item B<two_pow>

  my $two_to_the_power_of_n = two_pow( $n );

  Returns a new Math::BigInt equal to 2 ** $n.
  
=item B<bigint_from_coeff>

  my irreducible = bigint_from_coeff( [ 3, 1, 0 ] );

  returns a bigint given a list of exponents for a
  polynomial of base 2, such that [ 3, 1, 0 ] => 2**3 + 2**1 + 2**0 = 8 + 2 + 1
  
=item B<is_probably_prime>

  my $is_prime = is_probably_prime( $n );

  Returns 1 if $n is almost certainly prime ( chance

=item B<make_pq_seed_counter_new>

my( $p, $q, $seed, $counter ) = make_pq_seed_counter_new( 2048, 256, 256 );

  Make primes p and q for use in DSA algorithms, given L, N, and seed length.
  See FIPS PUB 186-3, 2006 (draft standard).
  
=item B<make_seed_and_pq_with_sha1>

my( $p, $q, $seed, $counter ) = make_seed_and_pq_with_sha1( 1024, 164 );

  Make primes p and q for use in DSA algorithms, given L and seed length.
  See FIPS 186-2, the CURRENT standard.  This is may be obsolete after 2008.

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

=back

=cut

1;
