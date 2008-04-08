package Crypt::ECDSA::Util;

our $VERSION = '0.062';

use strict;
use warnings;
require Exporter;
our @ISA    = qw(Exporter);
our @EXPORT = qw(
  two_pow random_bits bigint_from_coeff is_probably_prime
  make_pq_seed_counter_new make_seed_and_pq_with_sha1
  validate_pq_seed_counter_sha1 bint hex_bint random_hex_bytes 
);
use Carp qw(carp croak);
use POSIX qw(ceil);
use Math::BigInt::GMP;
use Math::BigInt only => 'GMP';
use Digest::SHA;


sub bint { Math::BigInt->new( shift || 0 ) }

sub hex_bint {
    my ($hx) = @_;
    $hx = '0x' . $hx unless $hx =~ /^0x/;
    return Math::BigInt->new($hx);
}

sub two_pow {
    my ($exp) = @_;
    my $a = Math::BigInt->new(1);
    return $a->blsft($exp);
}

# returns a bigint given a list of exponents for a
# polynomial of base 2, so [ 3 1 0 ] = 2**3 + 2**1 + 2**0 = 8 + 2 + 1
sub bigint_from_coeff {
    my $arrayref = shift;
    my $n        = bint();
    for my $t (@$arrayref) { $n += two_pow($t) }
    return $n;
}

sub random_bits {
    my ($bitlength) = @_;
    require Crypt::ECDSA;
    my $result = bint(1);
    $result->{value} = Crypt::ECDSA::gmp_random_bits( $bitlength );
    return $result;
}

sub random_hex_bytes {
    my ($bytelength) = @_;
    return substr( random_bits( $bytelength * 8 )->as_hex, 2 );
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
    my $q        = bint();
    my $p        = bint();
    my $X        = bint();
    my $c        = bint();
    my $W        = bint();

    while (1) {
        my $seed        = random_bits($seedlen);
        my $seed_digest = $alg->add_bits( substr( $seed->as_bin, 2 ) );
        my $U           = hex_bint( $seed_digest->hexdigest ) % $twopowN;
        $q = $U | $twopowN1 | 1;
        next unless is_probably_prime($q);
        my $offset = 1;
        for ( my $counter = 0 ; $counter < 4096 ; ++$counter ) {
            my @v = ();
            for my $j ( 0 .. $n ) {
                my $basenum = Math::BigInt->new( $seed + $offset + $j );
                $basenum->bmod($twopowS);
                $alg->reset;
                $alg->add_bits( substr( $basenum->as_bin, 2 ) );
                push @v, hex_bint( $alg->hexdigest );
            }
            $W = 0;
            for ( my $i = 0 ; $i < $n ; ++$i ) {
                $W += $v[$i] * two_pow( $outlen * $i );
            }
            $W += ( $v[$n] % two_pow($b) ) * two_pow( $n * $outlen );
            $X = $W + two_pow( $L - 1 );
            $c = $X % ( $q * 2 );
            $p = $X - ( $c - 1 );
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
    my $q        = bint();
    my $p        = bint();
    my $X        = bint();
    my $c        = bint();
    my $U        = bint();
    my $W        = bint();
    my $s        = bint();
    while (1) {
        my $seed = random_bits($g);
        my $alg  = Digest::SHA->new(1);
        $alg->add_bits( substr( $seed->as_bin, 2 ) );
        my $seed_digest = hex_bint( $alg->hexdigest );
        $alg->reset;
        $s = $seed + 1;
        $s %= two_pow($g);
        $alg->add_bits( substr( $s->as_bin, 2 ) );
        $U = $seed_digest ^ hex_bint( $alg->hexdigest );
        $q = $U | two_pow(159) | 1;
        next unless is_probably_prime($q);
        my $offset = 2;

        for ( my $counter = 0 ; $counter < 4096 ; ++$counter ) {
            my @v = ();
            for my $k ( 0 .. $n ) {
                $alg->reset;
                $s = $seed + $offset + $k;
                $s %= $twopowG;
                $alg->add_bits( substr( $s->as_bin, 2 ) );
                push @v, hex_bint( $alg->hexdigest );
            }
            $W = 0;
            for ( my $i = 0 ; $i < $n ; ++$i ) {
                $W += $v[$i] * two_pow( $i * 160 );
            }
            $W += ( $v[$n] % two_pow($b) ) * two_pow( $n * 160 );
            $X = $W + two_pow( $L - 1 );
            $c = $X % ( $q * 2 );
            $p = $X - ( $c - 1 );
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

# Rabin-Miller primality test
sub is_probably_prime {
    my ( $w, $k ) = @_;
    $k = 50 unless $k;
    $w = bint($w) unless ref $w;
    require Crypt::ECDSA;
    return Crypt::ECDSA::gmp_is_probably_prime( $w->{value}, $k );
}

sub validate_pq_seed_counter_sha1 {
    croak "Not implemented yet";
}

=head1 NAME

Crypt::ECDSA::Util -- Utility functions for Crypt::ECDSA

=head1 DESCRIPTION

  These are for use with Crypt::ECDSA and require Math::BigInt::GMP.


=head1 METHODS

=over 4

=item B<bint>

  bint( $scalar );
  Mostly a shortcut for Math::GMPz->new( ).
  
  Makes a new Math::GMPz type bigint arbitrary sized integer 
  from a scalar argument or another bigint.

=item B<two_pow>

  my $two_to_the_power_of_n = two_pow( $n );

  Returns a new bigint equal to 2 ** $n.
  
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
