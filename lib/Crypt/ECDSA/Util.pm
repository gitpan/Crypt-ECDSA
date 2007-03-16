package Crypt::ECDSA::Util;

our $VERSION = '0.045';

use strict;
use warnings;
require Exporter;
our @ISA    = qw(Exporter);
our @EXPORT = qw( 
  two_pow random_bits bigint_from_coeff is_probably_prime 
  make_pq_seed_counter_new make_seed_and_pq_with_sha1 
  validate_pq_seed_counter_sha1 bint bint_hex
);
use Carp qw(carp croak);
use POSIX qw(ceil);
use Math::GMPz qw( :mpz :primes );
use Digest::SHA;

sub bint { 
    my( $n ) = @_;
    $n = 0 unless defined $n;
    if( !ref $n and length $n > 2 ) {
        if( $n =~ /^0b/i ) {
            $n =~ s/^0b//;
            return Rmpz_init_set_str( $n, 2 );
        }
        elsif($n =~ /^0x/i ) {
            $n =~ s/^0x//;
            return Rmpz_init_set_str( $n, 16 );
        }
        else {
            return Rmpz_init_set_str( $n, 10 );
        }
    }
    return Math::GMPz->new($n);    
}

sub two_pow { 
    my ($exp) = @_;
    my $a = bint(1);
    Rmpz_mul_2exp( $a, $a, $exp );    
    return $a;
}

# returns a bigint given a list of exponents for a
# polynomial of base 2, so [ 3 1 0 ] = 2**3 + 2**1 + 2**0 = 8 + 2 + 1
sub bigint_from_coeff {
    my $arrayref = shift;
    my $n        = bint(0);
    for my $t (@$arrayref) { $n += two_pow($t) }
    return $n;
}

sub random_bits {
    my( $bitlength ) = @_;
    my @r;
    push @r, Rmpz_init();
    my $state = rand_init( bint( int rand(10000) + (time % 100) ) );
    Rmpz_urandomb( @r, $state, $bitlength, 1 );
    rand_clear($state);
    return $r[0];
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
    my $q        = Rmpz_init();
    my $p        = Rmpz_init();
    my $X        = Rmpz_init();
    my $c        = Rmpz_init();
    my $W        = Rmpz_init();
    while (1) {
        my $seed = random_bits( $seedlen );
        my $seed_digest = $alg->add_bits( Rmpz_get_str( $seed, 2 ) );
        my $U = Rmpz_init_set_str( $seed_digest->hexdigest, 16 ) % $twopowN;
        $q = $U | $twopowN1 | 1;
        next unless is_probably_prime($q);
        my $offset = 1;
        for ( my $counter = 0 ; $counter < 4096 ; ++$counter ) {
            my @v = ();
            for my $j ( 0 .. $n ) {
                $alg->reset;
                $alg->add_bits( 
                  Rmpz_get_str( bint( $seed + $offset + $j ) % $twopowS , 2 )
                );
                push @v, Rmpz_init_set_str( $alg->hexdigest, 16 );
            }
            Rmpz_set_ui( $W, 0 );
            for ( my $i = 0 ; $i < $n ; ++$i ) {
                $W += $v[$i] * two_pow( $outlen * $i );
            }
            $W +=  ( $v[$n] % two_pow($b) ) * two_pow( $n * $outlen );
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
    my $q        = Rmpz_init();
    my $p        = Rmpz_init();
    my $X        = Rmpz_init();
    my $c        = Rmpz_init();
    my $U        = Rmpz_init(); 
    my $W        = Rmpz_init(); 
    my $s        = Rmpz_init();     
    while (1) {
        my $seed = random_bits( $g );
        my $alg = Digest::SHA->new(1);
        $alg->add_bits( Rmpz_get_str( $seed, 2 ) );
        my $seed_digest = Rmpz_init_set_str( $alg->hexdigest, 16 );
        $alg->reset;
        $s = $seed + 1;
        $s %= two_pow($g);
        $alg->add_bits( Rmpz_get_str( $s, 2 ) );
        $U = $seed_digest ^ Rmpz_init_set_str( $alg->hexdigest, 16 );
        $q = $U | two_pow( 159 ) | 1;
        next unless is_probably_prime($q);
        my $offset = 2;

        for ( my $counter = 0 ; $counter < 4096 ; ++$counter ) {
            my @v = ();
            for my $k ( 0 .. $n ) {
                $alg->reset;
                $s = $seed + $offset + $k;
                $s %= $twopowG;
                $alg->add_bits( Rmpz_get_str( $s, 2 ) );
                push @v, Rmpz_init_set_str( $alg->hexdigest, 16 );
            }
            Rmpz_set_ui( $W, 0 );
            for ( my $i = 0 ; $i < $n ; ++$i ) {
                $W +=  $v[$i] * two_pow( $i * 160 );
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

sub is_probably_prime {
    my ($w) = @_;
    return unless $w;
    $w = bint($w) unless ref $w;
    return unless $w > 1;
    return 1 if $w < 4;

    return Rmpz_probab_prime_p( $w, 48 );
}

sub validate_pq_seed_counter_sha1 {
    croak "Not implemented yet";
}


=head1 NAME

Crypt::ECDSA::Util -- Utility functions for Crypt::ECDSA

=head1 DESCRIPTION

These are for use with Crypt::ECDSA, a Math::GMPz based cryptography module

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
