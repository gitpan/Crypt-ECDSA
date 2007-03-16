use Test::More tests => 15;

use strict;
require 5.008;

use Math::GMPz qw( :mpz );

use_ok( 'Crypt::ECDSA::Util' );

# First, some ECDSA FIPS 186-3 stuff from Crypt::ECDSA::Util

# check on prime checks

my @prime = qw( 49919 49921 49927 49937 49939 49943 49957 49991 49993 49999 );

# check primes via our function is_probably_prime
my $checked_primes_ok = 1;
for my $n (@prime) {
    if ( ! Crypt::ECDSA::Util::is_probably_prime( Math::GMPz->new($n) ) ) {
        warn "$n is not checking as prime";
        $checked_primes_ok = 0;
    }
    ok( $checked_primes_ok, "Prime $n is checked ok as prime" );
    $checked_primes_ok = 1;
}

# test some prime generation routines
# Generate and check a prime pair for DSA per FIPS 186-3
my $L       = 2048;
my $N       = 256; 
my $seedlen = 256;
my ( $p, $q, $seed, $counter ) =
  Crypt::ECDSA::Util::make_pq_seed_counter_new( $L, $N, $seedlen );
my $q_len = length( Rmpz_get_str( $q, 2 ) );
ok( $q_len == $N, "prime q length $q_len is $N" );
my $p_len = length( Rmpz_get_str( $p, 2 ) );
ok( $p_len == $L, "prime p length $p_len is $L" );


# Generate and check a prime pair for DSA per FIPS 186-2 with SHA1
# this is commonly used but is deprecated as of 2007
$L       = 1024;
$seedlen = 164;
( $p, $q, $seed, $counter ) =
  Crypt::ECDSA::Util::make_seed_and_pq_with_sha1( $L, $seedlen );
$q_len = length( Rmpz_get_str( $q, 2 ) );
ok( $q_len == 160, "prime q length $q_len is 160" );
$p_len = length( Rmpz_get_str( $p, 2 ) );
ok( $p_len == $L, "prime p length $p_len is $L" );

