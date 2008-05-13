use Test::More tests => 17;

use strict;
require 5.008;

use Crypt::ECDSA::Util qw( bint hex_bint );

# check all points
#our $WARN_IF_NEW_POINT_INVALID = 1;

# First, some ECDSA FIPS 186-3 stuff from Crypt::ECDSA::Util

# check on prime checks

my @prime = qw( 49919 49921 49927 49937 49939 49943 49957 49991 49993 49999 );
my @not_prime = qw( 49923 49931 49997 );

# check primes via our function is_probably_prime
my $checked_primes_ok = 1;
for my $n (@prime) {
    if ( ! Crypt::ECDSA::Util::is_probably_prime( bint($n) ) ) {
        warn "$n is not checking as prime";
        $checked_primes_ok = 0;
    }
    ok( $checked_primes_ok, "Prime $n is checked ok as prime" );
    $checked_primes_ok = 1;
}

# check non-primes via our function is_probably_prime
my $checked_non_primes_ok = 1;
for my $nn (@not_prime) {
    if ( Crypt::ECDSA::Util::is_probably_prime( bint($nn) ) ) {
        warn "$nn is checking as prime";
        $checked_non_primes_ok = 0;
    }
    ok( $checked_non_primes_ok, "Non-prime $nn is checked ok as not prime" );
    $checked_non_primes_ok = 1;
}

# test some prime generation routines
# Generate and check a prime pair for DSA per FIPS 186-3
my $L       = 2048;
my $N       = 256; 
my $seedlen = 256;
my ( $p, $q, $seed, $counter ) =
  Crypt::ECDSA::Util::make_pq_seed_counter_new( $L, $N, $seedlen );
my $q_len = length( $q->as_bin ) - 2;
ok( $q_len == $N, "prime $q length $q_len is $N bits" );
my $p_len = length( $p->as_bin ) - 2;
ok( $p_len == $L, "prime $p length $p_len is $L bits" );


# Generate and check a prime pair for DSA per FIPS 186-2 with SHA1
# this is commonly used but is deprecated as of 2007
$L       = 1024;
$seedlen = 164;
( $p, $q, $seed, $counter ) =
  Crypt::ECDSA::Util::make_seed_and_pq_with_sha1( $L, $seedlen );
$q_len = length( $q->as_bin ) - 2;
ok( $q_len == 160, "prime $q length $q_len is 160 bits" );
$p_len = length( $p->as_bin ) - 2;
ok( $p_len == $L, "prime $p length $p_len is $L bits" );

