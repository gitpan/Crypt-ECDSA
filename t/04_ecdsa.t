use Test::More tests => 10;

use strict;
use warnings;
require 5.006;
use Data::Compare qw( Compare );

use_ok( 'Crypt::ECDSA::ECDSAVS' );

# Run a simulated ECDSAVS verification set
# See Bassham, NIST, 2004 ( ECDSAVS )

my $ecdsavs = Crypt::ECDSA::ECDSAVS->new();

my $callback = sub { ok( 1, shift ) };

$ecdsavs->do_all_tasks( $callback );

my ( $own_pkv_hashes, $own_pkv_comments ) = 
  Crypt::ECDSA::ECDSAVS::process_lines( 
    Crypt::ECDSA::ECDSAVS::read_file('PubKey_response') );
my ( $correct_pkv_hashes, $correct_pkv_comments ) = 
  Crypt::ECDSA::ECDSAVS::process_lines( 
    Crypt::ECDSA::ECDSAVS::read_file('PubKey_correct') );
    
ok(Compare( $own_pkv_hashes->{'P-192'}, $correct_pkv_hashes->{'P-192'} ), 
  "ECDSA Public Key check is ok" );

ok(Compare( $own_pkv_hashes->{'K-233'}, $correct_pkv_hashes->{'K-233'} ), 
  "ECDSA Public Key check is ok" );

my ( $own_sigver_hashes, $own_sigver_comments ) = 
  Crypt::ECDSA::ECDSAVS::process_lines( 
    Crypt::ECDSA::ECDSAVS::read_file('SigVer_response') );
my ( $correct_sigver_hashes, $correct_sigver_comments ) = 
  Crypt::ECDSA::ECDSAVS::process_lines( 
    Crypt::ECDSA::ECDSAVS::read_file('SigVer_correct') );

ok(Compare( $own_sigver_hashes->{'P-192'}, $correct_sigver_hashes->{'P-192'} ), 
  "ECDSA signature verification check is ok" );

ok(Compare( $own_sigver_hashes->{'K-233'}, $correct_sigver_hashes->{'K-233'} ), 
  "ECDSA signature verification check is ok" );


