use Test::More tests => 10;

use strict;
use warnings;
require 5.008;
use Data::Compare qw( Compare );

use_ok( 'Crypt::ECDSA::ECDSAVS' );

# check all points
our $WARN_IF_NEW_POINT_INVALID = 1;

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
  "ECDSA Public Key check is ok for P-192" );
ok(Compare( $own_pkv_hashes->{'K-233'}, $correct_pkv_hashes->{'K-233'} ), 
  "ECDSA Public Key check is ok for K-233" );

my ( $own_sigver_hashes, $own_sigver_comments ) = 
  Crypt::ECDSA::ECDSAVS::process_lines( 
    Crypt::ECDSA::ECDSAVS::read_file('SigVer_response') );
my ( $correct_sigver_hashes, $correct_sigver_comments ) = 
  Crypt::ECDSA::ECDSAVS::process_lines( 
    Crypt::ECDSA::ECDSAVS::read_file('SigVer_correct') );

ok(Compare( $own_sigver_hashes->{'P-192'}->{Result}, $correct_sigver_hashes->{'P-192'}->{Result} ), 
  "ECDSA signature verification check is ok for P-192" );
ok(Compare( $own_sigver_hashes->{'K-233'}->{Result}, $correct_sigver_hashes->{'K-233'}->{Result} ), 
  "ECDSA signature verification check is ok for K-233" );
