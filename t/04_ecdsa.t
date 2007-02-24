use Test::More tests => 10;

use strict;
no warnings;
require 5.006;
use Data::Compare qw( Compare );

use_ok( 'Crypt::ECDSA::ECDSAVS' );

# Run a simulated partial verification set
# See Bassham, NIST, 2004 

my $ecdsavs = Crypt::ECDSA::ECDSAVS->new();

my $callback = sub { ok( 1, shift ) };

my $alternate_filename = {
    MakeApplication  => 't/Application.txt',
    KeyPair_request  => 't/KeyPair.req.brief',
    KeyPair_response => 't/KeyPair.rsp.brief',
    PubKey_request   => 't/PKV.req.brief',
    PubKey_response  => 't/PKV.rsp.brief',
    PubKey_correct   => 't/PKV.rsp.correct.brief',
    SigGen_request   => 't/SigGen.req.brief',
    SigGen_response  => 't/SigGen.rsp.brief',
    SigVer_request   => 't/SigVer.req.brief',
    SigVer_response  => 't/SigVer.rsp.brief',
    SigVer_correct   => 't/SigVer.rsp.correct.brief',
};

$Crypt::ECDSA::ECDSAVS::default_filename = $alternate_filename;

print STDERR "\n\nStarting partial ECDSAVS test suite. This may take a while...\n";

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


