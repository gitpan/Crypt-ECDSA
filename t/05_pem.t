use Test::More tests => 32;

use strict;
require 5.008;

use_ok( 'Crypt::ECDSA' );
use_ok( 'Crypt::ECDSA::Point' );
use_ok( 'Crypt::ECDSA::Key' );
use_ok( 'Crypt::ECDSA::PEM' );

# check all points
our $WARN_IF_NEW_POINT_INVALID = 1;

my $ecdsa = Crypt::ECDSA->new( standard => 'ECP-256', PEM => 't/test1ecdsa.pem' );
isa_ok( $ecdsa, 'Crypt::ECDSA' );
my $pem1test = Crypt::ECDSA::PEM->new( Filename => 't/test2pem.pem' );
isa_ok( $pem1test, 'Crypt::ECDSA::PEM' );
$pem1test->key_to_private_pem( $ecdsa->key );
my $pem3test = Crypt::ECDSA::PEM->new( Filename => 't/test2pem.pem' );
isa_ok( $pem3test, 'Crypt::ECDSA::PEM' );


my $oid = $pem3test->{ec_parameters_tree}->{namedCurve};
ok( $oid eq '1.3.132.0.10', "PEM curves parameters ( $oid )ok");
ok( ! defined $pem3test->{ec_parameters_tree}->{standard}, 
  "Unlabeled OPENSSL standard secp256k1");
  
my $key = $ecdsa->key();
ok( $key->curve->is_on_curve( $key->Qx, $key->Qy ), "PEM public key is ok" );
ok ( $key->Q == $key->G * $key->secret, "PEM key parameters are ok" );

my $orig_x = $key->Qx;
my $orig_y = $key->Qy;
my $orig_secret = $key->secret;
my $written = $pem1test->write_PEM( 
    filename => 't/test1out.pem',
    key => $key,
    private => 1,
);
ok( $written > 0, "PEM writing with a private key");

my $ecdsa_reread = Crypt::ECDSA->new( PEM => 't/test1out.pem' );
isa_ok( $ecdsa_reread, 'Crypt::ECDSA' );

my $key_reread = $ecdsa_reread->key();
my $new_x = $key_reread->Qx;
my $new_y = $key_reread->Qy;
ok($orig_x == $new_x, "PEM and back ok with X");
ok($orig_y == $new_y, "PEM and back ok with Y");

my $ecdsa_aes128 = Crypt::ECDSA->new( standard => 'ECP-256', 
  PEM => 't/test1aes128ec.pem', Password => 'aes128ecaes128ec' );
isa_ok( $ecdsa_aes128, 'Crypt::ECDSA' );
ok($orig_x == $ecdsa_aes128->key->Qx, "crypted x with aes128");
ok($orig_y == $ecdsa_aes128->key->Qy, "crypted y with aes128");
ok($orig_secret == $ecdsa_aes128->key->secret, "crypted d with aes128");

$pem1test->write_PEM( key => $key_reread, private => 1, Password => 'aes128',  
                      filename => 't/test2out.pem' );

my $ecdsa_rw = Crypt::ECDSA->new( standard => 'ECP-256', 
  PEM => 't/test2out.pem', Password => 'aes128' );
isa_ok( $ecdsa_rw, 'Crypt::ECDSA' );
ok($orig_x == $ecdsa_rw->key->Qx, "crypted x with aes128");
ok($orig_y == $ecdsa_rw->key->Qy, "crypted y with aes128");
ok($orig_secret == $ecdsa_rw->key->secret, "crypted d with aes128");

my $ecdsa_des3 = Crypt::ECDSA->new( standard => 'ECP-256', 
  PEM => 't/test1des3.pem', Password => 'des3' );
isa_ok( $ecdsa_des3, 'Crypt::ECDSA' );
ok($orig_x == $ecdsa_des3->key->Qx, "crypted x with des3");
ok($orig_y == $ecdsa_des3->key->Qy, "crypted y with des3");
ok($orig_secret == $ecdsa_des3->key->secret, "crypted d with des3");

my $ecdsa_bf = Crypt::ECDSA->new( standard => 'ECP-256', 
  PEM => 't/test1bf.pem', Password => 'bf-cbc' );
isa_ok( $ecdsa_bf, 'Crypt::ECDSA' );
ok($orig_x == $ecdsa_bf->key->Qx, "crypted x with Blowfishd");
ok($orig_y == $ecdsa_bf->key->Qy, "crypted y with Blowfishd");
ok($orig_secret == $ecdsa_bf->key->secret, "crypted d with Blowfish");

$ecdsa->sign( 
  message_file => 't/Gettysburg.jpg', 
  sig_file => 't/Gettysburg.jpg.sha1',
);

ok( $ecdsa->verify( 
  message_file => 't/Gettysburg.jpg', 
  sig_file => 't/Gettysburg.jpg.sha1' 
  ) == 1, "read and write sig file"
);




