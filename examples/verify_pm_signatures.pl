#!/usr/bin/perl

use strict;
use warnings;
use File::Find;
use Crypt::ECDSA;

my $base_search_dir = "../lib/";

my $standard = 'ECP-256';

my $Qx =
    '0x83455c33571dd81f9c25978b2a0af6ce6ec6d981c692cb8c7dfe842a77076835';
my $Qy =
    '0x3baa447ce7dc079b8ff8ba2e98b423233eed979966415d5314b7c1743cf805e3';

my $package_files = {
'ECDSA.pm' => {
    r   => '0xb488559d23ac25e92e916c2d6d6cccf15ce292dd56e00e11cdc5af6c46b5becb',
    's' => '0x259ae7e85ea914f3aaa4f1bd3304a9befd3e6dec22fa06c9367367e4c7c68cbd',
    },
'Curve.pm' => {
    r   => '0x3471a413422812c7b483ffba4ddf54ece326a95c5ba0edec0175871319539148',
    's' => '0xd3d22b752181d73e6247189e205df73a943f8e7350b4418e3e119134f2ac1e62',
    },
'ECDSAVS.pm' => {
    r   => '0x5a9b852bb1513475ca122d6a2ae555b16a81317afa4aaeb365a5abcf67eab0e5',
    's' => '0x6dbbd3d2787b1d7bb7d0746d0e221c04bbfe9d79f585d6acec2005b1907504a',
    },
'Key.pm' => {
    r   => '0x9b02a45eac3b9b706f76ac30b4c8a63e028b77ec73ae16273cd9a2129901b2ef',
    's' => '0x72392f7874543340d752cb0fb55209132cf781a962248aca04396b710f542d3c',
    },
'PEM.pm' => {
    r   => '0x3770a8c4bab1cb65f838cae4cf41310d397d11663954a31ba27187860c152afc',
    's' => '0xf331df12fc866e5f2de51487f55945afc093b48b97121aaae96480be31223a63',
    },
'Point.pm' => {
    r   => '0x433849fdc71d3056cfda856e690b74291f4115dcdacc1f167d71975bc608ce17',
    's' => '0xcf7ca8ced0eaf827ec50579b402d59cb3e70bd046d4c4bf90046e1fc14d9251c',
    },
'Util.pm' => {
    r   => '0xb006ddfbfa2fd4fad5531d6ee284521faa2c6a8dc3b03a2c1fefc2d447bc2a34',
    's' => '0xb3289c6a365f7b7d6ff072101180b5726db8feec45c55a739f118bd98d767297',
    },
'Koblitz.pm' => {
    r   => '0xf9b1db6785aa4ceaaecb4f27277e7154557b5bfbc5ad3023365f662caad3bb57',
    's' => '0x79ab544d259e0c3ec85c2228dc5076d83b60d0529c28ae9813fe0499c676f859',
    },
'Prime.pm' => {
    r   => '0xed5062f508f1a9e4dc9b705813058155f5392d96b5858213abada10fd2203e80',
    's' => '0x208941580e003c54801cd398e41bbceac9d150a56e54d9d67f4ae339bc94fec6',
    },
};

my $ecdsa = Crypt::ECDSA->new( standard => 'ECP-256' );
$ecdsa->key->set_public_Q( $Qx, $Qy );

print "Qx as hex is\n", ($ecdsa->key->Qx)->as_hex, "\n\n";
print "Qy as hex is\n", ($ecdsa->key->Qy)->as_hex, "\n\n";

find( \&process_pm_signature, $base_search_dir );


sub process_pm_signature
{
    if( -f and m/\.pm$/ ) {
        my $filename = $_;
        if( exists $package_files->{$filename} ) {
            my $entry = $package_files->{$filename};
            my $r = $entry->{r};
            my $s = $entry->{'s'};
            my $verify_ok = 
              $ecdsa->verify( r => $r, 's' => $s, message_file => $filename );
            if( $verify_ok ) { 
                print "File $File::Find::name verified.\n"; 
            } 
            else { 
                print "File $File::Find::name NOT verified.\n"; 
            }
        }
    }
}

