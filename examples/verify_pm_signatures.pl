#!/usr/bin/perl

use strict;
use warnings;
use File::Find;
use Crypt::ECDSA;

my $base_search_dir = "../lib/";

my $standard = 'ECP-256';

my $Qx =
    '0xb03425bcb6d7dc76fbcc9ccd45c112ea2e7e179c0f55282de81cc8c7a7a731dc';
my $Qy =
    '0x89b802c72fd094779449ae0df0b7f53a66e5a5c34aa2478254bbcd981861aa37';

my $package_files = {
'ECDSA.pm' => {
    r   => '0x3345b04e96a3d70f3e7d795732a56423276de131723a3b0242507b282b33f70e',
    's' => '0x18ce3efed966fc46e0bc75d641d1258500fa1bd518675b70217f3b0cd353c7f2',
    },
'Curve.pm' => {
    r   => '0x678c637fcbd5f9b1c65f578739f7e25e98d48f1f30dd001e2ae8536dc2f090af',
    's' => '0x79cb061431544af21c6e8955edb7b9af91685eeede51883b970cb729093f6c87',
    },
'ECDSAVS.pm' => {
    r   => '0x4cbbd56968f134d1c5e364fb62667f9d89f26476d191f18868936a96f13b5c36',
    's' => '0x369c297a9c5d40e554af587aa14e347e40327b561fb217b8c3edb3c12f9a6f54',
    },
'Key.pm' => {
    r   => '0xa5c6b28df16e027eaa11c1df9afdd0c116a68147fe03c4d42bb1f05b9384a964',
    's' => '0xf0298d6f51745bcf1f8dcadbafe3258a9da9b1f5f6b3e9f5164537aa92d9212a',
    },
'PEM.pm' => {
    r   => '0x698b17343a32b91fd205c1b13a3e9b536483c532bfb935fd88feee6dfb3cec05',
    's' => '0x805aee17eb8e95262f60f3baa9b5a3960671fbb96d9f668a222c7c5c482c81ef',
    },
'Point.pm' => {
    r   => '0xab699c540c065e2b56d5e8f2a984f9b4aefd829b4050b03ec8e5f6b5c85aba39',
    's' => '0xaa5d8384bbf42f53c18ec927a9861e63e97ad0c4a4af5e12d80ab688168c3339',
    },
'Util.pm' => {
    r   => '0x4ab13ebd1f08dc1538ee6e7e8724082480c77014e2b1cf141fec8ecaa2d0c3d4',
    's' => '0xb2ff92d2ffb27fd612689ba79abf3ec4b0d606cb47d268f94f233981356504e9',
    },
'Koblitz.pm' => {
    r   => '0x11a867e21d76bf8ba4b683c357811e3c4677dbed8d32174523be5a97e4066da1',
    's' => '0xb47256459b06e5f25282fac780afae261f980036f90209c235460250ca6aeb9e',
    },
'Prime.pm' => {
    r   => '0xacea0efe1d74726d3cb4d37bf1cd6d14ce6ef202baabcd9fddeaffc7a9505706',
    's' => '0x89d595206ecf8d727caa7e7bbd831f9a203cf3852bb2d07c2ebdedf69a21a86f',
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

