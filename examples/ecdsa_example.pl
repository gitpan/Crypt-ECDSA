#!/usr/bin/perl

use strict;
use warnings;
use Crypt::ECDSA;
use Crypt::ECDSA::PEM;

my $ecdsa = Crypt::ECDSA->new( standard => 'ECP-256' );

my $msg = "This is a test message for perl ecdsa.";
my ( $r, $s ) = $ecdsa->signature( message => $msg );
my $verify_ok = $ecdsa->verify( r => $r, 's' => $s, message => $msg );

if( $verify_ok ) { print "ECDSA: verified." } else { print "not verified."; }

