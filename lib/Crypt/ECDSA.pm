package Crypt::ECDSA;

our $VERSION = '0.045';

use strict;
use warnings;
use Carp qw( carp croak );
use Math::GMPz qw( :mpz );
use Digest::SHA;

use Crypt::ECDSA::Key;
use Crypt::ECDSA::Util qw( bint random_bits );

require Exporter;
require DynaLoader;

our @ISA = qw(Exporter DynaLoader);
our @EXPORT = qw( multiply_F2m invert_F2m );
bootstrap Crypt::ECDSA $VERSION;

sub new {
    my ( $class, %args ) = @_;
    my $self = {};
    bless $self, $class;
    $self->{key} = Crypt::ECDSA::Key->new(%args);
    my $algo = ( $args{algorithm} ) ? $args{algorithm} : Digest::SHA->new(1);
    $self->{algo} = $algo;
    return $self;
}

sub key {
    my ( $self, $new_key ) = @_;
    $self->{key} = $new_key if $new_key;
    return $self->{key};
}

sub errstr {
    my ($self) = @_;
    my $errmsg = $self->{_last_ECDSA_error} || $!;
    return $errmsg;
}

sub keygen {
    my ($self) = @_;
    $self->{key}->new_secret_value();
    return ( $self->{key}->{d}, $self->{key}->{G} );
}

sub is_valid_point { verify_public_key( @_ ) }

sub make_text_digest {
    my ( $self, $text ) = @_;
    $self->{algo}->reset;
    $self->{algo}->add( $text );
    return Rmpz_init_set_str( $self->{algo}->hexdigest, 16 );
}

sub _make_k_kinv_pair {
    my( $self, $n ) = @_;
    my $len = length( Rmpz_get_str( $n, 16 ) );
    my $k = Rmpz_init();
    my $kinv = Rmpz_init();
    $k = random_bits( ($len + 8) * 16 ) % ( $n - 1 ) + 1;
    Rmpz_invert( $kinv, $k, $n );
    return unless Rmpz_sgn($k) and Rmpz_sgn($kinv);
    return ($k, $kinv);
}

sub signature {
    my ( $self, %args ) = @_;

    # first some error checks
    my $key = $self->key;
    my $G = $key->{G};
    unless( $key->curve->is_on_curve($G->X, $G->Y) ) {
        carp(" Bad private key for signature");
        return;
    }
    my $q  = bint( $key->curve->q );
    my $n  = bint( $G->{order} );
    unless($n) {
        carp("Cannot sign curve without a point of known order");
        return;
    }
    my $e = $args{hash} 
      || ( $args{message} ? $self->make_text_digest($args{message}) : 
           croak("Need a message or the hash of a message for the signature" ) )
    ;
    my $d = bint( $self->{key}->{d} );
    my $max_tries = 12;
    my($r, $s);
    while ( $max_tries-- ) {
        my($k, $kinv) = $self->_make_k_kinv_pair($q);
        my $kG = $G * $k;
        $r  = bint( $kG->{X} );
        next unless Rmpz_sgn($r);
        $s = ( $kinv * ( $e + ( $d * $r )% $n ) ) % $n;
        next unless Rmpz_sgn($s);
        return ( $r, $s );
    }
    $self->{_last_ECDSA_error} =
      "Failed with getting digest (r,s) = ($r, $s) in signature after $max_tries tries";
    return;
}

# sign is a synonym for signature
sub sign { signature(@_) }

# check a public key provided for validity, given a curve
sub verify_public_key {
    my ( $self, $Qx, $Qy ) = @_;
    return $self->key->verify_public_key( $Qx, $Qy );
}

sub verify {
    my ( $self, %args ) = @_;
    my $key = $self->key;
    # some error checks
    my $q = $self->key->curve->q;
    my $G = $self->key->{G};
    my $n = $self->key->curve->order;
    unless($n) {
        carp("Cannot verify public point without knowing its base point's order");
        return;
    }
    my $r = $args{r};
    my $s = $args{'s'};
    return if $r < 1 or $r >= $q;
    return if $s < 1 or $s >= $q;
    my $e = $args{hash} 
      || ( $args{message} ? $self->make_text_digest($args{message}) : 
           croak("Need a message or the hash of a message for the signature" ) )
    ;
    my $w  = Rmpz_init;
    my $invert_ok = Rmpz_invert( $w, $s, $n );
    unless( $invert_ok ) {
        carp( "Error: s and n are not coprime in signature verify" );
        return;
    }
    my $u_g = Rmpz_init;
    my $u_r = Rmpz_init;
    $u_g = ( $e * $w ) % $n;
    $u_r = ( $r * $w ) % $n;
    my $prod = $G * $u_g + $key->Q * $u_r;
    return 1 if $prod->{X} % $n == $r;
    return 0;
}

=head1 NAME

Crypt::ECDSA -- Elliptical Cryptography Digital Signature Algorithm

=head1 DESCRIPTION

    An implementation of the elliptic curve digital signature algorithm in Perl,
    using the Math::GMPz library and a little C for speed.

    Implements the pending FIPS 186-3 ECDSA standard for digital signatures using
    elliptical key crytography.  Like FIPS 186-3, this is preliminary-- not yet 
    ready for full use.  It does contain a working implementation of the elliptical 
    key crypto found in the current 186-2 standard.  The final details of the 186-3 
    standard are still being worked out.  Perhaps a preliminary version of signature
    in the NEW standard might be the following, which uses SHA-256 instead of the
    current SHA-1 digest:
    
    my $ecdsa = Crypt::ECDSA->new( 
      standard => 'ECP-256',
      algorithm => Digest::SHA->new(256);
    );
    my $msg = "This is a test message for perl ecdsa."    
    my ( $r, $s ) = ecdsa->signature( message => $msg );

    print "Signature (r, s) is: \nr = $r\ns = $s\n";
    
    
=head1 SYNOPSIS

    my $ecdsa = Crypt::ECDSA->new( standard => 'ECP-256' );
    
    my $msg = "This is a test message fpr perl ecdsa."
    
    my ( $r, $s ) = ecdsa->signature( message => $msg );
    
    my $verify_ok = $ecdsa->verify( r => $r, 's' => $s, message => $msg );

    my $ecdsa_from_PEM = Crypt::ECDSA->new( PEM => $pem_filename );


=head1 METHODS

=over 4

=item B<new>
  
  Create an ECDSA object.
  
  Arguments include:
  
  standard => curve type, one of 'ECP-192', 'ECP-224', 'ECP-256', 'ECP-384',
    'ECP-521', 'EC2N-163', 'EC2N-233', 'EC2N-283', 'EC2N-409', 'EC2N-571',
    
  algorithm => $algo,  where $algo is a Digest::SHA interface compatible object,
    which defaults to Digest::SHA(1) which does SHA-1 digests for ECDSA.
    
  .. and other arguments, used as per Crypt::ECDSA::Key.
  
);
  
  
  
=item B<key>

  my $key = $ecdsa->key;

  Get the key object in use by this ecdsa object

=item B<errstr> 

  print $ecdsa->errstr;

  Get the last internal error message

=item B<keygen>

  if( $want_new_key ) {  $
    my( $secret, $base_point ) = ecdsa->keygen(); 

  Make a new private/ public key pair

=item B<make_text_digest>

    my $msg = "This is a test message fpr perl ecdsa."
    
    my  $digest = ecdsa->make_text_digest( $msg );

  Make a text digest via the algorithm passed to new ( default is SHA-1 )

  
=item B<signature>

    
    my ( $r, $s ) = ecdsa->signature( message => $msg );
    
  Sign a message as message => message or a digest as hash => $digest

=item B<sign>

  Sign is a synonym for signature

=item B<verify_public_key>

  Verify a public key point, as in the Crypt::ECDSA::Key method 

=item B<verify>

  Verify as message given  r, s, and either message or its digest


    my $msg = "This is a test message fpr perl ecdsa."
    my $digest = ecdsa->make_text_digest( $msg );
    my $verify_ok = $ecdsa->verify( r => $r, 's' => $s, message => $msg );
    my $verify_ok = $ecdsa->verify( r => $r, 's' => $s, hash => $digest );


=back

=head1 NOTES

=item B<See FIPS 186-3, draft standard>
  Note the use of SHA-1 hashing is becoming deprecated, but is still the default.  
  SHA-256 hashing may be used instead of SHA-1 when practicable.

=item See also L<http://en.wikipedia.org/wiki/Elliptic_Curve_DSA>, quoted below:

  Signature generation algorithm

  Suppose Alice wants to send a signed message to Bob. 
  Initially, the curve parameters (q,FR,a,b,G,n,h) must be agreed upon. 
  Also, Alice must have a key pair suitable for elliptic curve cryptography, 
  consisting of a private key dA (a randomly selected integer in the 
  interval [1,n ? 1]) and a public key QA (where QA = dAG).

  For Alice to sign a message m, she follows these steps:

   1. Calculate e = HASH(m), where HASH is a cryptographic hash function, such as SHA-1.
   2. Select a random integer k from [1,n ? 1].
   3. Calculate r = x1(mod n), where (x1,y1) = kG. If r = 0, go back to step 2.
   4. Calculate s = k ? 1(e + dAr)(mod n). If s = 0, go back to step 2.
   5. The signature is the pair (r,s).

  Signature verification algorithm

  For Bob to authenticate Alice's signature, he must have a copy of her 
  public key QA. He follows these steps:

   1. Verify that r and s are integers in [1,n ? 1]. If not, the signature is invalid.
   2. Calculate e = HASH(m), where HASH is the same function used in the signature generation.
   3. Calculate w = s ? 1(mod n).
   4. Calculate u1 = ew(mod n) and u2 = rw(mod n).
   5. Calculate (x1,y1) = u1G + u2QA.
   6. The signature is valid if x1 = r(mod n), invalid otherwise.

=head1  TODO

    Currently I know of no working non-Cygwin Windows versions of the library needed by 
    Math::GMPz.  The GMP library is available for most other systems. I may try to 
    create a PPD file for PPM.
    
    The Koblitz curve point multiplication algorithm could be optimized a bit more.

=head1 AUTHOR

William Herrera (wherrera@skylightview.com)

=head1 COPYRIGHT

  Copyright (C) 2007 William Hererra.  All Rights Reserved.

  This module is free software; you can redistribute it and/or modify it
  under the same terms as Perl itself.

 
=cut

1;


