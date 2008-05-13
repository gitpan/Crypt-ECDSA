package Crypt::ECDSA;

our $VERSION = '0.069';

use strict;
use warnings;
use Carp qw( carp croak );
use Digest::SHA;

use Crypt::ECDSA::Util qw( bint hex_bint random_bits );
use Crypt::ECDSA::Key;
require Exporter;
require DynaLoader;
our @ISA = qw(Exporter DynaLoader);
our @EXPORT_OK = qw( multiply_F2m invert_F2m gmp_is_probably_prime 
                ecdsa_sign_hash ecdsa_verify_hash );

bootstrap Crypt::ECDSA $VERSION;

my $DEBUG = 0;

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
    return hex_bint( $self->{algo}->hexdigest );
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
    my $Gx = $G->{X};
    my $Gy = $G->{Y};
    my $d = bint( $self->{key}->{d} );
    my $a = $key->curve->{a};
    my $a_neg = ($a < 0 ) ? 1 : 0;
    my $r = bint(1);
    my $s = bint(1);
    my $max_tries = 120;
    my $is_binary = $key->curve->{irreducible} ? 1 : 0;      
    my $n   = bint( $key->G->order );
    my $mod = bint( $key->curve->{modulus} );
    unless($n) {
        carp("Cannot sign curve without a point of known order");
        return;
    }
    if( $args{ message_file} ) {
        open( my $infh, '<', $args{message_file} )
          or croak( "cannot open file $args{message_file}: $!" );
        binmode $infh;
        read( $infh, $args{message}, -s $infh );
        close $infh;
    }
    my $e = $args{hash}
      || ( $args{message} ? $self->make_text_digest($args{message}) :
           croak("Need a message or the hash of a message for the signature" ) )
    ;
    ecdsa_sign_hash( $r->{value}, $s->{value}, $e->{value}, $Gx->{value}, 
      $Gy->{value}, $n->{value}, $d->{value}, $mod->{value}, $a->{value}, 
      $a_neg, $is_binary, $max_tries );
      
    warn "XS signature: r is $r, s is $s\n" if $DEBUG;

    if( $r != 0 ) {
        if( $args{sig_file} ) {
            Crypt::ECDSA::PEM::write_ECDSA_signature_file
              ( $args{sig_file}, bint($r), bint($s) );
        }
        return ( $r, $s );
    }
    else { 
        $self->{_last_ECDSA_error} =
      "Failed with getting digest (r,s) in signature after $max_tries tries";
    }
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
    unless( defined $key->{Q} ) {
        carp( "Need a Q point in key for ecdsa verify" );
        return;
    }
    my $Gx = $key->{G}->{X};
    my $Gy = $key->{G}->{Y};
    my $Qx = $key->{Q}->{X};
    my $Qy = $key->{Q}->{Y};
    my $d = bint( $self->{key}->{d} );
    my $a = $key->curve->{a};
    my $a_neg = ($a < 0 ) ? 1 : 0;
    my $is_binary = $key->curve->{irreducible} ? 1 : 0;      
    my $n   = bint( $key->G->order );
    my $mod = bint( $key->curve->modulus );
    unless($n) {
        carp("Cannot verify public point without knowing its base point's order");
        return;
    }
    my( $r, $s ) = $args{sig_file}
      ? Crypt::ECDSA::PEM::read_ECDSA_signature_file( $args{sig_file} )
      : ( bint( $args{r} ), bint( $args{'s'} ) )
    ;
    if( $args{ message_file} ) {
        open( my $infh, '<', $args{message_file} )
          or croak( "cannot open file $args{message_file}: $!" );
        binmode $infh;
        read( $infh, $args{message}, -s $infh );
        close $infh;
    }
    my $e = $args{hash}
      || ( $args{message} ? $self->make_text_digest($args{message}) :
           croak("Need a message or the hash of a message for the signature" ) )
    ;
    warn "begin verify:  r is $r, s is $s\n" if $DEBUG;
    
    return ecdsa_verify_hash( $r->{value}, $s->{value}, $e->{value}, 
      $Gx->{value}, $Gy->{value}, $Qx->{value}, $Qy->{value}, 
      $n->{value}, $mod->{value}, $a->{value}, $a_neg, $is_binary );
}

# this is a function NOT a method (no self argument)
sub sidechannel_protection {
    my( $setting ) = @_;
    return ( defined $setting ) ?
        _set_sidechannel_protection($setting) : _get_sidechannel_protection();
}


=head1 NAME

Crypt::ECDSA -- Elliptical Cryptography Digital Signature Algorithm

=head1 DESCRIPTION

    An implementation of the elliptic curve digital signature algorithm in Perl,
    using the Math::BigInt::GMP library and a little C for speed.

    Implements the pending FIPS 186-3 ECDSA standard for digital signatures using
    elliptical key crytography.  Routines include a working implementation of 
    elliptical key cryptography.  Perhaps a preliminary version of signature
    in the newer standard might be the following, which uses SHA-256 instead of the
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

    my $msg = "This is a test message for perl ecdsa."

    my ( $r, $s ) = $ecdsa->signature( message => $msg );

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

    my ( $r, $s ) = $ecdsa->signature( message => $msg );
    
    my( $r, $s ) = $ecdsa->signature( hash => $digest );
    
    $ecdsa->signature( message_file => $filename, sig_file => $outfilename );

  Sign a message as message => message or a digest as hash => $digest
  
  Optionally, the message_file is a file to be hashed and signed, and the 
  sig_file is a file to which a DER encoded (r,s) signature pair is written.

=item B<sign>

  Sign is a synonym for signature

=item B<verify_public_key>

  Verify a public key point, as in the Crypt::ECDSA::Key methods

=item B<verify>

    my $msg = "This is a test message fpr perl ecdsa."
    my $digest = ecdsa->make_text_digest( $msg );
    my $verify_ok = $ecdsa->verify( r => $r, 's' => $s, message => $msg );
    my $verify_ok = $ecdsa->verify( r => $r, 's' => $s, hash => $digest );

    $ok = $ecdsa->verify( message => $msg, r => $r, 's' => $s );   
    $ok = $ecdsa->verify( r => $r, s => $s, hash => $digest );
    $ok = $ecdsa->verify( message_file => $filename, sig_file => $sigfilename );

  Verify a message as message => message or a digest as hash => $digest
  
  Optionally, the message_file is a file to be hashed and verified against the 
  sig_file, which is a file to which a DER encoded (r,s) signature pair has
  been written.

  Verify as message given  r, s, and either message or its digest

=back

=head2 Package Non-object (Static) Functions

=over 4

=item B<ecdsa_sign_hash>

ecdsa_sign_hash( r, s, hash, gx, gy, q, d, mod, a, is_binary, max_tries );
  
Direct call to the XS routine, with numbers as Math::BigInt::GMP values fields.
Places the r and s values of the signature in r and s.
  
=item B<ecdsa_verify_hash>

ecdsa_verify_hash( r, s, hash, gx, gy, qx, qy, q, mod, a, is_binary );

Direct call to the XS routine.  Returns 1 if hash verifies, 0 if not.

=item B<sidechannel_protection>

  sidechannel_protection(1);  # slightly safer from hardware snooping

  $side_channels_normalized = sidechannel_protection();  # 1
  
  sidechannel_protection(0);  # slightly faster with prime field multiplies
  
Off by default.

Set or get an option to normalize doubling/adding calculation methods during 
ECC multiplication to make side-channel snooping more difficult. This is a 
security feature which seems to incur a 0 to 10% performance hit, less with
binary curves than prime field curves. If the ECC computation is to be run on 
a PC or larger general purpose computing device, side-channel vulnerability 
protection is probably unnecessary since most persons with access to the 
inner physical side channels of such a device would also be able to access 
protected data more simply.  With dedicated small devices such protection may 
be of value.  It may be useful to check the specifics of your CPU and/or device
to see if side channels would be an issue.

=back

=head2 Class Internal Functions

=over 4

=item B<add_F2m_point>

=item B<add_Fp_point>

=item B<double_F2m_point>

=item B<double_Fp_point>

=item B<gmp_is_probably_prime>

=item B<gmp_random_bits>

=item B<invert_F2m>

=item B<is_F2m_point_on_curve>

=item B<is_Fp_point_on_curve>

=item B<is_valid_point>

=item B<multiply_F2m>

=item B<multiply_F2m_point>

=item B<multiply_Fp_point>

=back

=head1 NOTES

=over 4

=item B<See FIPS 186-3, draft standard>

  Note the use of SHA-1 hashing is becoming deprecated, but is still the default.
  SHA-256 hashing may be used instead of SHA-1 when practicable.

=item See also L<http://en.wikipedia.org/wiki/Elliptic_Curve_DSA>, quoted below:

  Signature generation algorithm

  Suppose Alice wants to send a signed message to Bob.
  Initially, the curve parameters (q,FR,a,b,G,n,h) must be agreed upon.
  Also, Alice must have a key pair suitable for elliptic curve cryptography,
  consisting of a private key dA (a randomly selected integer in the
  interval [1,n - 1]) and a public key QA (where QA = dAG).

  For Alice to sign a message m, she follows these steps:

   1. Calculate e = HASH(m), where HASH is a cryptographic hash function, such as SHA-1.
   2. Select a random integer k from [1,n - 1].
   3. Calculate r = x1(mod n), where (x1,y1) = kG. If r = 0, go back to step 2.
   4. Calculate s = k**(-1)*(e + dAr)(mod n). If s = 0, go back to step 2.
   5. The signature is the pair (r,s).

  Signature verification algorithm

  For Bob to authenticate Alice's signature, he must have a copy of her
  public key QA. He follows these steps:

   1. Verify that r and s are integers in [1,n - 1]. If not, the signature is invalid.
   2. Calculate e = HASH(m), where HASH is the same function used in the signature generation.
   3. Calculate w = s**(-1)(mod n).
   4. Calculate u1 = ew(mod n) and u2 = rw(mod n).
   5. Calculate (x1,y1) = u1G + u2QA.
   6. The signature is valid if x1 = r(mod n), invalid otherwise.

=back

=head1 AUTHOR

William Herrera (wherrera@skylightview.com)

=head1 COPYRIGHT

  Copyright (C) 2007, 2008 William Hererra.  All Rights Reserved.

  This module is free software; you can redistribute it and/or modify it
  under the same terms as Perl itself.


=cut

1;


