package Crypt::ECDSA::PEM;

our $VERSION = '0.067';

use strict;
use warnings;

use Carp qw( carp croak );
use MIME::Base64 qw( encode_base64 decode_base64 );
use Encoding::BER::DER;
use Crypt::CBC;
use Crypt::Rijndael;
use Text::Wrap;
use Digest::MD5 qw( md5 );

use Crypt::ECDSA::Util qw( bint hex_bint random_hex_bytes );

require Exporter;
our @ISA    = qw(Exporter);
our @EXPORT = qw( read_ECDSA_signature_file write_ECDSA_signature_file );

my $DEBUG = 0;

our $parameters_label      = "EC PARAMETERS";
our $private_pem_label     = "EC PRIVATE KEY";
our $public_pem_label      = "EC PUBLIC KEY";
our $ecdsa_signature_label = "ECDSA SIGNATURE";

# See http://www.secg.org/collateral/sec1.pdf
# and
# http://tools.ietf.org/html/draft-ietf-pkix-sha2-dsa-ecdsa-00.txt

sub new {
    my ( $class, %args ) = @_;
    my $self = {};
    bless $self, $class;
    $self->{password} = $args{password} if $args{password};
    if ( $args{filename} ) {
        $self->{filename} = $args{filename};
        $self->read_PEM(%args);
    }
    return $self;
}

# file input
sub read_PEM {
    my ( $self, %args ) = @_;
    open( my $fh, '<', $args{filename} )
      or croak "Cannot open file $args{filename} for reading: $!";
    $args{fh} = $fh;
    my $retval = $self->read_PEM_fh(%args);
    close $fh;
    return $retval;
}

# file handle read
sub read_PEM_fh {
    my ( $self, %args ) = @_;
    my $infh = $args{fh} or return;
    my @pem_lines = <$infh>;
    @pem_lines = decrypt_pem( \@pem_lines, $args{password} ) if $args{password};
    my $buf = '';
    my %names;
    my $working_key;
    foreach my $line (@pem_lines) {

        if ( $line =~ /^--.+--$/ ) {
            if ( $line =~ /^[\s\-]+BEGIN\s+([\w\s\d]+)[\s\-]+/ ) {
                $working_key = $1;
                $names{$1} = ();
            }
            elsif ( $line =~ /^[\s\-]+END\s+([\w\s\d]+)[\s\-]+/ ) {
                $working_key = '';
            }
        }
        else {
            $names{$working_key} .= $line if $working_key;
        }
    }
    $self->{DER_entries} = \%names;
    $self->read_PEM_entries(%args);
}

sub read_PEM_entries {
    my ( $self, %args ) = @_;
    my %names = %{ $self->{DER_entries} };
    while ( my ( $name, $content ) = each %names ) {
        if ( $name eq $private_pem_label ) {
            $self->{private_pem_tree}->{name} = $content;
            my $der_content = decode_base64($content);
            $args{der_content} = $der_content;
            $args{ptree}       = $self->{private_pem_tree};
            $self->private_pem_DER_to_tree( $args{der_content}, $args{ptree} );
        }
        elsif ( $name eq $parameters_label ) {
            $self->{ec_parameters_tree}->{name} = $content;
            my $der_content = decode_base64($content);
            my @ber_bytes = unpack( 'w*', substr $der_content, 2 );
            if ( $ber_bytes[0] < 0x28 ) { unshift @ber_bytes, 0x00 }
            elsif ( $ber_bytes[0] < 0x50 ) {
                $ber_bytes[0] -= 0x28;
                unshift @ber_bytes, 0x01;
            }
            else { $ber_bytes[0] -= 0x50; unshift @ber_bytes, 0x02 }
            my $oid = join '.', @ber_bytes;
            $self->{ec_parameters_tree}->{namedCurve} = $oid;
            ( $self->{ec_parameters_tree}->{standard}, undef ) =
              ANS1_oid_to_standard_curve($oid);
        }
        elsif ( $name eq $public_pem_label ) {

        }
        elsif ( $name eq $ecdsa_signature_label ) {

        }
    }
}

sub private_pem_DER_to_tree {
    my ( $self, $content, $ptree ) = @_;
    my $coding = Encoding::BER::DER->new();
    $coding->add_implicit_tag( 'context', 'constructed', 'namedCurve', 0x00,
        'oid' );
    $coding->add_implicit_tag( 'context', 'constructed', 'subjectPublicKey',
        0x01, 'bit_string' );
    my $tree = $coding->decode($content);
    $ptree->{d} = DER_octet_string_to_bint( $tree->{value}->[1]->{value} );
    my $curve_oid = $tree->{value}->[2]->{value}->[0]->{value};
    my ( $standard, $alg ) = ANS1_oid_to_standard_curve($curve_oid);

    # default to prime curve--since most of the time that is used
    my $curve =
      $alg eq 'Koblitz'
      ? Crypt::ECDSA::Curve::Koblitz->new( standard => $standard )
      : Crypt::ECDSA::Curve::Prime->new( standard   => $standard );
    my $pkey_bstring = $tree->{value}->[3]->{value};
    my $pub_point = DER_public_key_to_point( $pkey_bstring, $curve );
    $ptree->{standard} = $standard;
    $ptree->{curve}    = $curve;
    $ptree->{Q}        = $pub_point;
    $ptree->{order}    = $curve->{point_order};
    $ptree->{tree}     = $tree;
    return $ptree;
}

# file output
sub write_PEM {
    my ( $self, %args ) = @_;
    my $key      = $args{key};
    my $filename = $args{filename};
    my $password = $args{password};
    my $cipher   = $args{cipher};
    my $txt;
    if ( $args{private} ) {
        $txt = $self->key_to_private_PEM( $key, $password, $cipher );
    }
    else {
        warn "making public key PEM" if $DEBUG;
        $txt = $self->key_to_public_PEM($key);
    }
    open my $outfh, '>', $filename or croak "Cannot write to $filename: $!";
    binmode $outfh;
    my $written = print $outfh $txt;
    close $outfh;
    return $written;
}

sub key_to_private_PEM {
    my ( $self, $key, $password, $cipher ) = @_;
    $cipher = 'Rijndael' unless $cipher;
    my $version      = 1;
    my $d_octet      = pack "H*", substr( $key->secret->as_hex, 2 );
    my $ans1_numbers = standard_curve_to_ANS1( $key->curve->standard );
    my $public_octet = $key->curve->to_octet( $key->Qx, $key->Qy );
    my $coding       = Encoding::BER::DER->new();
    $coding->add_implicit_tag( 'context', 'constructed', 'namedCurve', 0x00,
        'oid' );
    $coding->add_implicit_tag( 'context', 'constructed', 'subjectPublicKey',
        0x01, 'bit_string' );
    my $tree = {
        'type'  => [ 'universal', 'constructed', 'sequence' ],
        'value' => [
            {
                'value' => 1,
                'type'  => [ 'universal', 'primitive', 'integer', ],
            },
            {
                'type'  => [ 'universal', 'primitive', 'octet_string', ],
                'value' => $d_octet,
            },
            {
                'type'  => [ 'context', 'constructed', 'namedCurve', ],
                'value' => [
                    {
                        'value' => $ans1_numbers,
                        'type'  => [ 'universal', 'primitive', 'oid', ],
                    },
                ],
            },
            {
                'type'  => [ 'context', 'constructed', 'subjectPublicKey', ],
                'value' => [
                    {
                        'value' => $public_octet,
                        'type'  => [ 'universal', 'primitive', 'bit_string', ],
                    },
                ],
            },
        ],
    };
    my $b64str = encode_base64( $coding->encode($tree) );
    $b64str =~ s/\s//g;
    $Text::Wrap::columns = 65;
    my $txt = Text::Wrap::wrap( '', '', $b64str );
    my $PEM;

    if ($password) {
        my @lines = map { "$_\n" } split /\n/, $txt;
        $PEM = encrypt_pem( \@lines, $cipher, $password );
    }
    else {
        my $dashes = '-----';
        my $begin  = 'BEGIN ';
        my $end    = 'END ';
        $PEM =
            "$dashes$begin$private_pem_label$dashes\n" 
          . $txt
          . "\n$dashes$end$private_pem_label$dashes";
    }
    $self->{private_pem_tree}->{output_PEM} = $PEM;
    return $PEM;
}

sub key_to_public_PEM {
    my ( $self, $key, $password ) = @_;
    my $version      = 1;
    my $ans1_numbers = standard_curve_to_ANS1( $key->curve->standard );
    my $public_octet = $key->curve->to_octet( $key->Qx, $key->Qy );
    my $coding       = Encoding::BER::DER->new();
    $coding->add_implicit_tag( 'context', 'constructed', 'namedCurve', 0x00,
        'oid' );
    $coding->add_implicit_tag( 'context', 'constructed', 'subjectPublicKey',
        0x01, 'bit_string' );
    my $tree = {
        'type'  => [ 'universal', 'constructed', 'sequence' ],
        'value' => [
            {
                'value' => 1,
                'type'  => [ 'universal', 'primitive', 'integer', ],
            },
            {
                'type'  => [ 'context', 'constructed', 'namedCurve', ],
                'value' => [
                    {
                        'value' => $ans1_numbers,
                        'type'  => [ 'universal', 'primitive', 'oid', ],
                    },
                ],
            },
            {
                'type'  => [ 'context', 'constructed', 'subjectPublicKey', ],
                'value' => [
                    {
                        'value' => $public_octet,
                        'type'  => [ 'universal', 'primitive', 'bit_string', ],
                    },
                ],
            },
        ],
    };
    my $b64str = encode_base64( $coding->encode($tree) );
    $b64str =~ s/\s//g;
    $Text::Wrap::columns = 65;    # copy openssl's line length here
    my $txt    = Text::Wrap::wrap( '', '', $b64str );
    my $dashes = '-----';
    my $begin  = 'BEGIN ';
    my $end    = 'END ';
    my $PEM =
        "$dashes$begin$public_pem_label$dashes\n" 
      . $txt
      . "\n$dashes$end$public_pem_label$dashes";
    $self->{public_pem_tree}->{output_PEM} = $PEM;
    return $PEM;
}

#######  utility helper functions  ###########

sub read_ECDSA_signature_file {
    my ($filename) = @_;
    open( my $fh, '<', $filename )
      or croak("Cannot read signature file $filename: $!");
    binmode $fh;
    read( $fh, my $content, -s $fh );
    close $fh;
    require Math::BigInt;
    my $coding = Encoding::BER::DER->new();
    my $tree   = $coding->decode($content);
    my $r      = bint( $tree->{value}->[0]->{value}->as_hex );
    my $s      = bint( $tree->{value}->[1]->{value}->as_hex );
    warn "r is $r and s is $s" if $DEBUG;
    return ( $r, $s );
}

sub write_ECDSA_signature_file {
    my ( $filename, $r, $s ) = @_;
    open( my $outfh, '>', $filename )
      or croak("Cannot open file $filename for writing: $!");
    binmode $outfh;
    my $coding = Encoding::BER::DER->new();
    warn "r is $r and s is $s" if $DEBUG;
    my $tree = {
        'type'  => [ 'universal', 'constructed', 'sequence' ],
        'value' => [
            {
                'value' => $r->as_hex,
                'type'  => [ 'universal', 'primitive', 'integer', ],
            },
            {
                'value' => $s->as_hex,
                'type'  => [ 'universal', 'primitive', 'integer', ],
            },
        ],
    };
    my $retval = print $outfh $coding->encode($tree);
    close $outfh;
    return $retval;
}

sub DER_octet_string_to_bint {
    my ($str) = @_;
    return hex_bint( unpack( 'H*', $str ) );
}

sub bint_to_DER_octet_string {
    my ($n) = @_;
    $n = bint($n) unless ref $n;
    return uc substr( $n->as_hex, 2 );
}

sub DER_public_key_to_point {
    my ( $str, $curve ) = @_;
    my $point = Crypt::ECDSA::Point->new(
        octet => $str,
        curve => $curve,
        order => $curve->order
    );
    return $point;
}

# curve types are numbered via organization of apparent origin
# Certicom is 1.3.132.0
# ANSI X9-62 is 1.2.840.10045
our $curve_type = {
    '1.2.840.10045.3.1.1' => 'secp192r1',
    '1.3.132.0.1'         => 'sect163k1',
    '1.3.132.0.15'        => 'sect163r2',
    '1.3.132.0.33'        => 'sect224r1',
    '1.3.132.0.26'        => 'sect233k1',
    '1.3.132.0.27'        => 'sect233r1',
    '1.2.840.10045.3.1.7' => 'secp256r1',
    '1.3.132.0.16'        => 'sect283k1',
    '1.3.132.0.17'        => 'sect283r1',
    '1.3.132.0.34'        => 'sect384r1',
    '1.3.132.0.36'        => 'sect409k1',
    '1.3.132.0.37'        => 'sect409r1',
    '1.3.132.0.35'        => 'secp521r1',
    '1.3.132.0.38'        => 'sect571k1',
    '1.3.132.0.39'        => 'sect571r1',
};

sub ANS1_oid_to_standard_curve {
    my ($oid) = @_;
    return unless $oid and $curve_type->{$oid};
    no warnings;
    my $curve_type_to_curve = $Crypt::ECDSA::Curve::ANS1_lookup;
    my $named_curve         = $Crypt::ECDSA::Curve::named_curve;
    use warnings;
    my $standard = $curve_type_to_curve->{ $curve_type->{$oid} };
    return unless $standard;
    my $alg = $named_curve->{$standard}->{algorithm};
    return ( $standard, $alg );
}

sub standard_curve_to_ANS1 {
    my ($standard)          = @_;
    my $curve_type_to_curve = $Crypt::ECDSA::Curve::ANS1_lookup;
    my %standard_to_names   = reverse %$curve_type_to_curve;
    my %names_to_ans1       = reverse %$curve_type;
    return $names_to_ans1{ $standard_to_names{$standard} };
}

our $PEM_cipher_type = {
    'DES-CBC'      => 'DES',
    'DES-EDE3-CBC' => 'DES_EDE3',
    'AES-128-CBC'  => 'Rijndael',
    'BF-CBC'       => 'Blowfish',
};

our $cipher_to_DEK = {
    Blowfish   => 'BF-CBC',
    "DES_EDE3" => 'DES-EDE3-CBC',
    Rijndael   => 'AES-128-CBC',
    DES        => 'DES-CBC',
};

our $cipher_iv_bitsize = {
    "DES_EDE3" => 64,
    Rijndael   => 128,
    Blowfish   => 64,    # really none
    DES        => 64,
};

our $cipher_key_bytesize = {
    "DES_EDE3" => 24,
    Rijndael   => 16,
    Blowfish   => 16,
    DES        => 8,
};

sub encrypt_pem {
    my ( $pem_lines, $cipher, $password ) = @_;
    my $DEK_type = $cipher_to_DEK->{$cipher};
    croak "Need password and cipher type" unless $password and $DEK_type;
    warn "encrypting PEM with password $password and type $DEK_type" if $DEBUG;
    my $bytes_needed = $cipher_iv_bitsize->{$cipher} / 8;
    my $iv_str       = '';
    do {
        $iv_str = uc random_hex_bytes( $cipher_iv_bitsize->{$cipher} / 8 );
        warn "desired bit length is ", $cipher_iv_bitsize->{$cipher},
          " and generated length of $iv_str is ", length($iv_str) * 8
          if $DEBUG;
    } while length($iv_str) * 4 != $cipher_iv_bitsize->{$cipher};
    my $iv = pack "H*", $iv_str;
    my $keystring = evp_key( $password, $iv, $cipher_key_bytesize->{$cipher} );
    my $work = join '', @{$pem_lines};
    warn "decoding base64" if $DEBUG;
    $work = decode_base64($work);
    my $alg = Crypt::CBC->new(
        -literal_key => 1,
        -key         => $keystring,
        -cipher      => $cipher,
        -iv          => $iv,
        -header      => 'none',
        -keysize     => $cipher_key_bytesize->{$cipher},
    );
    warn "encrypting binary" if $DEBUG;
    $work = $alg->encrypt($work);
    warn "beginning base64 encode" if $DEBUG;
    my $b64str = encode_base64($work);
    $b64str =~ s/\s//g;
    $Text::Wrap::columns = 65;
    my $txt    = Text::Wrap::wrap( '', '', $b64str );
    my $begin  = "-----BEGIN EC PRIVATE KEY-----";
    my $second = "Proc-Type: 4,ENCRYPTED";
    my $third  = "DEK-Info: $cipher_to_DEK->{$cipher},$iv_str";
    my $end    = "-----END EC PRIVATE KEY-----";
    my $PEM    = "$begin\n$second\n$third\n\n$txt\n$end\n";
    return $PEM;
}

sub decrypt_pem {
    my ( $pem_lines, $password ) = @_;
    my ( $begin, $end, $cipher, $iv, $keystring );
    my $work = '';
    my $found_encryption;
    for my $line (@$pem_lines) {
        if ( $line =~ /^-----BEGIN/ ) {
            $begin = $line;
        }
        elsif ( $line =~ /^-----END/ ) {
            $end = $line;
            last;
        }
        elsif ( $line =~ /^Proc-Type/i ) {
            next;
        }
        elsif ( $line =~ /^DEK-Info:\s*([^\,]+),([\dabcdef]+)/i ) {
            $found_encryption = 1;
            $cipher           = $PEM_cipher_type->{$1};
            my $key_bytesize = $cipher_key_bytesize->{$cipher};
            $iv = pack "H*", $2;
            $keystring = evp_key( $password, $iv, $key_bytesize );
        }
        else {
            $work .= $line;
        }
    }
    return (@$pem_lines) unless $found_encryption;
    croak "Missing data: password($password), iv($iv)" unless $password and $iv;
    $work =~ s/\s//g;
    $work = decode_base64($work);
    my $alg = Crypt::CBC->new(
        -keysize     => $cipher_key_bytesize->{$cipher},
        -literal_key => 1,
        -key         => $keystring,
        -cipher      => $cipher,
        -iv          => $iv,
        -header      => 'none',
    );
    $work = $alg->decrypt($work);
    $work = encode_base64($work);
    return ( $begin, $work, $end );
}

sub evp_key {
    my ( $data, $salt, $key_byte_size ) = @_;
    $salt = substr( $salt, 0, 8 );
    my $key = md5( $data, $salt );
    while ( length($key) < $key_byte_size ) {
        $key .= md5( $key, $data, $salt );
    }
    return substr $key, 0, $key_byte_size;
}

=head1 NAME

Crypt::ECDSA::PEM -- ECDSA PEM file management for elliptic key DSA cryptography

=head1 DESCRIPTION

  These are for use with Crypt::ECDSA and require Math::BigInt::GMP.


=head1 METHODS

=over 4

=item B<new>

  Constructor.  Takes the following named pair arguments:
  
  filename =>  $file_name
  
  Open and parse a PEM key file at initialization of the object.
  
  password => $passwd
  
  Use $passwd as a key to and encrypted PEM file.
  
  
=item B<read_PEM>

  $pem->read_PEM( filename => $filename, password => $password );

  Read and parse a PEM file.  The password is optional.
  
=item B<read_PEM_fh>

    $pem->read_PEM_fh( filename => $fname );
    
    Read from an open file handle.  Otherwise like read_PEM().
    
=item B<write_PEM>

  $pem->write_PEM( filename => $outfile, private => 1, 
    password => $pwrd, cipher => 'Rijndael' );
  
  Write a PEM file.  The private parameter indicates to write out the 
  private key.  Otherwise the public key only is wriiten to the file.
  The password is for encryption if desired. cipher => $cipher is for the
  cipher method: 'Rijndael' (AES) is suggested, but if your installation has them,
  the module can use DES_EDE3 and Blowfish as well.
  
  
=item B<key_to_private_PEM>

    my $pem_text = $pem->key_to_private_PEM( $key, $password );
    print $pem_text;
    
    Create and return a PEM file containing the pirvate and public keys as 
    a scalar.  The second, password parameter is optional.

=back

=head2 Class Internal Functions

=over 4

=item B<ANS1_oid_to_standard_curve>

=item B<DER_octet_string_to_bint>

=item B<DER_public_key_to_point>

=item B<bint_to_DER_octet_string>

=item B<decrypt_pem>

=item B<encrypt_pem>

=item B<evp_key>

=item B<key_to_public_PEM>

=item B<private_pem_DER_to_tree>

=item B<read_ECDSA_signature_file>

=item B<read_PEM_entries>

=item B<standard_curve_to_ANS1>

=item B<write_ECDSA_signature_file>

=back

=head1 AUTHOR 

   William Herrera B<wherrera@skylightview.com>. 

=head1 SUPPORT 

Questions, feature requests and bug reports should go to 
<wherrera@skylightview.com>.

=head1 COPYRIGHT 

=over 4

Copyright (c) 2007 William Herrera. All rights reserved.  
This program is free software; you can redistribute it and/or modify 
it under the same terms as Perl itself.


=cut

1;
