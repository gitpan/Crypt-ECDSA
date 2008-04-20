package Crypt::ECDSA::ECDSAVS;

# This package exists to test this ECDSA implementation against the NIST
# ECDSAVS verifier. It is NOT intended for general use and is entirely
# customized for the current crypto FIPS verifier file formats, which are
# a variant of the Windows style config file format.

our $VERSION = '0.063';

use strict;
no warnings;
use Carp qw/ carp croak /;
use Digest::SHA;

use Crypt::ECDSA;
use Crypt::ECDSA::Util qw( bint hex_bint );


my $DEBUG = 0;

my %supported = (
    'P-192' => 'ECP-192',
    'P-224' => 'ECP-224',
    'P-256' => 'ECP-256',
    'P-384' => 'ECP-384',
    'P-521' => 'ECP-521',
    'K-163' => 'EC2N-163',
    'K-233' => 'EC2N-233',
    'K-283' => 'EC2N-283',
    'K-409' => 'EC2N-409',
    'K-571' => 'EC2N-571',
);

my $curves = $Crypt::ECDSA::Curve::named_curve;

my $application_data = {
    'Vendor Name'     => 'William Herrera  <wherrera@skylightview.com>',
    'Product Name'    => "ECDSA Perl Modules",
    'Product Version' => $VERSION,
    'Implementation'  => 'software',
    'System Version'  => "Operating System: $^O,  Perl Version: ". int( $^V ),
    'IUT Information' => 'This is a set of Perl software modules for elliptic'
      . ' key crptography.  These modules are free and open source.  '
      . 'See http://www.cpan.org ',
    'Curves' => join( ', ', keys %supported ),
};

our $default_filename = {
    MakeApplication  => 't/Application.txt',
    KeyPair_request  => 't/KeyPair.req',
    KeyPair_response => 't/KeyPair.rsp',
    PubKey_request   => 't/PKV.req',
    PubKey_response  => 't/PKV.rsp',
    PubKey_correct   => 't/PKV.rsp.correct',
    SigGen_request   => 't/SigGen.req',
    SigGen_response  => 't/SigGen.rsp',
    SigVer_request   => 't/SigVer.req',
    SigVer_response  => 't/SigVer.rsp',
    SigVer_correct   => 't/SigVer.rsp.correct',
};

sub new {
    my ( $class, %args ) = @_;
    my $self = \%args;
    bless $self, $class;
    return $self;
}

sub write_application_data {
    my ($filename) = @_;
    $filename ||= $default_filename->{MakeApplication};
    my $info = '';
    while ( my ( $k, $v ) = each %$application_data ) {
        $info .= $k . ': ' . $v . "\n";
    }
    open my $fh, '>', $filename or croak("Cannot write application data: $!");
    print $fh $info;
    close $fh;
    return $info;
}

sub KeyPair_test {
    my ($self) = @_;
    my $retval = '';
    my ( $hashes, $comments ) = process_lines( read_file('KeyPair_request') );
    foreach my $cmt (@$comments) { $retval .= $cmt . "\n" }
    my @curves;
    foreach my $curve ( keys %{$hashes} ) {
        unless ( $supported{$curve} ) {
            carp("\nNo support found for curve $curve");
            next;
        }
        $retval .= '[' . $curve . ']' . "\n";
        my $requested_pairs = $hashes->{$curve}->{N}->[0];
        my $ecdsa = Crypt::ECDSA->new( standard => $supported{$curve} );
        for ( my $i = 0 ; $i < $requested_pairs ; ++$i ) {
            my ( $d, $x, $y ) = $ecdsa->key->new_key_values();
            $retval .= 'd = ' .  ihex($d) . "\n";
            $retval .= 'Qx = ' . ihex($x) . "\n";
            $retval .= 'Qy = ' . ihex($y) . "\n";
            print STDERR "\rDone with key value $i for $curve in KeyPair"
              if $DEBUG;
        }
        print STDERR "\rDone with curve $curve in KeyPair                     \r"
          if $DEBUG;
    }
    write_file( 'KeyPair_response', $retval );
    $self->{KeyPair_results} = $retval;
    return $retval;
}

sub PubKey_test {
    my ($self) = @_;
    my $retval = '';
    my ( $hashes, $comments ) = process_lines( read_file('PubKey_request') );
    foreach my $cmt (@$comments) { $retval .= $cmt . "\n" }
    my @curves;
    foreach my $curve ( keys %$hashes ) {
        unless ( $supported{$curve} ) {
            debug_warn("\nno supported curve for $curve");
            next;
        }
        $retval .= '[' . $curve . ']' . "\n";
        my $ecdsa = Crypt::ECDSA->new( standard => $supported{$curve} );
        my $Qx    = $hashes->{$curve}->{Qx};
        my $Qy    = $hashes->{$curve}->{Qy};
        my $n     = scalar @$Qx;
        for ( my $i = 0 ; $i < $n ; ++$i ) {
            my $x      = $Qx->[$i];
            my $y      = $Qy->[$i];
            my $result = $ecdsa->is_valid_point( $x, $y ) ? 'P' : 'F';
            $retval .= 'Qx = ' . ihex($x) . "\n";
            $retval .= 'Qy = ' . ihex($y) . "\n";
            $retval .= 'Result = ' . $result . "\n";
            print STDERR "\rDone with iteration $i  ( $result ) for $curve in PubKey"
              if $DEBUG;
        }
        print STDERR "\rDone with curve $curve in PubKey                               \r"
          if $DEBUG;
    }
    $self->{PubKey_results} = $retval;
    write_file( 'PubKey_response', $retval );
print "response is $retval\n";
    return $retval;
}

sub SigGen_test {
    my ($self) = @_;
    my $retval = '';
    my ( $hashes, $comments ) = process_lines( read_file('SigGen_request') );
    foreach my $cmt (@$comments) { $retval .= $cmt . "\n" }
    my @curves;
    foreach my $curve ( keys %$hashes ) {
        unless ( $supported{$curve} ) {
            debug_warn("\nno supported curve for $curve");
            next;
        }
        $retval .= '[' . $curve . ']' . "\n";
        my $ecdsa        = Crypt::ECDSA->new( standard => $supported{$curve} );
        my $Msg          = $hashes->{$curve}->{Msg};
        my $num_messages = scalar(@$Msg);
        my $sh1          = Digest::SHA->new(1);
        for ( my $i = 0 ; $i < $num_messages ; ++$i ) {
            my $text = $Msg->[$i];
            my $Q    = $ecdsa->key->Q;
            my $qx   = $Q->X;
            my $qy   = $Q->Y;
            $sh1->reset;
            my $bits = substr( $text->as_bin, 2 );
            while ( length($bits) < 1024 ) { $bits = '0' . $bits }
            $sh1->add_bits($bits);
            my $hash_digest = $sh1->hexdigest;
            my ( $r, $s ) =
              $ecdsa->signature( hash => bint( 'ox' . $hash_digest ) );
            $retval .= "Msg = "
              . ihex($text)
              . "\nQx = "
              . ihex($qx)
              . "\nQy = "
              . ihex($qy)
              . "\nR = "
              . ihex($r)
              . "\nS = "
              . ihex($s) . "\n";
            print STDERR "\rDone with iteration $i for $curve in SigGen"
              if $DEBUG;
        }
        print STDERR "\rDone with curve $curve in SigGen              \r"
          if $DEBUG;
    }
    $self->{SigGen_results} = $retval;
    write_file( 'SigGen_response', $retval );
    return $retval;
}

sub SigVer_test {
    my ($self) = @_;
    my $retval = '';
    my ( $hashes, $comments ) = process_lines( read_file('SigVer_request') );
    foreach my $cmt (@$comments) { $retval .= $cmt . "\n" }
    my @curves;
    foreach my $curve ( keys %$hashes ) {
        unless ( $supported{$curve} ) {
            debug_warn("\nno supported curve for $curve");
            next;
        }
        $retval .= '[' . $curve . ']' . "\n";
        my $Msg          = $hashes->{$curve}->{Msg};
        my $Qx           = $hashes->{$curve}->{Qx};
        my $Qy           = $hashes->{$curve}->{Qy};
        my $R            = $hashes->{$curve}->{R};
        my $S            = $hashes->{$curve}->{S};
        my $num_messages = scalar(@$Msg);
        my $sh1          = Digest::SHA->new(1);
        my $ecdsa        = Crypt::ECDSA->new( standard => $supported{$curve} );

        for ( my $i = 0 ; $i < $num_messages ; ++$i ) {
            my $text = $Msg->[$i];
            my $qx   = $Qx->[$i];
            my $qy   = $Qy->[$i];
            my $r    = $R->[$i];
            my $s    = $S->[$i];
            $sh1->reset;
            my $bits = substr( $text->as_bin, 2 );
            while ( length($bits) < 1024 ) { $bits = '0' . $bits }
            $sh1->add_bits($bits);
            my $hash_digest = hex_bint( $sh1->hexdigest );
            my $verified    = 'F';
            if ( $ecdsa->key->curve->is_on_curve( $qx, $qy ) ) {
                $ecdsa->key->set_public_Q( $qx, $qy );
                $verified = 'P'
                  if $ecdsa->verify( r => $r, 's' => $s, hash => $hash_digest );
            }
            $retval .= "Msg = "
              . ihex($text)
              . "\nQx = "
              . ihex($qx)
              . "\nQy = "
              . ihex($qy)
              . "\nR = "
              . ihex($r)
              . "\nS = "
              . ihex($s) . "\n";
            $retval .= "Result = $verified\n";
            print STDERR 
              "\rDone with iteration $i ( $verified ) for $curve in SigVer"
                if $DEBUG;
        }
        print STDERR "\rDone with curve $curve in SigVer                            \r"
          if $DEBUG;
    }
    $self->{SigVer_results} = $retval;
    write_file( 'SigVer_response', $retval );
    return $retval;
}

my @tasks = (
    \&write_application_data, 
    \&KeyPair_test, 
    \&PubKey_test, 
    \&SigGen_test,
    \&SigVer_test,
);

sub do_all_tasks {
    my ( $self, $callback ) = @_;
    foreach my $task (@tasks) {
        my $code = $task->();
        $callback->($code) if $callback;
    }
}

######  non-member utility functions  ########

# GUESS as to number format, return bigint based on GUESS as to base
# works for big ECDSAVS numbers, but likely breaks with smaller values
sub string_to_bigint {
    my $s = shift;
    $s =~ s/\s//;
    $s =~ s/^0*//;
    return bint($s)     if $s =~ /^[0123456789]+$/;
    return hex_bint('0x' . $s) if $s =~ /^[0123456789a-fA-F]+$/;
    warn("Unknown number format for bigint constuctor: $s") if $DEBUG;
    return bint($s);  # by default we try to pass to bint anyway
}

# hex print for file output
sub ihex {
    my($num) = @_;
    return substr( $num->as_hex, 2 );
}

sub process_lines {
    my $lines = shift;

    # skip lines beginning with # as comments
    # each bracket is an EC curve category
    # join all numbers
    # word = number becomes a hash entry
    # numbers are BigInt->bstr()
    my %curves = ();
    my @comments;
    my $working_curve;
    my $working_key;
    my %working_index;
    foreach my $line (@$lines) {
        chomp $line;
        if ( $line =~ /^\#/ ) {
            push @comments, $line;
            next;
        }
        my $cline = clean_line($line);
        if ( $cline =~ /^\s*\[\s*(\S+)\s*\]\s*/ ) {
            $curves{$1}    = {};
            $working_curve = $1;
            $working_key   = '';
            %working_index = ();
        }
        elsif ( $cline =~ /\s*(\w+)\s*\=\s*([\d\w]*)/ and $working_curve ) {
            $working_key = $1;
            ++$working_index{$working_key};
            my $v = $2 || '';
            $curves{$working_curve}->{$working_key}
              ->[ $working_index{$working_key} - 1 ] = $v;
        }
        elsif ( $cline =~ /^[a-zA-Z0123456789]+$/ and $working_key ) {
            $curves{$working_curve}->{$working_key}
              ->[ $working_index{$working_key} - 1 ] .= $cline;
        }
    }

    # now change all big numbers to bigints
    foreach my $curve ( values %curves ) {
        foreach my $a ( values %$curve ) {
            foreach my $num (@$a) {
                $num = string_to_bigint($num) if $num and length($num) > 7;
            }
        }
    }
    return ( \%curves, \@comments );
}

sub clean_line {
    my ($data) = shift;
    $data =~ /\s*([a-zA-Z0123456789\-\_\=\[\]\.\s]+)/;
    my $untainted_data = $1;
    return unless defined $untainted_data;
    $untainted_data =~ s/\s+$//;
    return $untainted_data;
}

sub read_file {
    my $tag    = shift;
    my $infile = $default_filename->{$tag};
    my @lines;
    open( my $infh, '<', $infile )
      or croak "Cannot open input for $tag of $infile: $!";
    @lines = <$infh>;
    close $infh;
    return \@lines;
}

sub write_file {
    my ( $tag, $data ) = @_;
    my $outfile = $default_filename->{$tag};
    open( my $ofh, '>', $outfile )
      or croak "Cannot open output $outfile: $!";
    print $ofh $data;
    close $ofh;
}

=head1 NAME

Crypt::ECDSA::ECDSAVS -- Verification system for elliptic curve cryptography DSA

=head1 DESCRIPTION

  This package exists to test this ECDSA implementation against the NIST
  ECDSAVS verifier. It is NOT intended for general use and is entirely
  customized for the current crypto FIPS verifier file formats, which are
  a variant of the Windows style config file format.

=head1 AUTHOR 

   William Herrera B<wherrera@skylightview.com>. 

=head1 METHODS

=over 4

=item B<new>

  make new testing object

=item B<write_application_data>

  write information about the ECDSA modules

=item B<KeyPair_test>

  generate key pairs

=item B<PubKey_test>

  test public keys for validity

=item B<SigGen_test>

  do signature genetation

=item B<SigVer_test>

  do signature verification

=item B<do_all_tasks> 

  do all tests

=item B<string_to_bigint>

  convert input string to a bigint -- tries to differentiate hex from base 10 numbers 
  
=item B<ihex>
 
 print a number as hex without the usual leading '0x' code

=item B<process_lines>
 
  process input lines of input files

=item B<clean_line>

  untaint input for the module

=item B<read_file>
  
  read input

=item B<write_file>

  write output

=back

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
