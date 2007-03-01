package Crypt::ECDSA::Curve;

our $VERSION = '0.042';

use strict;
use warnings;
use Carp 'croak';

use Crypt::ECDSA::Point;
use Crypt::ECDSA::Util qw( bint bigint_from_coeff two_pow );

our $named_curve;

###### constructors ##############

sub new {
    my ( $class, %params ) = @_;
    my $standard = $params{standard};
    if ( $standard ) {
        if( $standard eq 'generic_prime' ) {
            return _make_generic_prime_curve( $class, %params );
        }
        elsif( $standard eq 'generic_binary' ) {
            return _make_generic_binary_curve( $class, %params );
        }
        else {
            return _make_named( $class, %params );
        }
    }
    my $self = {};
    $self->{p} = bint( $params{p} );
    $self->{a} = bint( $params{a} );
    $self->{b} = bint( $params{b} );
    bless $self, $class;
    return $self;
}

sub _make_named {
    my ( $class, %params ) = @_;
    my $self = {};
    bless $self, $class;
    my $standard     = $params{standard};
    my $curve_params = $named_curve->{$standard}
      or croak("Cannot get curve parameters for curve $standard");
    $self->{p} = bint( $curve_params->{p} );
    $self->{a} = bint( $curve_params->{a} );
    $self->{b} = bint( $curve_params->{b} );
    $self->{N} = $curve_params->{N} if $curve_params->{N};
    $self->{p} = two_pow( $curve_params->{N} ) if $curve_params->{N} and !$self->{p};
    if ( $curve_params->{polynomial} ) {
        $self->{polynomial}  = $curve_params->{polynomial};
        $self->{irreducible} = bint( $curve_params->{irreducible} );
        $self->{tau_s0}      = bint( $curve_params->{tau_s0} );
        $self->{tau_s1}      = bint( $curve_params->{tau_s1} );
        $self->{tau_V}       = bint( $curve_params->{tau_V} );
        $self->{q}           = two_pow( bint( $curve_params->{N} ) );
    }
    else {
        $self->{q}           = $self->{p};
    }

    # curve order is base point order * cofactor ( called r * h by NIST )
    $self->{cofactor} = bint( $curve_params->{h} );
    if ( $curve_params->{r} ) {
        $self->{point_order} = bint( $curve_params->{r} );
    }
    elsif ( $curve_params->{n} ) {
        $self->{point_order} = bint( $curve_params->{n} );
    }
    else {
        # FIXME: probably need to calculate this here instead of this poor guess
        # but calculating the order of a point takes a while-- this may be 0
        $self->{point_order} = bint( $self->{p} / $self->{cofactor} );
    }
    $self->{order} = $self->{point_order};
    $self->{curve_order} = $self->{point_order} * $self->{cofactor};    
    $self->{G_x} = bint( $curve_params->{G_x} );
    $self->{G_y} = bint( $curve_params->{G_y} );

    return $self;
}

sub _make_generic_prime_curve {
    my ( $class, %params ) = @_;
    my $self = {};
    bless $self, $class;
    $self->{p} = bint( $params{p} );
    $self->{a} = bint( $params{a} );
    $self->{b} = bint( $params{b} );
    croak( "New generic prime curve needs p => prime, a => a, and b => b" )
      unless $self->{p} and defined $self->{a} and defined $self->{b};
    return $self;
}

sub _make_generic_binary_curve {
    my ( $class, %params ) = @_;
    my $self = {};
    bless $self, $class;
    $self->{N} = bint( $params{N} );
    $self->{a} = bint( $params{a} );
    $self->{b} = bint( $params{b} );
    $self->{irreducible} = bint( $params{irreducible} );
    if( !$self->{irreducible} and $self->{polynomial} ) {
        $self->{irreducible} = bigint_from_coeff( $self->{polynomial} );
    }
    croak(  
"New generic binary curve needs N => 2**N order, a => a, and b => b, and either a polynomial arrayref or a bigint for the irreducicible polynomial"
      ) unless $self->{N} and defined $self->{a} and defined $self->{b} 
        and $self->{irreducible};
    return $self;
}


sub a {
    my ( $self, $new_a ) = @_;
    $self->{a} = bint($new_a) if defined $new_a;
    return $self->{a};
}

sub b {
    my ( $self, $new_b ) = @_;
    $self->{b} = bint($new_b) if defined $new_b;
    return $self->{b};
}

sub p {
    my ( $self, $new_p ) = @_;
    $self->{p} = bint($new_p) if defined $new_p;
    return $self->{p};
}

sub q { 
    my ( $self, $new_q ) = @_;
    $self->{q} = bint($new_q) if defined $new_q;
    return $self->{q};
}

sub order {
    my ( $self, $new_order ) = @_;
    $self->{p} = bint($new_order) if defined $new_order;
    return $self->{order};
}

sub curve_order {
    my ( $self, $new_curve_order ) = @_;
    $self->{p} = bint($new_curve_order) if defined $new_curve_order;
    return $self->{curve_order};
}


sub infinity {
    my ($self) = @_;
    return Crypt::ECDSA::Point->new(
        X           => 0,
        Y           => 0,
        curve       => $self,
        is_infinity => 1,
    );
}

###   predefined curves ###

$named_curve = {
    generic_prime => {
        algorithm => 'Prime',
        NIST      => undef,
    },
    generic_binary => {
        algorithm => 'Koblitz',
        NIST      => undef,
    },
    'ECP-160' => {
        algorithm => 'Prime',
        table     => 'secp160r1',
        NIST      => undef,
        p         => '1461501637330902918203684832716283019653785059327',
        a         => -3,
        b         => '0x1c97befc54bd7a8b65acf89f81d4d4adc565fa45',
        r         => '0x100000000000000000001f4c8f927aed3ca752257',
        G_x       => '0x4a96b5688ef573284664698968c38bb913cbfc82',
        G_y       => '0x23a628553168947d59dcc912042351377ac5fb32',
        h         => 1,
        's'       => '0x203370bf41c7ca0822e2ccd8f4d4a01191977373',
        c         => '1461501637330902918203684832716283019653785059324',
    },
    'ECP-192' => {
        algorithm => 'Prime',
        table     => 'secp192r1',
        NIST      => 'P-192',
        p   => '6277101735386680763835789423207666416083908700390324961279',
        a   => -3,
        b   => '0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1',
        r   => '6277101735386680763835789423176059013767194773182842284081',
        G_x => '0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012',
        G_y => '0x7192b95ffc8da78631011ed6b24cdd573f977a11e794811',
        h   => 1,
        's' => '0x3045ae6fc8422f64ed579528d38120eae12196d5',
        c   => '0x3099d2bbbfcb2538542dcd5fb078b6ef5f3d6fe2c745de65,'
    },
    'ECP-224' => {
        algorithm => 'Prime',
        table     => 'secp224r1',
        NIST      => 'P-224',
        p         =>
'26959946667150639794667015087019630673557916260026308143510066298881',
        a => -3,
        b => '0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4',
        r =>
'26959946667150639794667015087019625940457807714424391721682722368061',
        G_x => '0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21',
        G_y => '0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34',
        h   => 1,
        's' => '0xbd71344799d5c7fcdc45b59fa3b9ab8f6a948bc5',
        c   => '0x5b056c7e11dd68f40469ee7f3c7a7d74f7d121116506d031218291fb',
    },
    'ECP-256' => {
        algorithm => 'Prime',
        table     => 'secp256r1',
        NIST      => 'P-256',
        p         =>
'115792089210356248762697446949407573530086143415290314195533631308867097853951',
        a => -3,
        b =>
          '0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b',
        r =>
'115792089210356248762697446949407573529996955224135760342422259061068512044369',
        G_x =>
          '0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296',
        G_y =>
          '0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5',
        h   => 1,
        's' => '0xc49d360886e704936a6678e1139d26b7819f7e90',
        c   =>
          '0x7efba1662985be9403cb055c75d4f7e0ce8d84a9c5114abcaf3177680104fa0d',
    },
    'ECP-384' => {
        algorithm => 'Prime',
        table     => 'secp384r1',
        NIST      => 'P-384',
        p         =>
'39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319',
        a => -3,
        r =>
'39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643',
        's' => '0xa335926aa319a27a1d00896a6773a4827acdac73',
        b   =>
'0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef',
        G_x =>
'0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7',
        G_y =>
'0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f',
        h => 1,
        c =>
'0x79d1e655f868f02fff48dcdee14151ddb80643c1406d0ca10dfe6fc52009540a495e8042ea5f744f6e184667cc722483',
    },
    'ECP-521' => {
        algorithm => 'Prime',
        table     => 'secp521r1',
        NIST      => 'P-521',
        p         =>
'6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151',
        a => -3,
        r =>
'6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449',
        's' => '0xd09e8800291cb85396cc6717393284aaa0da64ba',
        b   =>
'0x051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00',
        G_x =>
'0xc6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66',
        G_y =>
'0x11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650',
        h => 1,
        c =>
'0x0b48bfa5f420a34949539d2bdfc264eeeeb077688e44fbf0ad8f6d0edb37bd6b533281000518e19f1b9ffbe0fe9ed8a3c2200b8f875e523868c70c1e5bf55bad637',
    },
    'EC2N-163' => {    # K-163 Koblitz binary curve polynomial basis
        algorithm   => 'Koblitz',
        N           => 163,
        polynomial  => [ 163, 7, 6, 3, 0 ],
        a           => 1,
        h           => 2,
        n           => '5846006549323611672814741753598448348329118574063',
        G_x         => '0x2fe13c0537bbc11acaa07d793de4e6d5e5c94eee8',
        G_y         => '0x289070fb05d38ff58321f2e800536d538ccdaa3d9',
        irreducible => '0x800000000000000000000000000000000000000c9',
        tau_s0      => '2579386439110731650419537',
        tau_s1      => '-755360064476226375461594',
        tau_V       => '-4845466632539410776804317',
    },
    'EC2N-233' => {    # K-233 Koblitz binary curve polynomial basis
        algorithm  => 'Koblitz',
        polynomial => [ 233, 74, 0 ],
        N          => 233,
        a          => 0,
        h          => 4,
        n          =>
'3450873173395281893717377931138512760570940988862252126328087024741343',
        G_x => '0x17232ba853a7e731af129f22ff4149563a419c26bf50a4c9d6eefad6126',
        G_y => '0x1db537dece819b7f70f555a67c427a8cd9bf18aeb9b56e0c11056fae6a3',
        irreducible =>
          '0x20000000000000000000000000000000000000004000000000000000001',
        tau_s0 => '-27859711741434429761757834964435883',
        tau_s1 => '-44192136247082304936052160908934886',
        tau_V  => '-137381546011108235394987299651366779',
    },
    'EC2N-283' => {    # K-283 Koblitz binary curve polynomial basis
        algorithm  => 'Koblitz',
        N          => 283,
        polynomial => [ 283, 12, 7, 5, 0 ],
        a          => 0,
        h          => 4,
        n          =>
'3885337784451458141838923813647037813284811733793061324295874997529815829704422603873',
        G_x =>
'0x503213f78ca44883f1a3b8162f188e553cd265f23c1567a16876913b0c2ac2458492836',
        G_y =>
'0x1ccda380f1c9e318d90f95d07e5426fe87e45c0e8184698e45962364e34116177dd2259',
        irreducible =>
'0x800000000000000000000000000000000000000000000000000000000000000000010a1',
        tau_s0 => '-665981532109049041108795536001591469280025',
        tau_s1 => '1155860054909136775192281072591609913945968',
        tau_V  => '7777244870872830999287791970962823977569917',
    },
    'EC2N-409' => {    # K-409 Koblitz binary curve polynomial basis
        algorithm  => 'Koblitz',
        N          => 409,
        polynomial => [ 409, 87, 0 ],
        a          => 0,
        h          => 4,
        n          =>
'33052798439512429475957654016385519914202341482140609642324395022880711289249191050673258457777458014096366590617731358671',
        G_x =>
'0x060f05f658f49c1ad3ab1890f7184210efd0987e307c84c27accfb8f9f67cc2c460189eb5aaaa62ee222eb1b35540cfe9023746',
        G_y =>
'0x1e369050b7c4e42acba1dacbf04299c3460782f918ea427e6325165e9ea10e3da5f6c42e9c55215aa9ca27a5863ec48d8e0286b',
        irreducible =>
'0x2000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000001',
        tau_s0 =>
          '-18307510456002382137810317198756461378590542487556869338419259',
        tau_s1 =>
          '-8893048526138304097196653241844212679626566100996606444816790',
        tau_V =>
          '10457288737315625927447685387048320737638796957687575791173829',
    },
    'EC2N-571' => {    # K-571 Koblitz binary curve polynomial basis
        algorithm  => 'Koblitz',
        N          => 571,
        polynomial => [ 571, 10, 5, 2, 0 ],
        a          => 0,
        h          => 4,
        n          =>
'1932268761508629172347675945465993672149463664853217499328617625725759571144780212268133978522706711834706712800825351461273674974066617311929682421617092503555733685276673',
        G_x =>
'0x26eb7a859923fbc82189631f8103fe4ac9ca2970012d5d46024804801841ca44370958493b205e647da304db4ceb08cbbd1ba39494776fb988b47174dca88c7e2945283a01c8972',
        G_y =>
'0x349dc807f4fbf374f4aeade3bca95314dd58cec9f307a54ffc61efc006d8a2c9d4979c0ac44aea74fbebbb9f772aedcb620b01a7ba7af1b320430c8591984f601cd4c143ef1c7a3',
        irreducible =>
'0x80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000425',
        tau_s0 =>
'-3737319446876463692429385892476115567147293964596131024123406420235241916729983261305',
        tau_s1 =>
'-319185770644641609958381459594895967413196891214856465861056511758982848515832612248752',
        tau_V =>
'-148380926981691413899619140297051490364542574180493936232912339534208516828973111459843',
    },
};

=head1 NAME

Crypt::ECDSA::Curve -- Base class for ECC curves

=head1 DESCRIPTION

 These are for use with Crypt::ECDSA, a Math::GMPz based cryptography module.

=head1 METHODS

=over 4

=item B<new>

  Constructor.  Takes the following named pair arguments:
  
  standard => 'standard-curve-name'
  
  Used for named standard curves such as the NIST standard curves.  
  Preferentially, these are invoked by classes which inherit
  from Crypt::ECDSA::Curve, such as Crypt::ECDSA::Curve::Prime, 
  Crypt::ECDSA::Curve::Binary, or Crypt::ECDSA::Curve::Koblitz.

  See US govenment standard publications FIPS 186-2 or FIPS 186-3.

  used as:
  
  new(standard => 'standard curve name'), where curve name is one of:
  
  Crypt::ECDSA::Curve::Prime->new( standard => 
   [ one of 'ECP-192', 'ECP-224', 'ECP-256', 'ECP-384', 'ECP-521' ] )
   
  Crypt::ECDSA::Curve::Koblitz->new( standard => 
   [ one of 'EC2N-163', 'EC2N-233', 'EC2N-283', 'EC2N-409', 'EC2N-571' ] )
   
  Koblitz curves are a special case of binary curves, with a simpler equation.
  
  Non-standard curve types are supported either via specifying parameters and algorithm,
  or by specifying a generic "standard" via specifying in new the pair:
     standard => 'generic_prime' or standard => 'generic_binary'.
  
  The following are used mainly for non-standard curve types.  They are 
  gotten from pre-defined values for named curves:
  
  p => $p , sets curve modulus  ( for prime curve over F(p) )
  
  a => $a, sets curve param a
  
  b => $b, sets curve param b
  
  N  =>  the exponent in 2**N, where 2**N is a binary curve modulus
    ( for binary or Koblitz curve over F(2**N) )
  
  h    => curve cofactor for the point order
  
  r    =>  base point G order for prime curves
  
  n   =>   base point G order for binary curves
  
  G_x  => $x,  a base point x coordinate
  
  G_y  =>  $y, a base point y coordinate
  
  irreducible => binary curve irreducible basis polynimial in binary integer 
    format, so that x**233 + x**74 + 1 becomes
       polynomial => [ 233, 74, 0 ] and irreducible =>           
         '0x20000000000000000000000000000000000000004000000000000000001'

=item B<a>

  Returns parameter a in the elliptic equation
  
=item B<b>

  Returns parameter b in the elliptic equation

=item B<p>

  returns parameter p in the equation-- this is the field modulus parameter for prime curves
  
  
  
=item B<order>

  Returns the curve base point G order if known
  
=item B<curve_order>

  Returns the curve order if known

=item B<infinity>

  Returns a valid point at infinity for the curve

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
