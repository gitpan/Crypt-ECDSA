use Test::More tests => 46;

use strict;
no warnings;
require 5.006;

use Math::BigInt lib => 'GMP';
use Math::BigInt::Random qw( random_bigint );
use Crypt::ECDSA::Util qw( bint bigint_from_coeff );

use_ok('Crypt::ECDSA::Curve::Koblitz');


# arrange a generic binary curve
my $F2M = Crypt::ECDSA::Curve::Koblitz->new( 
    irreducible => 19, 
    standard => 'generic_binary',
    a => 1,
    b => 1,
    N => 4
);

my $x1 = bint(6);
my $y1 = bint(5);
my $z1 = $x1 ^ $y1;

my $z1_correct = 3;

ok( $z1 == $z1_correct, "Addition of $x1 to $y1 yields $z1" );
my $x2 = bint(13);
my $y2 = bint(9);

my $z2 = $F2M->multiply_F2m( $x2, $y2 );
my $z2_correct = 15;
ok( $z2 == $z2_correct, "Multiply of $x2 and $y2 to get $z2" );

my $z3 = $F2M->reduce_F2m( $x1 ^ $y1 );
$z3 = $F2M->reduce_F2m($z3);
ok( $z3 == $z1_correct, "Reduction again does nothing to the answer" );

my $coeff = [ 233, 74, 0 ];
$F2M->{irreducible} = bigint_from_coeff($coeff);

my $Gx = bint('0x17232ba853a7e731af129f22ff4149563a419c26bf50a4c9d6eefad6126');
my $Gy = bint('0x1db537dece819b7f70f555a67c427a8cd9bf18aeb9b56e0c11056fae6a3');
my $gx = bint($Gx);
my $gy = bint($Gy);
my $b  = bint(1);

my $lhs =
  $F2M->multiply_F2m( $gy, $gy )->bxor( $F2M->multiply_F2m( $gy, $gx ) );
my $rhs = $F2M->multiply_F2m( $F2M->multiply_F2m( $gx, $gx ), $gx )->badd($b);

ok( $lhs->bxor($rhs) == 0,
    "Curve parameters for K-233 make formula lhs = rhs" );

# import standard curve desciptions
my $named_curve = $Crypt::ECDSA::Curve::named_curve;

my $curve_K163 = Crypt::ECDSA::Curve::Koblitz->new( standard => 'EC2N-163' );
isa_ok( $curve_K163, 'Crypt::ECDSA::Curve' );

my $curve_K233 = Crypt::ECDSA::Curve::Koblitz->new( standard => 'EC2N-233' );
isa_ok( $curve_K233, 'Crypt::ECDSA::Curve' );

my $curve_K283 = Crypt::ECDSA::Curve::Koblitz->new( standard => 'EC2N-283' );
isa_ok( $curve_K283, 'Crypt::ECDSA::Curve' );

my $curve_K409 = Crypt::ECDSA::Curve::Koblitz->new( standard => 'EC2N-409' );
isa_ok( $curve_K409, 'Crypt::ECDSA::Curve' );

my $curve_K571 = Crypt::ECDSA::Curve::Koblitz->new( standard => 'EC2N-571' );
isa_ok( $curve_K571, 'Crypt::ECDSA::Curve' );

my ( $cur, $pG, $p_prod );

# NIST K-163

$pG = Crypt::ECDSA::Point->new(
    X     => $named_curve->{'EC2N-163'}->{G_x},
    Y     => $named_curve->{'EC2N-163'}->{G_y},
    curve => $curve_K163,
    order => $named_curve->{'EC2N-163'}->{n},
);
ok( $curve_K163->is_on_curve( $pG->X, $pG->Y ), "G is on K163" );
$p_prod = $pG * $curve_K163->{n};
ok( $p_prod->is_point_at_infinity, "point G times n is infinity for K-163" );
my $irr = bigint_from_coeff( $pG->{curve}->{polynomial} );
ok( $irr->bcmp( $pG->{curve}->{irreducible} ) == 0,
    "Check polynomial basis for K-163" );

my $pG1 = Crypt::ECDSA::Point->new(
    X     => $named_curve->{'EC2N-163'}->{G_x},
    Y     => $named_curve->{'EC2N-163'}->{G_y},
    curve => $curve_K163,
    order => $named_curve->{'EC2N-163'}->{n},
);
ok( $curve_K163->is_on_curve( $pG1->X, $pG1->Y ), "pG1 is on K163" );

# NIST K-233

$pG = Crypt::ECDSA::Point->new(
    X     => $named_curve->{'EC2N-233'}->{G_x},
    Y     => $named_curve->{'EC2N-233'}->{G_y},
    curve => $curve_K233,
    order => $named_curve->{'EC2N-233'}->{n},
);
ok( $curve_K233->is_on_curve( $pG->X, $pG->Y ), "G is on K233" );
$p_prod = $pG * $curve_K233->{n};
ok( $p_prod->is_point_at_infinity, "point G times n is infinity for K-233" );
$irr = bigint_from_coeff( $pG->{curve}->{polynomial} );
ok( $irr->bcmp( $pG->{curve}->{irreducible} ) == 0,
    "Check polynomial basis for K-233" );

# scalar multiplication
for my $k ( 1262 .. 1281 ) {
    my $Q = $pG1 * $k;
    ok( $Q->is_on_curve, "Point Q = $k" . "G is on curve" );
}

# NIST K-283

$pG = Crypt::ECDSA::Point->new(
    X     => $named_curve->{'EC2N-283'}->{G_x},
    Y     => $named_curve->{'EC2N-283'}->{G_y},
    curve => $curve_K283,
    order => $named_curve->{'EC2N-283'}->{n},
);
ok( $curve_K283->is_on_curve( $pG->X, $pG->Y ), "G is on K283" );
$p_prod = $pG * $curve_K283->{n};
ok( $p_prod->is_point_at_infinity, "point G times n is infinity for K-283" );
$irr = bigint_from_coeff( $pG->{curve}->{polynomial} );
ok( $irr->bcmp( $pG->{curve}->{irreducible} ) == 0,
    "Check polynomial basis for K-283" );

# NIST K-409

$pG = Crypt::ECDSA::Point->new(
    X     => $named_curve->{'EC2N-409'}->{G_x},
    Y     => $named_curve->{'EC2N-409'}->{G_y},
    curve => $curve_K409,
    order => $named_curve->{'EC2N-409'}->{n},
);
ok( $curve_K409->is_on_curve( $pG->X, $pG->Y ), "G is on K409" );
$p_prod = $pG * $curve_K409->{n};
ok( $p_prod->is_point_at_infinity, "point G times n is infinity for K-409" );
$irr = bigint_from_coeff( $pG->{curve}->{polynomial} );
ok( $irr->bcmp( $pG->{curve}->{irreducible} ) == 0,
    "Check polynomial basis for K-409" );

# NIST K-571

$pG = Crypt::ECDSA::Point->new(
    X     => $named_curve->{'EC2N-571'}->{G_x},
    Y     => $named_curve->{'EC2N-571'}->{G_y},
    curve => $curve_K571,
    order => $named_curve->{'EC2N-571'}->{n},
);
ok( $curve_K571->is_on_curve( $pG->X, $pG->Y ), "G is on K571" );
$p_prod = $pG * $curve_K163->{n};
ok( $p_prod->is_point_at_infinity, "point G times n is infinity for K-571" );
$irr = bigint_from_coeff( $pG->{curve}->{polynomial} );
ok( $irr->bcmp( $pG->{curve}->{irreducible} ) == 0,
    "Check polynomial basis for K-571" );
