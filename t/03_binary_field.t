use Test::More tests => 50;

use strict;
no warnings;
require 5.008;

use Crypt::ECDSA::Util qw( bint hex_bint bigint_from_coeff );
use Crypt::ECDSA qw( multiply_F2m );

# uncomment to sanity check all points generated
#our $WARN_IF_NEW_POINT_INVALID = 1;

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
my $z2 = $F2M->multiply_koblitz( $x2, $y2 );
my $z2_correct = bint(15);
ok( $z2 == $z2_correct, "Multiply of $x2 and $y2 to get $z2" );

my $coeff = [ 233, 74, 0 ];
$F2M->{irreducible} = bigint_from_coeff($coeff);

my $Gx = bint('0x17232ba853a7e731af129f22ff4149563a419c26bf50a4c9d6eefad6126');
my $Gy = bint('0x1db537dece819b7f70f555a67c427a8cd9bf18aeb9b56e0c11056fae6a3');
my $b  = 1;

my $lhs = $F2M->multiply_koblitz( $Gy, $Gy ) ^ $F2M->multiply_koblitz( $Gy, $Gx );
my $rhs = $F2M->multiply_koblitz( $F2M->multiply_koblitz( $Gx, $Gx ), $Gx ) + $b;

ok( $lhs == $rhs, "Curve parameters for K-233 make formula lhs = rhs" );

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
ok( $irr == $pG->{curve}->{irreducible},
    "Check polynomial basis for K-163" );

# check for simultaneous curves ok
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
ok( $irr == $pG->{curve}->{irreducible},
    "Check polynomial basis for K-233" );

# scalar multiplication
for my $k ( 1262 .. 1282 ) {
    my $Q = $pG * $k;
    ok( $Q->is_on_curve, "Point Q = $k" . " * pG1 is on curve" );
}

# check specific values for on-curve status

my $ecdsa = Crypt::ECDSA->new( standard => 'EC2N-233' );
my @false_k233_points = (
    { 
        Qx => bint('0x534537f7762394d8ff46675d194aa212c4f9a2b5705f68df74e4e35d59'),
        Qy => bint('0x1b4bb8fa0cd97777f60f4d7e4038cd65527eff4570b09204fdbedabc7d2'),
    },
    {
        Qx => bint('0x13ca0f0875f8fea41a1f44aa7603a85324507c7177b616627459feabd3b'),
        Qy => bint('0x61fc08300b6cf0c99c5f923ccc65f9be1fd9449b0625ed6a7f767e6a4d'),
    },
);
my @true_k233_points = (
    {
        Qx => bint('0x148dec1cffafce7ce21ae80652935bbb8b960bb1c4f27830d7ac0a786a5'),
        Qy => bint('0xc845acaaccc4549b8e2323a7f7ec17e0c8ae7a574c8e6a1ce337939c7b'),
    },
    {
        Qx => bint('0x79a6cbfe3a2e9e9eaef2b119787682ad51b7e1003e0bd952417f651d65'),
        Qy => bint('0x990e7736bed24326c49a683587e72b24d8e5b62c037495a99f21438bac'),
    },
);

foreach my $invalid_point (@false_k233_points) {
    my $qx = $invalid_point->{Qx};
    my $qy = $invalid_point->{Qy};
    ok( $ecdsa->is_valid_point( $qx, $qy ) == 0, "point on curve is not valid" );
}

foreach my $valid_point (@true_k233_points) {
    my $qx = $valid_point->{Qx};
    my $qy = $valid_point->{Qy};
    ok( $ecdsa->is_valid_point( $qx, $qy ) != 0, "point on curve is valid" );
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
ok( $p_prod->is_point_at_infinity, "point G times n ( " . 
    $p_prod->{Y} . ", " . $p_prod->{Y} . " ) is infinity for K-283" );
$irr = bigint_from_coeff( $pG->{curve}->{polynomial} );
ok( $irr == $pG->{curve}->{irreducible}, "Check polynomial basis for K-283" );

# NIST K-409

$pG = Crypt::ECDSA::Point->new(
    X     => $named_curve->{'EC2N-409'}->{G_x},
    Y     => $named_curve->{'EC2N-409'}->{G_y},
    curve => $curve_K409,
    order => $curve_K409->{point_order},
);
ok( $curve_K409->is_on_curve( $pG->X, $pG->Y ), "G is on K409" );
$p_prod = $pG * $curve_K409->{n};
ok( $p_prod->is_point_at_infinity, "point G times n ( " . 
    $p_prod->{Y} . ", " . $p_prod->{Y} . " ) is infinity for K-409" );
$irr = bigint_from_coeff( $pG->{curve}->{polynomial} );
ok( $irr == $pG->{curve}->{irreducible}, "Check polynomial basis for K-409" );


# NIST K-571

$pG = Crypt::ECDSA::Point->new(
    X     => $named_curve->{'EC2N-571'}->{G_x},
    Y     => $named_curve->{'EC2N-571'}->{G_y},
    curve => $curve_K571,
    order => $curve_K571->{point_order},
);
ok( $curve_K571->is_on_curve( $pG->X, $pG->Y ), "G is on K571" );
$p_prod = $pG * $curve_K571->{n};
ok( $p_prod->is_point_at_infinity, "point G times n ( " . 
    $p_prod->{Y} % $pG->{order} . ", " . $p_prod->{Y} % $pG->{order} . " ) is infinity for K-571" );
$irr = bigint_from_coeff( $pG->{curve}->{polynomial} );
ok( $irr == $pG->{curve}->{irreducible}, "Check polynomial basis for K-571" );
