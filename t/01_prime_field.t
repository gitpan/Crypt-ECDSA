use Test::More tests => 560;

use strict;
no warnings;
require 5.008;

use Crypt::ECDSA::Util qw( bint hex_bint );

use_ok( 'Crypt::ECDSA' );
use_ok('Crypt::ECDSA::Curve' );
use_ok('Crypt::ECDSA::Curve::Prime' );
use_ok( 'Crypt::ECDSA::Point' );
use_ok( 'Crypt::ECDSA::Key' );
use_ok( 'Crypt::ECDSA::ECDSAVS' );
use_ok( 'Crypt::ECDSA::PEM' );

# uncomment to sanity check all points generated
#our $WARN_IF_NEW_POINT_INVALID = 1;

# Test Crypt::ECDSA::Curve and Crypt::ECDSA::Point routines

# import standard curve desciptions
my $named_curve = $Crypt::ECDSA::Curve::named_curve;

# Generate a few curves
my $curve_p23 = Crypt::ECDSA::Curve::Prime->new(
    standard  => 'generic_prime',
    p         => 23,
    a         => 1,
    b         => 1,
);
isa_ok( $curve_p23, 'Crypt::ECDSA::Curve' );

my $curve_P160 = Crypt::ECDSA::Curve::Prime->new( standard => 'ECP-160' );
isa_ok( $curve_P160, 'Crypt::ECDSA::Curve' );

my $curve_P192 = Crypt::ECDSA::Curve::Prime->new( standard => 'ECP-192' );
isa_ok( $curve_P192, 'Crypt::ECDSA::Curve' );

my $curve_P224 = Crypt::ECDSA::Curve::Prime->new( standard => 'ECP-224' );
isa_ok( $curve_P224, 'Crypt::ECDSA::Curve' );

my $curve_P256 = Crypt::ECDSA::Curve::Prime->new( standard => 'ECP-256' );
isa_ok( $curve_P256, 'Crypt::ECDSA::Curve' );

my $curve_P384 = Crypt::ECDSA::Curve::Prime->new( standard => 'ECP-384' );
isa_ok( $curve_P384, 'Crypt::ECDSA::Curve' );

my $curve_P521 = Crypt::ECDSA::Curve::Prime->new( standard => 'ECP-521' );
isa_ok( $curve_P521, 'Crypt::ECDSA::Curve' );


# ECC curve math (prime fields)
# X9.62 B.3
my $p1 = Crypt::ECDSA::Point->new( X => 3,  Y =>  10,  curve => $curve_p23 );
my $p2 = Crypt::ECDSA::Point->new( X => 9,  Y =>   7,   curve => $curve_p23 );
my $p3 = Crypt::ECDSA::Point->new( X => 17, Y =>  20,  curve => $curve_p23 );
my $p4 = Crypt::ECDSA::Point->new( X => 7,  Y =>  12,  curve => $curve_p23 );
my $p5 = Crypt::ECDSA::Point->new( X => 7,  Y => -12, curve => $curve_p23 );
my $p6 =
  Crypt::ECDSA::Point->new( X => 13, Y => 7, curve => $curve_p23, order => 7 );
ok( $p1 + $p2 == $p3,     "Add points" );
ok( $p1->double() == $p4, "Double a point" );
ok( $p1 + $p1 == $p4,     "add more points" );
ok( $p1 * 2 == $p4,       "scalar point multiply" );
my $p7 = $p4 + $p5;
ok( $p7 == $p7->curve->infinity, 
  "Infinity as a result of " .
 " ( " . $p4->{X} . " , " . $p4->{Y} . " ) + " .
 " ( " . $p5->{X} . " , " . $p5->{Y} . " ) = " .
 " ( " . $p7->{X} . " , " . $p7->{Y} . " )" );
ok( $p6 * 0 == $p7, "multiply by 0" );

my $sum = $p6->curve->infinity;
$sum->order(7);
for my $i ( 0 .. 521 ) {
    ok( $p6 * $i == $sum, 
      "multiply [p6(13, 7) mod 23] by $i to get $sum->{X}, $sum->{Y}" );
    $sum += $p6;
}


# Next, test some standard named curves
# see X9.62 I.1
# make sure the point G(Gx, Gy) is on each curve for which we have Gx and Gy

my ( $cur, $pG, $p_prod );

# ECP-160  (not a NIST curve but used by some private industry standards)
my $i2 = bint('0x4a96b5688ef573284664698968c38bb913cbfc82');
my $i3 = bint('0x23a628553168947d59dcc912042351377ac5fb32');
$p1 = Crypt::ECDSA::Point->new( X => $i2, Y => $i3, curve => $curve_P160 );
isa_ok( $p1, 'Crypt::ECDSA::Point' );

$cur = $named_curve->{'ECP-160'};
$pG  = Crypt::ECDSA::Point->new(
    X     => $cur->{G_x},
    Y     => $cur->{G_y},
    curve => $curve_P160
);
$p_prod = $pG * $cur->{r};
ok( $p_prod->is_point_at_infinity, "point G times r is infinity for P-160" );


# NIST P-192

$p1 = Crypt::ECDSA::Point->new(
    X     => $named_curve->{'ECP-192'}->{G_x},
    Y     => $named_curve->{'ECP-192'}->{G_y},
    curve => $curve_P192,
    order => $named_curve->{'ECP-192'}->{r},
);
isa_ok( $p1, 'Crypt::ECDSA::Point' );
isa_ok( $p1->curve, 'Crypt::ECDSA::Curve' );

my $d =
  bint(
    '651056770906015076056810763456358567190100156695615665659');
my $x_ans =
  bint('0x62B12D60690CDCF330BABAB6E69763B471F994DD702D16A5');

my $qq = $p1 * $d;

ok( $qq->X == $x_ans, "multiply points on curve ECP-192" );

$x_ans =
  bint('0x885052380FF147B734C330C43D39B2C4A89F29B0F749FEAD');
my $y_ans =
  bint('0x9CF9FA1CBEFEFB917747A3BB29C072B9289C2547884FD835');
$d =
  bint(
    '2563697409189434185194736134579731015366492496392189760599');
my $e =
  bint(
    '6266643813348617967186477710235785849136406323338782220568');

$p2 = $p1 * $d + $qq * $e;
ok( $p2->X == $x_ans, "x checked in expression with P-192" );
ok( $p2->Y == $y_ans, "y checked in expression with P-192" );

$d =
  bint(
    '6140507067065001063065065565667405560006161556565665656654');
$qq = $p1 * $d;
ok( $qq->X() == $x_ans, "x checked in point multiply on curve P-192" );
ok( $qq->Y() == $y_ans, "y checked in point multiply on curve P-192" );

$cur = $named_curve->{'ECP-192'};
$pG  = Crypt::ECDSA::Point->new(
    X     => $cur->{G_x},
    Y     => $cur->{G_y},
    curve => $curve_P192
);
$p_prod = $pG * $cur->{r};
ok( $p_prod->is_point_at_infinity, "point G times r is infinity for P-192" );

# check specific values for on-curve status

my $ecdsa = Crypt::ECDSA->new( standard => 'ECP-192' );
my @false_p192_points = (
    { 
        Qx => bint('0xcd6d0f029a023e9aaca429615b8f577abee685d8257cc83a'),
        Qy => bint('0x19c410987680e9fb6c0b6ecc01d9a2647c8bae27721bacdfc'),

    },
    {
        Qx => bint('0x17f2fce203639e9eaf9fb50b81fc32776b30e3b02af16c73b'),
        Qy => bint('0x95da95c5e72dd48e229d4748d4eee658a9a54111b23b2adb'),
    },
);
my @true_p192_points = (
    {
        Qx => bint('0xc58d61f88d905293bcd4cd0080bcb1b7f811f2ffa41979f6'),
        Qy => bint('0x8804dc7a7c4c7f8b5d437f5156f3312ca7d6de8a0e11867f'),
    },
    {
        Qx => bint('0xcdf56c1aa3d8afc53c521adf3ffb96734a6a630a4a5b5a70'),
        Qy => bint('0x97c1c44a5fb229007b5ec5d25f7413d170068ffd023caa4e'),
    },
);

foreach my $invalid_point (@false_p192_points) {
    my $qx = $invalid_point->{Qx};
    my $qy = $invalid_point->{Qy};
    ok( $ecdsa->is_valid_point( $qx, $qy ) == 0, "point on curve is not valid" );
}

foreach my $valid_point (@true_p192_points) {
    my $qx = $valid_point->{Qx};
    my $qy = $valid_point->{Qy};
    ok( $ecdsa->is_valid_point( $qx, $qy ) != 0, "point on curve is valid" );
}


# NIST P-224
$cur = $named_curve->{'ECP-224'};
$pG  = Crypt::ECDSA::Point->new(
    X     => $cur->{G_x},
    Y     => $cur->{G_y},
    curve => $curve_P224
);

$p_prod = $pG * $cur->{r};
ok( $p_prod->is_point_at_infinity, "point G times r is infinity for P-224" );


# NIST P-256
$cur = $named_curve->{'ECP-256'};
$pG  = Crypt::ECDSA::Point->new(
    X     => $cur->{G_x},
    Y     => $cur->{G_y},
    curve => $curve_P256
);
$p_prod = $pG * $cur->{r};
ok( $p_prod->is_point_at_infinity, "point G times r is infinity for P-256" );


# NIST P-384
$cur = $named_curve->{'ECP-384'};
$pG  = Crypt::ECDSA::Point->new(
    X     => $cur->{G_x},
    Y     => $cur->{G_y},
    curve => $curve_P384
);
$p_prod = $pG * $cur->{r};
ok( $p_prod->is_point_at_infinity, "point G times r is infinity for P-384" );


# NIST P-521
$cur = $named_curve->{'ECP-521'};
$pG  = Crypt::ECDSA::Point->new(
    X     => $cur->{G_x},
    Y     => $cur->{G_y},
    curve => $curve_P521
);
$p_prod = $pG * $cur->{r};
ok( $p_prod->is_point_at_infinity, "point G times r is infinity for P-521" );

