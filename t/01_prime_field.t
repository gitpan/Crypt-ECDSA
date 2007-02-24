use Test::More tests => 50;

use strict;
no warnings;
require 5.006;

use_ok( 'Crypt::ECDSA' );
use_ok('Crypt::ECDSA::Curve' );
use_ok('Crypt::ECDSA::Curve::Prime' );
use_ok( 'Crypt::ECDSA::Point' );
use_ok( 'Crypt::ECDSA::Key' );
use_ok( 'Crypt::ECDSA::Util' );
use_ok( 'Crypt::ECDSA::ECDSAVS' );


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
my $p1 = Crypt::ECDSA::Point->new( X => 3,  Y => 10,  curve => $curve_p23 );
my $p2 = Crypt::ECDSA::Point->new( X => 9,  Y => 7,   curve => $curve_p23 );
my $p3 = Crypt::ECDSA::Point->new( X => 17, Y => 20,  curve => $curve_p23 );
my $p4 = Crypt::ECDSA::Point->new( X => 7,  Y => 12,  curve => $curve_p23 );
my $p5 = Crypt::ECDSA::Point->new( X => 7,  Y => -12, curve => $curve_p23 );
my $p6 =
  Crypt::ECDSA::Point->new( X => 13, Y => 7, curve => $curve_p23, order => 7 );
ok( $p1 + $p2 == $p3,     "Add points" );
ok( $p1->double() == $p4, "Double a point" );
ok( $p1 + $p1 == $p4,     "add more points" );
ok( $p1 * 2 == $p4,       "scalar point multiply" );
my $p7 = $p4 + $p5;
ok( $p7 == $p7->curve->infinity, "Infinity as a result" );
ok( $p6 * 0 == $p7, "multiply by 0" );

my $sum = $p6->curve->infinity;
$sum->order(7);
for my $i ( 0 .. 15 ) {
    ok( $p6 * $i == $sum, "multiply p6 by $i to get $sum->{X}, $sum->{Y}" );
    $sum += $p6;
}


# Next, test some standard named curves
# see X9.62 I.1
# make sure the point G(Gx, Gy) is on each curve for which we have Gx and Gy

my ( $cur, $pG, $p_prod );

# ECP-160  (not a NIST curve but used by some private industry standards)
my $i2 = Math::BigInt->new('0x4a96b5688ef573284664698968c38bb913cbfc82');
my $i3 = Math::BigInt->new('0x23a628553168947d59dcc912042351377ac5fb32');
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
  Math::BigInt->new(
    '651056770906015076056810763456358567190100156695615665659');
my $x_ans =
  Math::BigInt->new('0x62B12D60690CDCF330BABAB6E69763B471F994DD702D16A5');

my $qq = $p1 * $d;

ok( $qq->X == $x_ans, "multiply points on curve ECP-192" );

$x_ans =
  Math::BigInt->new('0x885052380FF147B734C330C43D39B2C4A89F29B0F749FEAD');
my $y_ans =
  Math::BigInt->new('0x9CF9FA1CBEFEFB917747A3BB29C072B9289C2547884FD835');
$d =
  Math::BigInt->new(
    '2563697409189434185194736134579731015366492496392189760599');
my $e =
  Math::BigInt->new(
    '6266643813348617967186477710235785849136406323338782220568');

$p2 = $p1 * $d + $qq * $e;
ok( $p2->X == $x_ans, "x checked in expression with P-192" );
ok( $p2->Y == $y_ans, "y checked in expression with P-192" );

$d =
  Math::BigInt->new(
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

