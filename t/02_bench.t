use Test::More tests => 8;

use strict;
use warnings;
use Crypt::ECDSA;
use Crypt::ECDSA::Point;
use Crypt::ECDSA::Util qw( bint );

SKIP:
{

    eval "use Time::HiRes";
    skip "because Time::HighRes is required for benchmarking", 4 if $@;

    # NIST P-256
    my $curve_P256 = Crypt::ECDSA::Curve::Prime->new( standard => 'ECP-256' );
    my $cur_list   = $Crypt::ECDSA::Curve::named_curve;
    my $cur        = $cur_list->{'ECP-256'};
    my ( $elapsed, $msec_per_iter );

    my $pG = Crypt::ECDSA::Point->new(
        X     => $cur->{G_x},
        Y     => $cur->{G_y},
        curve => $curve_P256
    );

    my $iters = 1000;

    for my $r ( 1 ... $iters ) {
        my $p_prod = $pG * $r;

        #print "pG * r, for r of $r, is ( ", $pG->{X}, ", " $pG->{Y}, " )\n";
    }

    my $t0;

    #Crypt::ECDSA::sidechannel_protection(0);

    $t0 = [ Time::HiRes::gettimeofday() ];
    for my $r ( 1 ... $iters ) {
        my $p_prod = $pG * $r;

        #print "pG * r, for r of $r, is ( ", $pG->{X}, ", " $pG->{Y}, " )\n";
    }

    $elapsed       = Time::HiRes::tv_interval($t0);
    $msec_per_iter = $elapsed * 1000 / $iters;
    print
"\nWithout sidechannel protection, benchmark $msec_per_iter msec/P-256 point multiply\n";
    ok( $msec_per_iter < 10, "fast enough on this machine" );

    Crypt::ECDSA::sidechannel_protection(1);

    $t0 = [ Time::HiRes::gettimeofday() ];
    for my $r ( 1 ... $iters ) {
        my $p_prod = $pG * $r;

        #print "pG * r, for r of $r, is ( ", $pG->{X}, ", " $pG->{Y}, " )\n";
    }

    $elapsed       = Time::HiRes::tv_interval($t0);
    $msec_per_iter = $elapsed * 1000 / $iters;
    print
"\nWith sidechannel protection, benchmark $msec_per_iter msec/P-256 point multiply\n";
    ok( $msec_per_iter < 10, "fast enough on this machine" );

    # NIST K-233

    my $curve_K233 =
      Crypt::ECDSA::Curve::Koblitz->new( standard => 'EC2N-233' );
    $cur = $cur_list->{'EC2N-233'};

    $pG = Crypt::ECDSA::Point->new(
        X     => $cur->{'EC2N-233'}->{G_x},
        Y     => $cur->{'EC2N-233'}->{G_y},
        curve => $curve_K233,
        order => $cur->{n},
    );

    Crypt::ECDSA::sidechannel_protection(0);

    $t0 = [ Time::HiRes::gettimeofday() ];
    for my $r ( 1 ... $iters ) {
        my $p_prod = $pG * $r;

        #print "pG * r, for r of $r, is ( ", $pG->{X}, ", " $pG->{Y}, " )\n";
    }

    $elapsed       = Time::HiRes::tv_interval($t0);
    $msec_per_iter = $elapsed * 1000 / $iters;
    print
"\nWithout sidechannel protection, benchmark $msec_per_iter msec/K-233 point multiply\n";
    ok( $msec_per_iter < 10, "fast enough on this machine" );

    Crypt::ECDSA::sidechannel_protection(1);

    $t0 = [ Time::HiRes::gettimeofday() ];
    for my $r ( 1 ... $iters ) {
        my $p_prod = $pG * $r;

        #print "pG * r, for r of $r, is ( ", $pG->{X}, ", " $pG->{Y}, " )\n";
    }

    $elapsed       = Time::HiRes::tv_interval($t0);
    $msec_per_iter = $elapsed * 1000 / $iters;
    print
"\nWith sidechannel protection, benchmark $msec_per_iter msec/K-233 point multiply\n";
    ok( $msec_per_iter < 10, "fast enough on this machine" );

    # benchmark ECDSA with 20 byte SHA-1 sig already calculated, sig and verify
    my $ecdsa    = Crypt::ECDSA->new( standard => 'ECP-256' );
    my $msg      = "This is a test message for perl ecdsa.";
    my $msg_hash = $ecdsa->make_text_digest($msg);
    Crypt::ECDSA::sidechannel_protection(0);

    my $key       = $ecdsa->key;
    my $r         = bint(1);
    my $s         = bint(1);
    my $Gx        = $key->{G}->{X};
    my $Gy        = $key->{G}->{Y};
    my $d         = bint( $key->{d} );
    my $is_binary = $key->curve->{irreducible} ? 1 : 0;
    my $n         = bint( $key->G->order );
    my $mod       = $key->curve->modulus;
    my $a         = $key->curve->{a};
    my $a_neg     = ( $a < 0 ) ? 1 : 0;
    my $max_tries = 120;

    $t0 = [ Time::HiRes::gettimeofday() ];
    for ( 1 ... 200 ) {
        Crypt::ECDSA::ecdsa_sign_hash(
            $r->{value},  $s->{value},   $msg_hash->{value},
            $Gx->{value}, $Gy->{value},  $n->{value},
            $d->{value},  $mod->{value}, $a->{value},
            $a_neg,       $is_binary,    $max_tries
        );
    }
    $elapsed       = Time::HiRes::tv_interval($t0);
    $msec_per_iter = $elapsed * 1000 / 200;
    print
      "\nIt takes an average of $msec_per_iter msec / ECDSA-256 signature\n";
    ok( $elapsed < 300, "fast enough on this machine" );
    my $Qx = $key->Qx;
    my $Qy = $key->Qy;
    $t0 = [ Time::HiRes::gettimeofday() ];

    for ( 1 ... 200 ) {
        my $verify_ok = ecdsa_verify_hash(
            $r->{value},  $s->{value},  $msg_hash->{value},
            $Gx->{value}, $Gy->{value}, $Qx->{value},
            $Qy->{value}, $n->{value},  $mod->{value},
            $a->{value}, $a_neg, $is_binary ? 1 : 0
        );
        die "bad sig not expected on iteration number $_" unless $verify_ok;
    }
    $elapsed       = Time::HiRes::tv_interval($t0);
    $msec_per_iter = $elapsed * 1000 / 200;
    print "\nIt takes an average of $msec_per_iter msec / ECDSA-256 verify\n";
    ok( $elapsed < 600, "fast enough on this machine" );

    $ecdsa     = Crypt::ECDSA->new( standard => 'EC2N-233' );
    $key       = $ecdsa->key;
    $r         = bint(1);
    $s         = bint(1);
    $Gx        = $key->{G}->{X};
    $Gy        = $key->{G}->{Y};
    $is_binary = $key->curve->{irreducible} ? 1 : 0;
    $n          = bint( $key->G->order );
    $mod        = $key->curve->modulus;
    $d         = bint( $key->{d} );
    $a         = $key->curve->{a};
    $a_neg     = ( $a < 0 ) ? 1 : 0;
    $is_binary = $ecdsa->key->curve->{irreducible} ? 1 : 0;
    $max_tries = 120;
    $Qx        = $key->Qx;
    $Qy        = $key->Qy;
    $t0        = [ Time::HiRes::gettimeofday() ];
    for ( 1 ... 100 ) {
        Crypt::ECDSA::ecdsa_sign_hash(
            $r->{value},  $s->{value},   $msg_hash->{value},
            $Gx->{value}, $Gy->{value},  $n->{value},
            $d->{value},  $mod->{value}, $a->{value},
            $a_neg,       $is_binary,   $max_tries
        );
    }
    $elapsed       = Time::HiRes::tv_interval($t0);
    $msec_per_iter = $elapsed * 1000 / 100;
    print
      "\nIt takes an average of $msec_per_iter msec / ECDSA-233 signature\n";
    ok( $elapsed < 300, "fast enough on this machine" );

    $t0 = [ Time::HiRes::gettimeofday() ];
    for ( 1 ... 50 ) {
        my $verify_ok = ecdsa_verify_hash(
            $r->{value},  $s->{value},  $msg_hash->{value},
            $Gx->{value}, $Gy->{value}, $Qx->{value},
            $Qy->{value}, $n->{value},  $mod->{value},
            $a->{value}, $a_neg, $is_binary ? 1 : 0
        );
        die "bad sig not expected on $_ iteration" unless $verify_ok;
    }
    $elapsed       = Time::HiRes::tv_interval($t0);
    $msec_per_iter = $elapsed * 1000 / 50;
    print "\nIt takes an average of $msec_per_iter msec / ECDSA-233 verify\n";
    ok( $elapsed < 600, "fast enough on this machine" );

}
