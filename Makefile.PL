use ExtUtils::MakeMaker;
use 5.006;

WriteMakefile(
    NAME         => 'Crypt::ECDSA',
    VERSION_FROM => 'lib/Crypt/ECDSA.pm', # finds $VERSION
    AUTHOR       => 'William Hererra (whererra@skylightview.com)',
    ABSTRACT     => 'Digital Signature using Elliptic Curve Cryptography',
    PREREQ_PM    => { 
        Carp => 0, Math::BigInt => 0, Digest::SHA => 0, Math::BigInt::GMP => 0,
        Math::GMP => 0, Data::Compare => 0 ,  #  Memoize => 0, 
    },
);
