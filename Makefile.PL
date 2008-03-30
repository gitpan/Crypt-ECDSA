use ExtUtils::MakeMaker;
use 5.008;

WriteMakefile(
    NAME         => 'Crypt::ECDSA', 
    OBJECT       => 'ECDSA.obj',
    LIBS          => [ '-lgmp' ],
    VERSION_FROM => 'lib/Crypt/ECDSA.pm', # finds $VERSION
    AUTHOR       => 'William Hererra (whererra@skylightview.com)',
    ABSTRACT     => 'Digital Signature using Elliptic Curve Cryptography',
    PREREQ_PM    => { 
        Carp => 0, Digest::SHA => 0, Data::Compare => 0, 
        Text::Wrap => 0, Encoding::BER => 0, MIME::Base64 => 0, 
        Crypt::CBC => 1.22, Crypt::Rijndael => 0, Digest::MD5 => 0, 
        Text::Wrap => 0, Crypt::Blowfish => 0, Crypt::DES_EDE3 => 0, 
        Math::BigInt => 0, Math::BigInt::GMP => 0,
    },
);
