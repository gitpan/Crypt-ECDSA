#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include <gmp.h>

#ifdef OLDPERL
#define SvUOK SvIsUV
#endif

/*
Crypt::ECDSA.xs, prime and finite binary field math routines for better speed
This code copyright (C) William Hererra, 2007, 2008, under terms of Perl itself
*/


SV * multiply_F2m( SV * x_in, SV * y_in, SV * mod_in ) {
    mpz_t * mpz_t_obj;
    SV * obj_ref, * obj;

    long i, r;
    mpz_t *x = INT2PTR( mpz_t *, SvIV(SvRV(x_in)) );
    mpz_t *y = INT2PTR( mpz_t *, SvIV(SvRV(y_in)) );
    mpz_t *mod = INT2PTR( mpz_t *, SvIV(SvRV(mod_in)) );
    mpz_t product, accum, yval;
    
    mpz_init( accum );
    mpz_init_set( yval, *y );
    r = mpz_sizeinbase( *x, 2 );
    for( i = 0; i < r; ++i ) {
        if( mpz_tstbit( *x, i ) ) {
            mpz_xor( accum, accum, yval );
        }
        mpz_mul_2exp( yval, yval, 1 );
    }
    mpz_init_set( product, accum );
    while( 1 ) {
        r = mpz_sizeinbase( product, 2 ) - mpz_sizeinbase( *mod, 2 );
        if( r < 0 ) {
            break;
        }
        mpz_mul_2exp( accum, *mod, r );
        mpz_xor( product, product, accum );
    }

    New(1, mpz_t_obj, 1, mpz_t);
    if(mpz_t_obj == NULL) croak("Failed to allocate memory in multiply_F2m function");
    obj_ref = newSViv(0);
    obj = newSVrv(obj_ref, "Math::BigInt::GMP");
    mpz_init_set(*mpz_t_obj, product);

    sv_setiv(obj, INT2PTR(IV, mpz_t_obj));
    SvREADONLY_on(obj);
    return obj_ref;
}


SV * invert_F2m( SV * x_in, SV * mod_in ) {
    mpz_t * mpz_t_obj;
    mpz_t b, c, u, v, temp, vj, cj;
    SV * obj_ref, * obj;
    long j, k;
    mpz_t * x   = INT2PTR( mpz_t *, SvIV(SvRV(x_in)) );
    mpz_t * mod = INT2PTR( mpz_t *, SvIV(SvRV(mod_in)) );
    
    mpz_init_set_si( b, 1 );
    mpz_init( c );
    mpz_init_set( u, *x );
    mpz_init_set( v, *mod );
    mpz_init( temp );
    mpz_init( vj );
    mpz_init( cj );
    while( ( k = mpz_sizeinbase( u, 2 ) ) > 1 ) {
        j = k - mpz_sizeinbase( v, 2 );
        if( j < 0 ) {
            mpz_set( temp, u );
            mpz_set( u, v );
            mpz_set( v, temp );
            mpz_set( temp, c );
            mpz_set( c, b );
            mpz_set( b, temp );
            j = -j;
        }
        mpz_mul_2exp( vj, v, j );
        mpz_xor( u, u, vj );
        mpz_mul_2exp( cj, c, j );
        mpz_xor( b, b, cj );
    }
    New( 1, mpz_t_obj, 1, mpz_t );
    if(mpz_t_obj == NULL) croak("Failed to allocate memory in invert_F2m function");
    obj_ref = newSViv(0);
    obj = newSVrv( obj_ref, "Math::BigInt::GMP" );
    mpz_init_set( *mpz_t_obj, b );

    sv_setiv( obj, INT2PTR(IV, mpz_t_obj) );
    SvREADONLY_on(obj);
    return obj_ref;
}


MODULE  = Crypt::ECDSA		PACKAGE = Crypt::ECDSA 
PROTOTYPES: ENABLE


SV *
multiply_F2m ( x_in, y_in, mod_in )
	SV *	x_in
	SV *	y_in
	SV *	mod_in


SV *
invert_F2m ( x_in, mod_in )
	SV *	x_in
	SV *	mod_in

