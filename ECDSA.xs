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


/* context static data for random intialization */

#define MY_CXT_KEY "Crypt::ECDSA::_guts" XS_VERSION

typedef struct {
   gmp_randstate_t state;
   int reserved;
} my_cxt_t;

START_MY_CXT

/* end random static function initialization */



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
    if(mpz_t_obj == NULL) 
        croak("Failed to allocate memory in invert_F2m function");
    obj_ref = newSViv(0);
    obj = newSVrv( obj_ref, "Math::BigInt::GMP" );
    mpz_init_set( *mpz_t_obj, b );

    sv_setiv( obj, INT2PTR(IV, mpz_t_obj) );
    SvREADONLY_on(obj);
    return obj_ref;
}


int gmp_is_probably_prime( SV * num, SV * reps_to_run ) {
    mpz_t * mpzp_n    = INT2PTR( mpz_t *, SvIV(SvRV(num)) );
    return mpz_probab_prime_p( *mpzp_n, SvUV(reps_to_run) );    
}

SV * gmp_random_bits( SV * num_bits ) {
    mpz_t * mpz_t_obj;
    SV * obj_ref, * obj;

    dMY_CXT;

    mpz_t result;
    unsigned long bits = SvIV(num_bits); 

    mpz_init(result);
    mpz_urandomb( result, MY_CXT.state, bits ); 

    New( 1, mpz_t_obj, 1, mpz_t );
    if(mpz_t_obj == NULL) 
      croak("Failed to allocate memory in gmp_random_bits function");
    obj_ref = newSViv(0);
    obj = newSVrv(obj_ref, "Math::BigInt::GMP");
    mpz_init_set( *mpz_t_obj, result );

    sv_setiv(obj, INT2PTR(IV, mpz_t_obj));
    SvREADONLY_on(obj);
    return obj_ref;
}

void double_Fp_pt( mpz_t x_result, mpz_t y_result, 
                   mpz_t x, mpz_t y, mpz_t mod, mpz_t a ) {
    mpz_t double_y, lm, temp;
    mpz_init(lm);
    mpz_init(temp);
    mpz_init(double_y);
    mpz_mul_ui( double_y, y, 2 );
    if( mpz_invert( double_y, double_y, mod ) == 0 ) {
        mpz_set_ui( x_result, 0 );
        mpz_set_ui( y_result, 0 );
    }
    else {
        mpz_mul( lm, x, x );
        mpz_mul_ui( lm, lm, 3 );
        mpz_add( lm, lm, a );
        mpz_mul( lm, lm, double_y );
        mpz_mod(lm, lm, mod );
        
        mpz_mul( x_result, lm, lm );
        mpz_mul_2exp( temp, x, 1 );
        mpz_sub( x_result, x_result, temp );
        mpz_mod( x_result, x_result, mod );
                   
        mpz_sub( temp, x, x_result );
        mpz_mul( temp, lm, temp );
        mpz_sub( temp, temp, y );
        mpz_mod( y_result, temp, mod );
    }  
}

void double_Fp_point( SV *x_in, SV *y_in, SV *mod_in, SV *a_in, SV * a_neg ) {
    mpz_t *x      = INT2PTR( mpz_t *, SvIV(SvRV(x_in)) );
    mpz_t *y      = INT2PTR( mpz_t *, SvIV(SvRV(y_in)) );
    mpz_t *mod    = INT2PTR( mpz_t *, SvIV(SvRV(mod_in)) );
    mpz_t *a      = INT2PTR( mpz_t *, SvIV(SvRV(a_in)) );
    mpz_t *neg_a  = INT2PTR( mpz_t *, SvIV(SvRV(a_neg)) );
    
    mpz_t old_x, old_y;

    mpz_init_set( old_x, *x );
    mpz_init_set( old_y, *y );

    if( mpz_sgn(*neg_a) ) mpz_neg( *a, *a );
    
    /* MODIFIES (x, y) IN PLACE */
    double_Fp_pt( *x, *y, old_x, old_y, *mod, *a );
}

void add_Fp_pt( mpz_t x_result, mpz_t y_result, mpz_t x1, mpz_t y1, 
                         mpz_t x2, mpz_t y2, mpz_t mod, mpz_t a ) {
    mpz_t dy2y1, dx2x1, lm, temp;
    mpz_init(temp);
    mpz_init(lm);
    mpz_init_set( dy2y1, y2 );
    mpz_sub( dy2y1, dy2y1, y1 );
    mpz_init_set( dx2x1, x2 );
    mpz_sub( dx2x1, dx2x1, x1 );
    if( mpz_cmp( x1, x2 ) == 0 ) {
        mpz_add( temp, y1, y2 );
        mpz_mod( temp, temp, mod );
        if( mpz_sgn(temp) == 0 ) {
            mpz_set_ui( x_result, 0);
            mpz_set_ui( y_result, 0);
        }
        else {
            double_Fp_pt( x_result, y_result, x1, y1, mod, a );
        }
    }
    else {
        if( mpz_invert( dx2x1, dx2x1, mod ) == 0 ) {
            mpz_set_ui( x_result, 0);
            mpz_set_ui( y_result, 0);
        }
        else {
            mpz_mul( lm, dy2y1, dx2x1 );
            mpz_mod( lm, lm, mod );
            mpz_mul( temp, lm, lm );
            mpz_sub( temp, temp, x1 );
            mpz_sub( temp, temp, x2 );
            mpz_mod( x_result, temp, mod );
        
            mpz_sub( temp, x1, x_result );
            mpz_mul( temp, lm, temp );
            mpz_sub( temp, temp, y1 );
            mpz_mod( y_result, temp, mod );
        }
    }
}

void add_Fp_point( SV *x1_in, SV *y1_in, SV *x2_in, SV *y2_in, 
                   SV *mod_in, SV *a_in, SV * a_neg ) {
    mpz_t *x1      = INT2PTR( mpz_t *, SvIV(SvRV(x1_in)) );
    mpz_t *y1      = INT2PTR( mpz_t *, SvIV(SvRV(y1_in)) );
    mpz_t *x2      = INT2PTR( mpz_t *, SvIV(SvRV(x2_in)) );
    mpz_t *y2      = INT2PTR( mpz_t *, SvIV(SvRV(y2_in)) );
    mpz_t *mod     = INT2PTR( mpz_t *, SvIV(SvRV(mod_in)) );
    mpz_t *a       = INT2PTR( mpz_t *, SvIV(SvRV(a_in)) );
    mpz_t *neg_a  = INT2PTR( mpz_t *, SvIV(SvRV(a_neg)) );
     
    mpz_t old_x1, old_y1;
    
    mpz_init_set( old_x1, *x1 );
    mpz_init_set( old_y1, *y1 );
    
    if( mpz_sgn(*neg_a) ) mpz_neg( *a, *a );
    
    /* MODIFIES (x1, y1) IN PLACE */
    add_Fp_pt( *x1, *y1, old_x1, old_y1, *x2, *y2, *mod, *a );
}

void multiply_Fp_pt( mpz_t x_result, mpz_t y_result, mpz_t x, mpz_t y, 
                         mpz_t scalar, mpz_t mod, mpz_t a ) {
    mpz_t y_neg, tripled, pivot_bit, accum_x, accum_y;
    mpz_t test_tripled, test_scalar, temp_accum_x, temp_accum_y;
    
    mpz_init_set( y_neg, y );
    mpz_neg( y_neg, y_neg );
    mpz_init_set( tripled, scalar );
    mpz_mul_ui( tripled, tripled, 3 );
    mpz_init_set_ui( pivot_bit, 1 );
    mpz_init_set( accum_x, x );
    mpz_init_set( accum_y, y );
    mpz_init(test_tripled);
    mpz_init(test_scalar);
    mpz_init(temp_accum_x);
    mpz_init(temp_accum_y);
    
    /* X9.62 docs, D.3.2 */
    do {
        mpz_mul_2exp( pivot_bit, pivot_bit, 1 );
    } while( mpz_cmp( pivot_bit, tripled) <= 0 );
    mpz_tdiv_q_2exp( pivot_bit, pivot_bit, 2 );

    while( mpz_cmp_ui( pivot_bit, 1 ) > 0 ) {
        mpz_set( temp_accum_x, accum_x );
        mpz_set( temp_accum_y, accum_y );
        double_Fp_pt( accum_x, accum_y, temp_accum_x, temp_accum_y, mod, a );
        mpz_and( test_tripled, tripled, pivot_bit );
        mpz_and( test_scalar, scalar, pivot_bit );
        mpz_set( temp_accum_x, accum_x );
        mpz_set( temp_accum_y, accum_y );
        if( ( mpz_sgn(test_tripled) != 0 ) 
            && ( mpz_sgn(test_scalar) == 0 ) ) {
            add_Fp_pt( accum_x, accum_y, temp_accum_x, temp_accum_y, x, y, mod, a );
        }
        if( ( mpz_sgn(test_tripled) == 0 ) 
            && ( mpz_sgn(test_scalar) != 0 ) ) {
            add_Fp_pt( accum_x, accum_y, temp_accum_x, temp_accum_y, x, y_neg, mod, a );
        }
        mpz_tdiv_q_2exp( pivot_bit, pivot_bit, 1 );
    }
    mpz_set( x_result, accum_x );
    mpz_set( y_result, accum_y );
}

void multiply_Fp_point( SV * x_in, SV * y_in, SV * scalar_in, 
                                    SV * mod_in, SV * a_in, SV * a_neg ) {
    mpz_t *x      = INT2PTR( mpz_t *, SvIV(SvRV(x_in)) );
    mpz_t *y      = INT2PTR( mpz_t *, SvIV(SvRV(y_in)) );
    mpz_t *scalar = INT2PTR( mpz_t *, SvIV(SvRV(scalar_in)) );
    mpz_t *mod    = INT2PTR( mpz_t *, SvIV(SvRV(mod_in)) );
    mpz_t *a      = INT2PTR( mpz_t *, SvIV(SvRV(a_in)) );
    mpz_t *neg_a  = INT2PTR( mpz_t *, SvIV(SvRV(a_neg)) );
    
    mpz_t old_x, old_y;
    
    mpz_init_set( old_x, *x );
    mpz_init_set( old_y, *y );
    
    if( mpz_sgn(*neg_a) ) mpz_neg( *a, *a );
    
    /* MODIFIES (x,y) IN PLACE */
    multiply_Fp_pt( *x, *y, old_x, old_y, *scalar, *mod, *a );
}


MODULE  = Crypt::ECDSA		PACKAGE = Crypt::ECDSA 
PROTOTYPES: ENABLE

BOOT: 
{
    MY_CXT_INIT;
    gmp_randinit_default(MY_CXT.state);
    MY_CXT.reserved = 0;
}


SV *
multiply_F2m ( x_in, y_in, mod_in )
	SV *	x_in
	SV *	y_in
	SV *	mod_in


SV *
invert_F2m ( x_in, mod_in )
	SV *	x_in
	SV *	mod_in


int 
gmp_is_probably_prime ( num, reps_to_run )
	SV *	num
	SV *	reps_to_run

SV *
gmp_random_bits ( bits )
	SV *	bits

void double_Fp_point( x_in, y_in, mod_in, a_in, a_neg )
	SV *	x_in
	SV *	y_in
	SV *	mod_in
	SV *	a_in
	SV *	a_neg
    


void add_Fp_point( x1_in, y1_in, x2_in, y2_in, mod_in, a_in, a_neg )
	SV *	x1_in
	SV *	y1_in
	SV *	x2_in
	SV *	y2_in
	SV *	mod_in
	SV *	a_in
	SV *	a_neg

void 
multiply_Fp_point( x_in, y_in, scalar_in, mod_in, a_in, a_neg )
	SV *	x_in
	SV *	y_in
	SV *	scalar_in
	SV *	mod_in
	SV *	a_in
	SV *	a_neg
