
#ifndef MBEDTLS_SHA512_H
#define MBEDTLS_SHA512_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stddef.h>
#include <stdint.h>

#if !defined(MBEDTLS_SHA512_ALT)


#ifdef __cplusplus
extern "C" {
#endif


typedef struct
{
    uint64_t total[2];          
    uint64_t state[8];          
    unsigned char buffer[128];  
    int is384;                  
}
mbedtls_sha512_context;


void mbedtls_sha512_init( mbedtls_sha512_context *ctx );


void mbedtls_sha512_free( mbedtls_sha512_context *ctx );


void mbedtls_sha512_clone( mbedtls_sha512_context *dst,
                           const mbedtls_sha512_context *src );


void mbedtls_sha512_starts( mbedtls_sha512_context *ctx, int is384 );


void mbedtls_sha512_update( mbedtls_sha512_context *ctx, const unsigned char *input,
                    size_t ilen );


void mbedtls_sha512_finish( mbedtls_sha512_context *ctx, unsigned char output[64] );

#ifdef __cplusplus
}
#endif

#else  
#include "sha512_alt.h"
#endif 

#ifdef __cplusplus
extern "C" {
#endif


void mbedtls_sha512( const unsigned char *input, size_t ilen,
             unsigned char output[64], int is384 );


int mbedtls_sha512_self_test( int verbose );


void mbedtls_sha512_process( mbedtls_sha512_context *ctx, const unsigned char data[128] );

#ifdef __cplusplus
}
#endif

#endif 