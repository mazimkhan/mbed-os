#line 2 "suites/main_test.function"
/*
 * *** THIS FILE HAS BEEN MACHINE GENERATED ***
 *
 * This file has been machine generated using the script:
 * generate_test_code.py
 *
 * Test file      : ./TESTS/mbedtls/test_suite_aes.cfb/test_suite_aes.cfb.c
 *
 * The following files were used to create this file.
 *
 *      Main code file      : suites/main_test.function
 *      Platform code file  : suites/target_test.function
 *      Helper file         : suites/helpers.function
 *      Test suite file     : suites/test_suite_aes.function
 *      Test suite data     : suites/test_suite_aes.cfb.data
 *
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include <mbedtls/config.h>
#else
#include MBEDTLS_CONFIG_FILE
#endif


/*----------------------------------------------------------------------------*/
/* Common helper code */

#line 2 "suites/helpers.function"
/*----------------------------------------------------------------------------*/
/* Headers */

#include <stdlib.h>

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_fprintf    fprintf
#define mbedtls_snprintf   snprintf
#define mbedtls_calloc     calloc
#define mbedtls_free       free
#define mbedtls_exit       exit
#define mbedtls_time       time
#define mbedtls_time_t     time_t
#define MBEDTLS_EXIT_SUCCESS EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE EXIT_FAILURE
#endif

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
#include "mbedtls/memory_buffer_alloc.h"
#endif

#ifdef _MSC_VER
#include <basetsd.h>
typedef UINT32 uint32_t;
#define strncasecmp _strnicmp
#define strcasecmp _stricmp
#else
#include <stdint.h>
#endif

#include <string.h>

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
#include <unistd.h>
#endif

/* Type for Hex parameters */
typedef struct HexParam_tag
{
    uint8_t *   x;
    uint32_t    len;
} HexParam_t;

/*----------------------------------------------------------------------------*/
/* Constants */

#define DEPENDENCY_SUPPORTED            0
#define KEY_VALUE_MAPPING_FOUND         0
#define DISPATCH_TEST_SUCCESS           0

#define KEY_VALUE_MAPPING_NOT_FOUND     -1
#define DEPENDENCY_NOT_SUPPORTED        -2
#define DISPATCH_TEST_FN_NOT_FOUND      -3
#define DISPATCH_INVALID_TEST_DATA      -4
#define DISPATCH_UNSUPPORTED_SUITE      -5


/*----------------------------------------------------------------------------*/
/* Macros */

#define TEST_ASSERT( TEST )                         \
    do {                                            \
        if( ! (TEST) )                              \
        {                                           \
            test_fail( #TEST, __LINE__, __FILE__ ); \
            goto exit;                              \
        }                                           \
    } while( 0 )

#define assert(a) if( !( a ) )                                      \
{                                                                   \
    mbedtls_fprintf( stderr, "Assertion Failed at %s:%d - %s\n",   \
                             __FILE__, __LINE__, #a );              \
    mbedtls_exit( 1 );                                             \
}

/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n,b,i)                            \
{                                                       \
    (n) = ( (uint32_t) (b)[(i)    ] << 24 )             \
        | ( (uint32_t) (b)[(i) + 1] << 16 )             \
        | ( (uint32_t) (b)[(i) + 2] <<  8 )             \
        | ( (uint32_t) (b)[(i) + 3]       );            \
}
#endif

#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n,b,i)                            \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif


/*----------------------------------------------------------------------------*/
/* Global variables */


static struct
{
    int failed;
    const char *test;
    const char *filename;
    int line_no;
}
test_info;


/*----------------------------------------------------------------------------*/
/* Helper flags for complex dependencies */

/* Indicates whether we expect mbedtls_entropy_init
 * to initialize some strong entropy source. */
#if defined(MBEDTLS_TEST_NULL_ENTROPY) ||             \
    ( !defined(MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES) && \
      ( !defined(MBEDTLS_NO_PLATFORM_ENTROPY)  ||     \
         defined(MBEDTLS_HAVEGE_C)             ||     \
         defined(MBEDTLS_ENTROPY_HARDWARE_ALT) ||     \
         defined(ENTROPY_NV_SEED) ) )
#define ENTROPY_HAVE_STRONG
#endif


/*----------------------------------------------------------------------------*/
/* Helper Functions */

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
static int redirect_output( FILE** out_stream, const char* path )
{
    int stdout_fd = dup( fileno( *out_stream ) );

    if( stdout_fd == -1 )
    {
        return -1;
    }

    fflush( *out_stream );
    fclose( *out_stream );
    *out_stream = fopen( path, "w" );

    if( *out_stream == NULL )
    {
        return -1;
    }

    return stdout_fd;
}

static int restore_output( FILE** out_stream, int old_fd )
{
    fflush( *out_stream );
    fclose( *out_stream );

    *out_stream = fdopen( old_fd, "w" );
    if( *out_stream == NULL )
    {
        return -1;
    }

    return 0;
}

static void close_output( FILE* out_stream )
{
    fclose( out_stream );
}
#endif /* __unix__ || __APPLE__ __MACH__ */

static int unhexify( unsigned char *obuf, const char *ibuf )
{
    unsigned char c, c2;
    int len = strlen( ibuf ) / 2;
    assert( strlen( ibuf ) % 2 == 0 ); /* must be even number of bytes */

    while( *ibuf != 0 )
    {
        c = *ibuf++;
        if( c >= '0' && c <= '9' )
            c -= '0';
        else if( c >= 'a' && c <= 'f' )
            c -= 'a' - 10;
        else if( c >= 'A' && c <= 'F' )
            c -= 'A' - 10;
        else
            assert( 0 );

        c2 = *ibuf++;
        if( c2 >= '0' && c2 <= '9' )
            c2 -= '0';
        else if( c2 >= 'a' && c2 <= 'f' )
            c2 -= 'a' - 10;
        else if( c2 >= 'A' && c2 <= 'F' )
            c2 -= 'A' - 10;
        else
            assert( 0 );

        *obuf++ = ( c << 4 ) | c2;
    }

    return len;
}

static void hexify( unsigned char *obuf, const unsigned char *ibuf, int len )
{
    unsigned char l, h;

    while( len != 0 )
    {
        h = *ibuf / 16;
        l = *ibuf % 16;

        if( h < 10 )
            *obuf++ = '0' + h;
        else
            *obuf++ = 'a' + h - 10;

        if( l < 10 )
            *obuf++ = '0' + l;
        else
            *obuf++ = 'a' + l - 10;

        ++ibuf;
        len--;
    }
}

/**
 * Allocate and zeroize a buffer.
 *
 * If the size if zero, a pointer to a zeroized 1-byte buffer is returned.
 *
 * For convenience, dies if allocation fails.
 */
static unsigned char *zero_alloc( size_t len )
{
    void *p;
    size_t actual_len = ( len != 0 ) ? len : 1;

    p = mbedtls_calloc( 1, actual_len );
    assert( p != NULL );

    memset( p, 0x00, actual_len );

    return( p );
}

/**
 * Allocate and fill a buffer from hex data.
 *
 * The buffer is sized exactly as needed. This allows to detect buffer
 * overruns (including overreads) when running the test suite under valgrind.
 *
 * If the size if zero, a pointer to a zeroized 1-byte buffer is returned.
 *
 * For convenience, dies if allocation fails.
 */
static unsigned char *unhexify_alloc( const char *ibuf, size_t *olen )
{
    unsigned char *obuf;

    *olen = strlen( ibuf ) / 2;

    if( *olen == 0 )
        return( zero_alloc( *olen ) );

    obuf = mbedtls_calloc( 1, *olen );
    assert( obuf != NULL );

    (void) unhexify( obuf, ibuf );

    return( obuf );
}

/**
 * This function just returns data from rand().
 * Although predictable and often similar on multiple
 * runs, this does not result in identical random on
 * each run. So do not use this if the results of a
 * test depend on the random data that is generated.
 *
 * rng_state shall be NULL.
 */
static int rnd_std_rand( void *rng_state, unsigned char *output, size_t len )
{
#if !defined(__OpenBSD__)
    size_t i;

    if( rng_state != NULL )
        rng_state  = NULL;

    for( i = 0; i < len; ++i )
        output[i] = rand();
#else
    if( rng_state != NULL )
        rng_state = NULL;

    arc4random_buf( output, len );
#endif /* !OpenBSD */

    return( 0 );
}

/**
 * This function only returns zeros
 *
 * rng_state shall be NULL.
 */
static int rnd_zero_rand( void *rng_state, unsigned char *output, size_t len )
{
    if( rng_state != NULL )
        rng_state  = NULL;

    memset( output, 0, len );

    return( 0 );
}

typedef struct
{
    unsigned char *buf;
    size_t length;
} rnd_buf_info;

/**
 * This function returns random based on a buffer it receives.
 *
 * rng_state shall be a pointer to a rnd_buf_info structure.
 *
 * The number of bytes released from the buffer on each call to
 * the random function is specified by per_call. (Can be between
 * 1 and 4)
 *
 * After the buffer is empty it will return rand();
 */
static int rnd_buffer_rand( void *rng_state, unsigned char *output, size_t len )
{
    rnd_buf_info *info = (rnd_buf_info *) rng_state;
    size_t use_len;

    if( rng_state == NULL )
        return( rnd_std_rand( NULL, output, len ) );

    use_len = len;
    if( len > info->length )
        use_len = info->length;

    if( use_len )
    {
        memcpy( output, info->buf, use_len );
        info->buf += use_len;
        info->length -= use_len;
    }

    if( len - use_len > 0 )
        return( rnd_std_rand( NULL, output + use_len, len - use_len ) );

    return( 0 );
}

/**
 * Info structure for the pseudo random function
 *
 * Key should be set at the start to a test-unique value.
 * Do not forget endianness!
 * State( v0, v1 ) should be set to zero.
 */
typedef struct
{
    uint32_t key[16];
    uint32_t v0, v1;
} rnd_pseudo_info;

/**
 * This function returns random based on a pseudo random function.
 * This means the results should be identical on all systems.
 * Pseudo random is based on the XTEA encryption algorithm to
 * generate pseudorandom.
 *
 * rng_state shall be a pointer to a rnd_pseudo_info structure.
 */
static int rnd_pseudo_rand( void *rng_state, unsigned char *output, size_t len )
{
    rnd_pseudo_info *info = (rnd_pseudo_info *) rng_state;
    uint32_t i, *k, sum, delta=0x9E3779B9;
    unsigned char result[4], *out = output;

    if( rng_state == NULL )
        return( rnd_std_rand( NULL, output, len ) );

    k = info->key;

    while( len > 0 )
    {
        size_t use_len = ( len > 4 ) ? 4 : len;
        sum = 0;

        for( i = 0; i < 32; i++ )
        {
            info->v0 += ( ( ( info->v1 << 4 ) ^ ( info->v1 >> 5 ) )
                            + info->v1 ) ^ ( sum + k[sum & 3] );
            sum += delta;
            info->v1 += ( ( ( info->v0 << 4 ) ^ ( info->v0 >> 5 ) )
                            + info->v0 ) ^ ( sum + k[( sum>>11 ) & 3] );
        }

        PUT_UINT32_BE( info->v0, result, 0 );
        memcpy( out, result, use_len );
        len -= use_len;
        out += 4;
    }

    return( 0 );
}

static void test_fail( const char *test, int line_no, const char* filename )
{
    test_info.failed = 1;
    test_info.test = test;
    test_info.line_no = line_no;
    test_info.filename = filename;
}

int hexcmp( uint8_t * a, uint8_t * b, uint32_t a_len, uint32_t b_len)
{
    int ret = 0;
    uint32_t i = 0;

    if ( a_len != b_len )
        return( a_len - b_len );

    for( i = 0; i < a_len; i++ )
    {
        if ( a[i] != b[i] )
        {
            ret = -1;
            break;
        }
    }
    return ret;
}



#line 35 "suites/main_test.function"


/*----------------------------------------------------------------------------*/
/* Test Suite Code */


#define TEST_SUITE_ACTIVE

#if defined(MBEDTLS_AES_C)
#line 1 "suites/test_suite_aes.function"
#include "mbedtls/aes.h"
#line 1 "suites/test_suite_aes.function"
void test_aes_encrypt_ecb( HexParam_t * key_str, HexParam_t * src_str,
                      HexParam_t * hex_dst_string, int setkey_result )
{
    unsigned char output[100];
    mbedtls_aes_context ctx;

    memset(output, 0x00, 100);
    mbedtls_aes_init( &ctx );


    TEST_ASSERT( mbedtls_aes_setkey_enc( &ctx, key_str->x, key_str->len * 8 ) == setkey_result );
    if( setkey_result == 0 )
    {
        TEST_ASSERT( mbedtls_aes_crypt_ecb( &ctx, MBEDTLS_AES_ENCRYPT, src_str->x, output ) == 0 );

        TEST_ASSERT( hexcmp( output, hex_dst_string->x, 16, hex_dst_string->len ) == 0 );
    }

exit:
    mbedtls_aes_free( &ctx );
}

void test_aes_encrypt_ecb_wrapper( void ** params )
{
    
    HexParam_t hex0 = {(uint8_t *) params[0], *( (uint32_t *) params[1] )};
    HexParam_t hex2 = {(uint8_t *) params[2], *( (uint32_t *) params[3] )};
    HexParam_t hex4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};

    test_aes_encrypt_ecb( &hex0, &hex2, &hex4, *( (int *) params[6] ) );
}
#line 1 "suites/test_suite_aes.function"
void test_aes_decrypt_ecb( HexParam_t * key_str, HexParam_t * src_str,
                      HexParam_t * hex_dst_string, int setkey_result )
{
    unsigned char output[100];
    mbedtls_aes_context ctx;

    memset(output, 0x00, 100);
    mbedtls_aes_init( &ctx );


    TEST_ASSERT( mbedtls_aes_setkey_dec( &ctx, key_str->x, key_str->len * 8 ) == setkey_result );
    if( setkey_result == 0 )
    {
        TEST_ASSERT( mbedtls_aes_crypt_ecb( &ctx, MBEDTLS_AES_DECRYPT, src_str->x, output ) == 0 );

        TEST_ASSERT( hexcmp( output, hex_dst_string->x, 16, hex_dst_string->len ) == 0 );
    }

exit:
    mbedtls_aes_free( &ctx );
}

void test_aes_decrypt_ecb_wrapper( void ** params )
{
    
    HexParam_t hex0 = {(uint8_t *) params[0], *( (uint32_t *) params[1] )};
    HexParam_t hex2 = {(uint8_t *) params[2], *( (uint32_t *) params[3] )};
    HexParam_t hex4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};

    test_aes_decrypt_ecb( &hex0, &hex2, &hex4, *( (int *) params[6] ) );
}
#if defined(MBEDTLS_CIPHER_MODE_CBC)
#line 1 "suites/test_suite_aes.function"
void test_aes_encrypt_cbc( HexParam_t * key_str, HexParam_t * iv_str,
                      HexParam_t * src_str, HexParam_t * hex_dst_string,
                      int cbc_result )
{
    unsigned char output[100];
    mbedtls_aes_context ctx;

    memset(output, 0x00, 100);
    mbedtls_aes_init( &ctx );


    mbedtls_aes_setkey_enc( &ctx, key_str->x, key_str->len * 8 );
    TEST_ASSERT( mbedtls_aes_crypt_cbc( &ctx, MBEDTLS_AES_ENCRYPT, src_str->len, iv_str->x, src_str->x, output ) == cbc_result );
    if( cbc_result == 0 )
    {

        TEST_ASSERT( hexcmp( output, hex_dst_string->x, src_str->len, hex_dst_string->len ) == 0 );
    }

exit:
    mbedtls_aes_free( &ctx );
}

void test_aes_encrypt_cbc_wrapper( void ** params )
{
    
    HexParam_t hex0 = {(uint8_t *) params[0], *( (uint32_t *) params[1] )};
    HexParam_t hex2 = {(uint8_t *) params[2], *( (uint32_t *) params[3] )};
    HexParam_t hex4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};
    HexParam_t hex6 = {(uint8_t *) params[6], *( (uint32_t *) params[7] )};

    test_aes_encrypt_cbc( &hex0, &hex2, &hex4, &hex6, *( (int *) params[8] ) );
}
#endif /* MBEDTLS_CIPHER_MODE_CBC */
#if defined(MBEDTLS_CIPHER_MODE_CBC)
#line 1 "suites/test_suite_aes.function"
void test_aes_decrypt_cbc( HexParam_t * key_str, HexParam_t * iv_str,
                      HexParam_t * src_str, HexParam_t * hex_dst_string,
                      int cbc_result )
{
    unsigned char output[100];
    mbedtls_aes_context ctx;

    memset(output, 0x00, 100);
    mbedtls_aes_init( &ctx );


    mbedtls_aes_setkey_dec( &ctx, key_str->x, key_str->len * 8 );
    TEST_ASSERT( mbedtls_aes_crypt_cbc( &ctx, MBEDTLS_AES_DECRYPT, src_str->len, iv_str->x, src_str->x, output ) == cbc_result );
    if( cbc_result == 0)
    {

        TEST_ASSERT( hexcmp( output, hex_dst_string->x, src_str->len, hex_dst_string->len ) == 0 );
    }

exit:
    mbedtls_aes_free( &ctx );
}

void test_aes_decrypt_cbc_wrapper( void ** params )
{
    
    HexParam_t hex0 = {(uint8_t *) params[0], *( (uint32_t *) params[1] )};
    HexParam_t hex2 = {(uint8_t *) params[2], *( (uint32_t *) params[3] )};
    HexParam_t hex4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};
    HexParam_t hex6 = {(uint8_t *) params[6], *( (uint32_t *) params[7] )};

    test_aes_decrypt_cbc( &hex0, &hex2, &hex4, &hex6, *( (int *) params[8] ) );
}
#endif /* MBEDTLS_CIPHER_MODE_CBC */
#if defined(MBEDTLS_CIPHER_MODE_CFB)
#line 1 "suites/test_suite_aes.function"
void test_aes_encrypt_cfb128( HexParam_t * key_str, HexParam_t * iv_str,
                         HexParam_t * src_str, HexParam_t * hex_dst_string )
{
    unsigned char output[100];
    mbedtls_aes_context ctx;
    size_t iv_offset = 0;

    memset(output, 0x00, 100);
    mbedtls_aes_init( &ctx );


    mbedtls_aes_setkey_enc( &ctx, key_str->x, key_str->len * 8 );
    TEST_ASSERT( mbedtls_aes_crypt_cfb128( &ctx, MBEDTLS_AES_ENCRYPT, 16, &iv_offset, iv_str->x, src_str->x, output ) == 0 );

    TEST_ASSERT( hexcmp( output, hex_dst_string->x, 16, hex_dst_string->len ) == 0 );

exit:
    mbedtls_aes_free( &ctx );
}

void test_aes_encrypt_cfb128_wrapper( void ** params )
{
    
    HexParam_t hex0 = {(uint8_t *) params[0], *( (uint32_t *) params[1] )};
    HexParam_t hex2 = {(uint8_t *) params[2], *( (uint32_t *) params[3] )};
    HexParam_t hex4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};
    HexParam_t hex6 = {(uint8_t *) params[6], *( (uint32_t *) params[7] )};

    test_aes_encrypt_cfb128( &hex0, &hex2, &hex4, &hex6 );
}
#endif /* MBEDTLS_CIPHER_MODE_CFB */
#if defined(MBEDTLS_CIPHER_MODE_CFB)
#line 1 "suites/test_suite_aes.function"
void test_aes_decrypt_cfb128( HexParam_t * key_str, HexParam_t * iv_str,
                         HexParam_t * src_str, HexParam_t * hex_dst_string )
{
    unsigned char output[100];
    mbedtls_aes_context ctx;
    size_t iv_offset = 0;

    memset(output, 0x00, 100);
    mbedtls_aes_init( &ctx );


    mbedtls_aes_setkey_enc( &ctx, key_str->x, key_str->len * 8 );
    TEST_ASSERT( mbedtls_aes_crypt_cfb128( &ctx, MBEDTLS_AES_DECRYPT, 16, &iv_offset, iv_str->x, src_str->x, output ) == 0 );

    TEST_ASSERT( hexcmp( output, hex_dst_string->x, 16, hex_dst_string->len ) == 0 );

exit:
    mbedtls_aes_free( &ctx );
}

void test_aes_decrypt_cfb128_wrapper( void ** params )
{
    
    HexParam_t hex0 = {(uint8_t *) params[0], *( (uint32_t *) params[1] )};
    HexParam_t hex2 = {(uint8_t *) params[2], *( (uint32_t *) params[3] )};
    HexParam_t hex4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};
    HexParam_t hex6 = {(uint8_t *) params[6], *( (uint32_t *) params[7] )};

    test_aes_decrypt_cfb128( &hex0, &hex2, &hex4, &hex6 );
}
#endif /* MBEDTLS_CIPHER_MODE_CFB */
#if defined(MBEDTLS_CIPHER_MODE_CFB)
#line 1 "suites/test_suite_aes.function"
void test_aes_encrypt_cfb8( HexParam_t * key_str, HexParam_t * iv_str,
                       HexParam_t * src_str, HexParam_t * hex_dst_string )
{
    unsigned char output[100];
    mbedtls_aes_context ctx;

    memset(output, 0x00, 100);
    mbedtls_aes_init( &ctx );


    mbedtls_aes_setkey_enc( &ctx, key_str->x, key_str->len * 8 );
    TEST_ASSERT( mbedtls_aes_crypt_cfb8( &ctx, MBEDTLS_AES_ENCRYPT, src_str->len, iv_str->x, src_str->x, output ) == 0 );

    TEST_ASSERT( hexcmp( output, hex_dst_string->x, src_str->len, hex_dst_string->len ) == 0 );

exit:
    mbedtls_aes_free( &ctx );
}

void test_aes_encrypt_cfb8_wrapper( void ** params )
{
    
    HexParam_t hex0 = {(uint8_t *) params[0], *( (uint32_t *) params[1] )};
    HexParam_t hex2 = {(uint8_t *) params[2], *( (uint32_t *) params[3] )};
    HexParam_t hex4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};
    HexParam_t hex6 = {(uint8_t *) params[6], *( (uint32_t *) params[7] )};

    test_aes_encrypt_cfb8( &hex0, &hex2, &hex4, &hex6 );
}
#endif /* MBEDTLS_CIPHER_MODE_CFB */
#if defined(MBEDTLS_CIPHER_MODE_CFB)
#line 1 "suites/test_suite_aes.function"
void test_aes_decrypt_cfb8( HexParam_t * key_str, HexParam_t * iv_str,
                       HexParam_t * src_str, HexParam_t * hex_dst_string )
{
    unsigned char output[100];
    mbedtls_aes_context ctx;

    memset(output, 0x00, 100);
    mbedtls_aes_init( &ctx );


    mbedtls_aes_setkey_enc( &ctx, key_str->x, key_str->len * 8 );
    TEST_ASSERT( mbedtls_aes_crypt_cfb8( &ctx, MBEDTLS_AES_DECRYPT, src_str->len, iv_str->x, src_str->x, output ) == 0 );

    TEST_ASSERT( hexcmp( output, hex_dst_string->x, src_str->len, hex_dst_string->len ) == 0 );

exit:
    mbedtls_aes_free( &ctx );
}

void test_aes_decrypt_cfb8_wrapper( void ** params )
{
    
    HexParam_t hex0 = {(uint8_t *) params[0], *( (uint32_t *) params[1] )};
    HexParam_t hex2 = {(uint8_t *) params[2], *( (uint32_t *) params[3] )};
    HexParam_t hex4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};
    HexParam_t hex6 = {(uint8_t *) params[6], *( (uint32_t *) params[7] )};

    test_aes_decrypt_cfb8( &hex0, &hex2, &hex4, &hex6 );
}
#endif /* MBEDTLS_CIPHER_MODE_CFB */
#if defined(MBEDTLS_SELF_TEST)
#line 1 "suites/test_suite_aes.function"
void test_aes_selftest(  )
{
    TEST_ASSERT( mbedtls_aes_self_test( 1 ) == 0 );
exit:
    ;;
}

void test_aes_selftest_wrapper( void ** params )
{
    (void)params;

    test_aes_selftest(  );
}
#endif /* MBEDTLS_SELF_TEST */
#endif /* MBEDTLS_AES_C */


#line 46 "suites/main_test.function"


/*----------------------------------------------------------------------------*/
/* Test dispatch code */


/**
 * \brief       Evaluates an expression/macro into its literal integer value.
 *              For optimizing space for embedded targets each expression/macro
 *              is identified by a unique identifier instead of string literals.
 *              Identifiers and evaluation code is generated by script:
 *              generate_test_code.py
 *
 * \param exp_id    Expression identifier.
 * \param out_value Pointer to int to hold the integer.
 *
 * \return       0 if exp_id is found. 1 otherwise.
 */
int get_expression( int32_t exp_id, int32_t * out_value )
{
    int ret = KEY_VALUE_MAPPING_FOUND;

    (void) exp_id;
    (void) out_value;

    switch( exp_id )
    {

#if defined(MBEDTLS_AES_C)

#endif

#line 75 "suites/main_test.function"
        default:
           {
                ret = KEY_VALUE_MAPPING_NOT_FOUND;
           }
           break;
    }
    return( ret );
}


/**
 * \brief       Checks if the dependency i.e. the compile flag is set.
 *              For optimizing space for embedded targets each dependency
 *              is identified by a unique identifier instead of string literals.
 *              Identifiers and check code is generated by script:
 *              generate_test_code.py
 *
 * \param exp_id    Dependency identifier.
 *
 * \return       DEPENDENCY_SUPPORTED if set else DEPENDENCY_NOT_SUPPORTED
 */
int dep_check( int dep_id )
{
    int ret = DEPENDENCY_NOT_SUPPORTED;

    (void) dep_id;

    switch( dep_id )
    {

#if defined(MBEDTLS_AES_C)

        case 0:
            {
#if defined(MBEDTLS_CIPHER_MODE_CFB)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
#endif

#line 106 "suites/main_test.function"
        default:
            break;
    }
    return( ret );
}


/**
 * \brief       Function pointer type for test function wrappers.
 *
 *
 * \param void **   Pointer to void pointers. Represents an array of test
 *                  function parameters.
 *
 * \return       void
 */
typedef void (*TestWrapper_t)( void ** );


/**
 * \brief       Table of test function wrappers. Used by dispatch_test().
 *              This table is populated by script:
 *              generate_test_code.py
 *
 */
TestWrapper_t test_funcs[] =
{
/* Function Id: 0 */

#if defined(MBEDTLS_AES_C)
    test_aes_encrypt_ecb_wrapper,
#else
    NULL,
#endif
/* Function Id: 1 */

#if defined(MBEDTLS_AES_C)
    test_aes_decrypt_ecb_wrapper,
#else
    NULL,
#endif
/* Function Id: 2 */

#if defined(MBEDTLS_AES_C) && defined(MBEDTLS_CIPHER_MODE_CBC)
    test_aes_encrypt_cbc_wrapper,
#else
    NULL,
#endif
/* Function Id: 3 */

#if defined(MBEDTLS_AES_C) && defined(MBEDTLS_CIPHER_MODE_CBC)
    test_aes_decrypt_cbc_wrapper,
#else
    NULL,
#endif
/* Function Id: 4 */

#if defined(MBEDTLS_AES_C) && defined(MBEDTLS_CIPHER_MODE_CFB)
    test_aes_encrypt_cfb128_wrapper,
#else
    NULL,
#endif
/* Function Id: 5 */

#if defined(MBEDTLS_AES_C) && defined(MBEDTLS_CIPHER_MODE_CFB)
    test_aes_decrypt_cfb128_wrapper,
#else
    NULL,
#endif
/* Function Id: 6 */

#if defined(MBEDTLS_AES_C) && defined(MBEDTLS_CIPHER_MODE_CFB)
    test_aes_encrypt_cfb8_wrapper,
#else
    NULL,
#endif
/* Function Id: 7 */

#if defined(MBEDTLS_AES_C) && defined(MBEDTLS_CIPHER_MODE_CFB)
    test_aes_decrypt_cfb8_wrapper,
#else
    NULL,
#endif
/* Function Id: 8 */

#if defined(MBEDTLS_AES_C) && defined(MBEDTLS_SELF_TEST)
    test_aes_selftest_wrapper,
#else
    NULL,
#endif
 
#line 135 "suites/main_test.function"
};


/**
 * \brief       Dispatches test functions based on function index.
 *
 * \param exp_id    Test function index.
 *
 * \return       DISPATCH_TEST_SUCCESS if found
 *               DISPATCH_TEST_FN_NOT_FOUND if not found
 *               DISPATCH_UNSUPPORTED_SUITE if not compile time enabled.
 */
int dispatch_test( int func_idx, void ** params )
{
    int ret = DISPATCH_TEST_SUCCESS;
    TestWrapper_t fp = NULL;

    if ( func_idx < (int)( sizeof(test_funcs)/sizeof( TestWrapper_t ) ) )
    {
        fp = test_funcs[func_idx];
        if ( fp )
            fp( params );
        else
            ret = ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    {
        ret = ( DISPATCH_TEST_FN_NOT_FOUND );
    }

    return( ret );
}


/**
 * \brief       Checks if test function is supported
 *
 * \param exp_id    Test function index.
 *
 * \return       DISPATCH_TEST_SUCCESS if found
 *               DISPATCH_TEST_FN_NOT_FOUND if not found
 *               DISPATCH_UNSUPPORTED_SUITE if not compile time enabled.
 */
int check_test( int func_idx )
{
    int ret = DISPATCH_TEST_SUCCESS;
    TestWrapper_t fp = NULL;

    if ( func_idx < (int)( sizeof(test_funcs)/sizeof( TestWrapper_t ) ) )
    {
        fp = test_funcs[func_idx];
        if ( fp == NULL )
            ret = ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    {
        ret = ( DISPATCH_TEST_FN_NOT_FOUND );
    }

    return( ret );
}


#line 2 "suites/target_test.function"

#include "greentea-client/test_env.h"

/**
 * \brief       Increments pointer and asserts that it does not overflow.
 *
 * \param p     Pointer to byte array
 * \param start Pointer to start of byte array
 * \param len   Length of byte array
 * \param step  Increment size
 *
 */
#define INCR_ASSERT(p, start, len, step) do                     \
{                                                               \
    assert( ( p ) >= ( start ) );                               \
    assert( sizeof( *( p ) ) == sizeof( *( start ) ) );         \
    /* <= is checked to support use inside a loop where         \
       pointer is incremented after reading data.       */      \
    assert( (uint32_t)( ( ( p ) - ( start ) ) + ( step ) ) <= ( len ) );\
    ( p ) += ( step );                                          \
}                                                               \
while( 0 )


/**
 * \brief       4 byte align unsigned char pointer
 *
 * \param p     Pointer to byte array
 * \param start Pointer to start of byte array
 * \param len   Length of byte array
 *
 */
#define ALIGN_32BIT(p, start, len) do           \
{                                               \
    uint32_t align = ( - (uintptr_t)( p ) ) % 4;\
    INCR_ASSERT( ( p ), ( start ), ( len ), align);\
}                                               \
while( 0 )


/**
 * \brief       Verify dependencies. Dependency identifiers are
 *              encoded in the buffer as 8 bit unsigned integers.
 *
 * \param count     Number of dependencies.
 * \param dep_p     Pointer to buffer.
 *
 * \return          DEPENDENCY_SUPPORTED if success else DEPENDENCY_NOT_SUPPORTED.
 */
int verify_dependencies( uint8_t count, uint8_t * dep_p )
{
    uint8_t i;
    for ( i = 0; i < count; i++ )
    {
        if ( dep_check( (int)(dep_p[i]) ) != DEPENDENCY_SUPPORTED )
            return( DEPENDENCY_NOT_SUPPORTED );
    }
    return( DEPENDENCY_SUPPORTED );
}


/**
 * \brief       Receives unsigned integer on serial interface.
 *              Integers are encoded in network order.
 *
 * \param none
 *
 * \return      unsigned int
 */
uint32_t receive_uint32()
{
    uint32_t value;
    value =  (uint8_t)greentea_getc() << 24;
    value |= (uint8_t)greentea_getc() << 16;
    value |= (uint8_t)greentea_getc() << 8;
    value |= (uint8_t)greentea_getc();
    return( (uint32_t)value );
}

/**
 * \brief       Parses out an unsigned 32 int value from the byte array.
 *              Integers are encoded in network order.
 *
 * \param p     Pointer to byte array
 *
 * \return      unsigned int
 */
uint32_t parse_uint32( uint8_t * p )
{
    uint32_t value;
    value =  *p++ << 24;
    value |= *p++ << 16;
    value |= *p++ << 8;
    value |= *p;
    return( value );
}


/**
 * \brief       Receives test data on serial as greentea key,value pair:
 *              {{<length>;<byte array>}}
 *
 * \param data_len  Out pointer to hold received data length.
 *
 * \return      Byte array.
 */
uint8_t * receive_data( uint32_t * data_len )
{
    uint32_t i = 0, errors = 0;
    char c;
    uint8_t * data = NULL;

    /* Read opening braces */
    i = 0;
    while ( i < 2 )
    {
        c = greentea_getc();
        /* Ignore any prevous CR LF characters */
        if ( c == '\n' || c == '\r' )
            continue;
        i++;
        if ( c != '{' )
            return( NULL );
    }

    /* Read data length */
    *data_len = receive_uint32();
    data = (uint8_t *)malloc( *data_len );
    assert( data != NULL );

    greentea_getc(); // read ';' received after key i.e. *data_len

    for( i = 0; i < *data_len; i++ )
        data[i] = greentea_getc();

    /* Read closing braces */
    for( i = 0; i < 2; i++ )
    {
        c = greentea_getc();
        if ( c != '}' )
        {
            errors++;
            break;
        }
    }

    if ( errors )
    {
        free( data );
        data = NULL;
        *data_len = 0;
    }

    return( data );
}

/**
 * \brief       Parse the received byte array and count the number of arguments
 *              to the test function passed as type hex.
 *
 * \param count     Parameter count
 * \param data      Received Byte array
 * \param data_len  Byte array length
 *
 * \return      count of hex params
 */
uint32_t find_hex_count( uint8_t count, uint8_t * data, uint32_t data_len )
{
    uint32_t i = 0, sz = 0;
    char c;
    uint8_t * p = NULL;
    uint32_t hex_count = 0;

    p = data;

    for( i = 0; i < count; i++ )
    {
        c = (char)*p;
        INCR_ASSERT( p, data, data_len, 1 );

        /* Align p to 4 bytes for int, expression, string len or hex length */
        ALIGN_32BIT( p, data, data_len );

        /* Network to host conversion */
        sz = (int32_t)parse_uint32( p );

        INCR_ASSERT( p, data, data_len, sizeof( int32_t ) );

        if ( c == 'H' || c == 'S' )
        {
            INCR_ASSERT( p, data, data_len, sz );
            hex_count += ( c == 'H' )?1:0;
        }
    }

    return( hex_count );
}

/**
 * \brief       Parses received byte array for test parameters.
 *
 * \param count     Parameter count
 * \param data      Received Byte array
 * \param data_len  Byte array length
 * \param error     Parsing error out variable.
 *
 * \return      Array of parsed parameters allocated on heap.
 *              Note: Caller has the responsibility to delete
 *                    the memory after use.
 */
void ** parse_parameters( uint8_t count, uint8_t * data, uint32_t data_len,
                            int * error )
{
    uint32_t i = 0, hex_count = 0;
    char c;
    void ** params = NULL;
    void ** cur = NULL;
    uint8_t * p = NULL;

    hex_count = find_hex_count(count, data, data_len);

    params = (void **)malloc( sizeof( void *) * ( count + hex_count ) );
    assert( params != NULL );
    cur = params;

    p = data;

    /* Parameters */
    for( i = 0; i < count; i++ )
    {
        c = (char)*p;
        INCR_ASSERT( p, data, data_len, 1 );

        /* Align p to 4 bytes for int, expression, string len or hex length */
        ALIGN_32BIT( p, data, data_len );

        /* Network to host conversion */
        *( (int32_t *)p ) = (int32_t)parse_uint32( p );

        switch( c )
        {
            case 'E':
                {
                    if ( get_expression( *( (int32_t *)p ), (int32_t *)p ) )
                    {
                        *error = KEY_VALUE_MAPPING_NOT_FOUND;
                        goto exit;
                    }
                } /* Intentional fall through */
            case 'I':
                {
                    *cur++ = (void *)p;
                    INCR_ASSERT( p, data, data_len, sizeof( int32_t ) );
                }
                break;
            case 'H': /* Intentional fall through */
            case 'S':
                {
                    uint32_t * sz = (uint32_t *)p;
                    INCR_ASSERT( p, data, data_len, sizeof( int32_t ) );
                    *cur++ = (void *)p;
                    if ( c == 'H' )
                        *cur++ = (void *)sz;
                    INCR_ASSERT( p, data, data_len, ( *sz ) );
                }
                break;
            default:
                    {
                        *error = DISPATCH_INVALID_TEST_DATA;
                        goto exit;
                    }
                break;
        }
    }

exit:
    if ( *error )
    {
        free( params );
        params = NULL;
    }

    return( params );
}

/**
 * \brief       Sends greentea key and int value pair to host.
 *
 * \param key   key string
 * \param value integer value
 *
 * \return      void
 */
void send_key_integer( char * key, int value )
{
    char str[50];
    snprintf( str, sizeof( str ), "%d", value );
    greentea_send_kv( key, str );
}

/**
 * \brief       Sends test setup failure to the host.
 *
 * \param failure   Test set failure
 *
 * \return      void
 */
void send_failure( int failure )
{
    send_key_integer( "F", failure );
}

/**
 * \brief       Sends test status to the host.
 *
 * \param status    Test status (PASS=0/FAIL=!0)
 *
 * \return      void
 */
void send_status( int status )
{
    send_key_integer( "R", status );
}


/**
 * \brief       Embedded implementation of execute_tests().
 *              Ignores command line and received test data
 *              on serial.
 *
 * \param argc  not used
 * \param argv  not used
 *
 * \return      Program exit status.
 */
int execute_tests( int args, const char ** argv )
{
    int ret = 0;
    uint32_t data_len = 0;
    uint8_t count = 0, function_id;
    void ** params = NULL;
    uint8_t * data = NULL, * p = NULL;

    GREENTEA_SETUP( 180, "mbedtls_test" );
    greentea_send_kv( "GO", " " );

    while ( 1 )
    {
        ret = 0;
        test_info.failed = 0;
        data_len = 0;

        data = receive_data( &data_len );
        if ( data == NULL )
            continue;
        p = data;

        do
        {
            /* Read dependency count */
            count = *p;
            assert( count < data_len );
            INCR_ASSERT( p, data, data_len, sizeof( uint8_t ) );
            ret = verify_dependencies( count, p );
            if ( ret != DEPENDENCY_SUPPORTED )
                break;

            if ( count )
                INCR_ASSERT( p, data, data_len, count );

            /* Read function id */
            function_id = *p;
            INCR_ASSERT( p, data, data_len, sizeof( uint8_t ) );
            if ( ( ret = check_test( function_id ) ) != DISPATCH_TEST_SUCCESS )
                break;

            /* Read number of parameters */
            count = *p;
            INCR_ASSERT( p, data, data_len, sizeof( uint8_t ) );

            /* Parse parameters if present */
            if ( count )
            {
                params = parse_parameters( count, p, data_len - ( p - data ), &ret );
                if ( ret )
                    break;
            }

            ret = dispatch_test( function_id, params );
        }
        while ( 0 );

        if ( data )
        {
            free(data);
            data = NULL;
        }

        if ( params )
        {
            free( params );
            params = NULL;
        }

        if ( ret )
            send_failure( ret );
        else
            send_status( test_info.failed );
    }
    return( 0 );
}



#line 201 "suites/main_test.function"

/*----------------------------------------------------------------------------*/
/* Main Test code */


/**
 * \brief       Program main. Invokes platform specific execute_tests().
 *
 * \param argc      Command line arguments count.
 * \param argv      Array of command line arguments.
 *
 * \return       Exit code.
 */
int main( int argc, const char *argv[] )
{
    return execute_tests( argc, argv );
}

