/*
 *  ccm_alt.c
 *
 *  Copyright (C) 2017, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

#include "mbedtls/ccm.h"
#if defined(MBEDTLS_CCM_ALT)
#include <string.h>
#include "mbedtls/platform.h"

/* Implementation that should never be optimized out by the compiler */
static void mbedtls_zeroize( void *v, size_t n ) {
    volatile unsigned char *p = (unsigned char*)v; while( n-- ) *p++ = 0;
}

void mbedtls_ccm_init( mbedtls_ccm_context *ctx )
{
    memset( ctx, 0, sizeof( mbedtls_ccm_context ) );
}

int mbedtls_ccm_setkey( mbedtls_ccm_context *ctx,
                        mbedtls_cipher_id_t cipher,
                        const unsigned char *key,
                        unsigned int keybits )
{
    if ( ctx == NULL )
        return MBEDTLS_ERR_CCM_BAD_INPUT;

    if ( cipher != MBEDTLS_CIPHER_ID_AES ||
         keybits != 128 )
    {
        ctx->is_default = 1;
        return mbedtls_ccm_setkey_default(  &ctx->u_ctx.ccm_default_ctx, cipher, key, keybits );
    }

    ctx->is_default = 0;

    memcpy( ctx->u_ctx.ccm_alt_ctx.cipher_key , key, keybits/8 );
    ctx->u_ctx.ccm_alt_ctx.keySize_ID = CRYS_AES_Key128BitSize;

    return 0;

}

void mbedtls_ccm_free( mbedtls_ccm_context *ctx )
{
    mbedtls_zeroize( ctx, sizeof( mbedtls_ccm_context ) );
}


int mbedtls_ccm_encrypt_and_tag( mbedtls_ccm_context *ctx, size_t length,
                         const unsigned char *iv, size_t iv_len,
                         const unsigned char *add, size_t add_len,
                         const unsigned char *input, unsigned char *output,
                         unsigned char *tag, size_t tag_len )

{
    if(  ctx->is_default )
        return( mbedtls_ccm_encrypt_and_tag_default( &ctx->u_ctx.ccm_default_ctx, length, iv, iv_len,
                                                     add, add_len, input, output,
                                                     tag, tag_len ) );

    return CRYS_AESCCM( SASI_AES_ENCRYPT, ctx->u_ctx.ccm_alt_ctx.cipher_key, ctx->u_ctx.ccm_alt_ctx.keySize_ID,
               (uint8_t*)iv, iv_len,  (uint8_t*)add, add_len,  (uint8_t*)input, length, output, tag_len, tag );


}

int mbedtls_ccm_auth_decrypt( mbedtls_ccm_context *ctx, size_t length,
                      const unsigned char *iv, size_t iv_len,
                      const unsigned char *add, size_t add_len,
                      const unsigned char *input, unsigned char *output,
                      const unsigned char *tag, size_t tag_len )

{
    int ret = 0;
    if ( ctx->is_default )
        return( mbedtls_ccm_auth_decrypt_default( &ctx->u_ctx.ccm_default_ctx, length, iv, iv_len,
                                                  add, add_len, input, output,
                                                  tag, tag_len ) );

    ret =  CRYS_AESCCM( SASI_AES_DECRYPT, ctx->u_ctx.ccm_alt_ctx.cipher_key, ctx->u_ctx.ccm_alt_ctx.keySize_ID,
                         (uint8_t*)iv, iv_len,  (uint8_t*)add, add_len,  (uint8_t*)input, length, output, tag_len, (uint8_t*)tag );
    if ( ret != 0 )
        ret = MBEDTLS_ERR_CCM_AUTH_FAILED;

    return ret;

}

#endif
