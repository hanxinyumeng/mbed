/*
 * Copyright (c) 2016, Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * o Redistributions of source code must retain the above copyright notice, this list
 *   of conditions and the following disclaimer.
 *
 * o Redistributions in binary form must reproduce the above copyright notice, this
 *   list of conditions and the following disclaimer in the documentation and/or
 *   other materials provided with the distribution.
 *
 * o Neither the name of Freescale Semiconductor, Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived from this
 *   software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "mbedtls/aes.h"
#include "fsl_common.h"

#if defined(MBEDTLS_AES_ALT)

/* Implementation that should never be optimized out by the compiler */
static void mbedtls_zeroize( void *v, size_t n ) {
    volatile unsigned char *p = (unsigned char*)v; while( n-- ) *p++ = 0;
}

void mbedtls_aes_init( mbedtls_aes_context *ctx )
{
    memset( ctx, 0, sizeof( mbedtls_aes_context ) );
#if defined(MBEDTLS_FREESCALE_LTC_AES)
    LTC_Init(LTC_INSTANCE);
#endif
}

void mbedtls_aes_free( mbedtls_aes_context *ctx )
{
    if( ctx == NULL )
        return;

    mbedtls_zeroize( ctx, sizeof( mbedtls_aes_context ) );
    LTC_Deinit(LTC_INSTANCE);
}

/*
 * AES key schedule (encryption)
 */
int mbedtls_aes_setkey_enc(mbedtls_aes_context *ctx, const unsigned char *key, unsigned int keybits)
{
    uint32_t *RK;

#if defined(MBEDTLS_FREESCALE_LTC_AES) || defined(MBEDTLS_FREESCALE_CAU3_AES)
    const unsigned char *key_tmp = key;
    ctx->rk = RK = ctx->buf;
    memcpy(RK, key_tmp, keybits / 8);

    switch (keybits)
    { /* Set keysize in bytes.*/
        case 128:
            ctx->nr = 16;
            break;
        case 192:
            ctx->nr = 24;
            break;
        case 256:
            ctx->nr = 32;
            break;
        default:
            return (MBEDTLS_ERR_AES_INVALID_KEY_LENGTH);
    }
#elif defined(MBEDTLS_FREESCALE_MMCAU_AES)
    ctx->rk = RK = ctx->buf;

    switch (keybits)
    {
        case 128:
            ctx->nr = 10;
            break;
        case 192:
            ctx->nr = 12;
            break;
        case 256:
            ctx->nr = 14;
            break;
        default:
            return (MBEDTLS_ERR_AES_INVALID_KEY_LENGTH);
    }

    MMCAU_AES_SetKey(key, keybits / 8, (uint8_t *)RK);
#endif
    return (0);
}

/*
 * AES key schedule (decryption)
 */
int mbedtls_aes_setkey_dec(mbedtls_aes_context *ctx, const unsigned char *key, unsigned int keybits)
{
    uint32_t *RK;

    ctx->rk = RK = ctx->buf;

#if defined(MBEDTLS_FREESCALE_LTC_AES) || defined(MBEDTLS_FREESCALE_CAU3_AES)
    const unsigned char *key_tmp = key;

    memcpy(RK, key_tmp, keybits / 8);

    switch (keybits)
    {
        case 128:
            ctx->nr = 16;
            break;
        case 192:
            ctx->nr = 24;
            break;
        case 256:
            ctx->nr = 32;
            break;
        default:
            return (MBEDTLS_ERR_AES_INVALID_KEY_LENGTH);
    }
#elif defined(MBEDTLS_FREESCALE_MMCAU_AES)
    ctx->rk = RK = ctx->buf;

    switch (keybits)
    {
        case 128:
            ctx->nr = 10;
            break;
        case 192:
            ctx->nr = 12;
            break;
        case 256:
            ctx->nr = 14;
            break;
        default:
            return (MBEDTLS_ERR_AES_INVALID_KEY_LENGTH);
    }

    MMCAU_AES_SetKey(key, keybits / 8, (uint8_t *)RK);
#endif

    return 0;
}

/*
 * AES-ECB block encryption/decryption
 */
int mbedtls_aes_crypt_ecb( mbedtls_aes_context *ctx,
                    int mode,
                    const unsigned char input[16],
                    unsigned char output[16] )
{
#if defined(MBEDTLS_AESNI_C) && defined(MBEDTLS_HAVE_X86_64)
    if( mbedtls_aesni_has_support( MBEDTLS_AESNI_AES ) )
        return( mbedtls_aesni_crypt_ecb( ctx, mode, input, output ) );
#endif

#if defined(MBEDTLS_PADLOCK_C) && defined(MBEDTLS_HAVE_X86)
    if( aes_padlock_ace )
    {
        if( mbedtls_padlock_xcryptecb( ctx, mode, input, output ) == 0 )
            return( 0 );

        // If padlock data misaligned, we just fall back to
        // unaccelerated mode
        //
    }
#endif

    if( mode == MBEDTLS_AES_ENCRYPT )
        mbedtls_aes_encrypt( ctx, input, output );
    else
        mbedtls_aes_decrypt( ctx, input, output );

    return( 0 );
}

/*
 * AES-ECB block encryption
 */
void mbedtls_aes_encrypt(mbedtls_aes_context *ctx, const unsigned char input[16], unsigned char output[16])
{
    uint8_t *key;

    key = (uint8_t *)ctx->rk;
#if defined(MBEDTLS_FREESCALE_LTC_AES)
    LTC_AES_EncryptEcb(LTC_INSTANCE, input, output, 16, key, ctx->nr);
#elif defined(MBEDTLS_FREESCALE_MMCAU_AES)
    MMCAU_AES_EncryptEcb(input, key, ctx->nr, output);
#elif defined(MBEDTLS_FREESCALE_CAU3_AES)
    cauKeyContext cau_ctx;

    cau_ctx.keySched = ctx->rk;
    cau_ctx.keySize = ctx->nr;
    memcpy(&cau_ctx.key, key, cau_ctx.keySize);
    CAU_LoadKeyContext((uint32_t *)&cau_ctx, 0, MBEDTLS_CAU3_COMPLETION_SIGNAL);
    CAU3_WRAP_AES_EncryptEcb(input, 0, output, MBEDTLS_CAU3_COMPLETION_SIGNAL);
#endif
}

/*
 * AES-ECB block decryption
 */
void mbedtls_aes_decrypt(mbedtls_aes_context *ctx, const unsigned char input[16], unsigned char output[16])
{
    uint8_t *key;

    key = (uint8_t *)ctx->rk;
#if defined(MBEDTLS_FREESCALE_LTC_AES)
    LTC_AES_DecryptEcb(LTC_INSTANCE, input, output, 16, key, ctx->nr, kLTC_EncryptKey);
#elif defined(MBEDTLS_FREESCALE_MMCAU_AES)
    MMCAU_AES_DecryptEcb(input, key, ctx->nr, output);
#elif defined(MBEDTLS_FREESCALE_CAU3_AES)
    cauKeyContext cau_ctx;

    cau_ctx.keySched = ctx->rk;
    cau_ctx.keySize = ctx->nr;
    memcpy(&cau_ctx.key, key, cau_ctx.keySize);
    CAU_LoadKeyContext((uint32_t *)&cau_ctx, 0, MBEDTLS_CAU3_COMPLETION_SIGNAL);
    CAU3_WRAP_AES_DecryptEcb(input, 0, output, MBEDTLS_CAU3_COMPLETION_SIGNAL);
#endif
}

#if defined(MBEDTLS_CIPHER_MODE_CBC)
/*
 * AES-CBC buffer encryption/decryption
 */
#if defined(MBEDTLS_FREESCALE_LTC_AES)
int mbedtls_aes_crypt_cbc(mbedtls_aes_context *ctx,
                          int mode,
                          size_t length,
                          unsigned char iv[16],
                          const unsigned char *input,
                          unsigned char *output)
{
    uint8_t *key = (uint8_t *)ctx->rk;
    uint32_t keySize = ctx->nr;

    if (length % 16)
        return (MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH);

    if (mode == MBEDTLS_AES_DECRYPT)
    {
        uint8_t tmp[16];
        memcpy(tmp, input + length - 16, 16);
        LTC_AES_DecryptCbc(LTC_INSTANCE, input, output, length, iv, key, keySize, kLTC_EncryptKey);
        memcpy(iv, tmp, 16);
    }
    else
    {
        LTC_AES_EncryptCbc(LTC_INSTANCE, input, output, length, iv, key, keySize);
        memcpy(iv, output + length - 16, 16);
    }

    return (0);
}
#endif
#endif /* MBEDTLS_CIPHER_MODE_CBC */


#if defined(MBEDTLS_CIPHER_MODE_CTR)
/*
 * AES-CTR buffer encryption/decryption
 */
#if defined(MBEDTLS_FREESCALE_LTC_AES)
int mbedtls_aes_crypt_ctr(mbedtls_aes_context *ctx,
                          size_t length,
                          size_t *nc_off,
                          unsigned char nonce_counter[16],
                          unsigned char stream_block[16],
                          const unsigned char *input,
                          unsigned char *output)
{
    uint8_t *key;
    uint32_t keySize;

    key = (uint8_t *)ctx->rk;
    keySize = ctx->nr;
    LTC_AES_CryptCtr(LTC_INSTANCE, input, output, length, nonce_counter, key, keySize, stream_block,
                     (uint32_t *)nc_off);

    return (0);
}
#endif
#endif /* MBEDTLS_CIPHER_MODE_CTR */

#if defined(MBEDTLS_CCM_C)

#include "mbedtls/ccm.h"

#define CCM_ENCRYPT 0
#define CCM_DECRYPT 1

/*
 * Authenticated encryption or decryption
 */
#if defined(MBEDTLS_FREESCALE_LTC_AES)
static int ccm_auth_crypt(mbedtls_ccm_context *ctx,
                          int mode,
                          size_t length,
                          const unsigned char *iv,
                          size_t iv_len,
                          const unsigned char *add,
                          size_t add_len,
                          const unsigned char *input,
                          unsigned char *output,
                          unsigned char *tag,
                          size_t tag_len)
{
    status_t status;
    const uint8_t *key;
    uint8_t keySize;
    mbedtls_aes_context *aes_ctx;

    aes_ctx = (mbedtls_aes_context *)ctx->cipher_ctx.cipher_ctx;
    key = (uint8_t *)aes_ctx->rk;
    keySize = aes_ctx->nr;
    if (mode == CCM_ENCRYPT)
    {
        status = LTC_AES_EncryptTagCcm(LTC_INSTANCE, input, output, length, iv, iv_len, add, add_len, key, keySize, tag,
                                       tag_len);
    }
    else
    {
        status = LTC_AES_DecryptTagCcm(LTC_INSTANCE, input, output, length, iv, iv_len, add, add_len, key, keySize, tag,
                                       tag_len);
    }

    if (status == kStatus_InvalidArgument)
    {
        return MBEDTLS_ERR_CCM_BAD_INPUT;
    }
    else if (status != kStatus_Success)
    {
        return MBEDTLS_ERR_CCM_AUTH_FAILED;
    }

    return (0);
}
#endif /* MBEDTLS_FREESCALE_LTC_AES */

#if defined(MBEDTLS_FREESCALE_LTC_AES)
#if 0
/*
 * Authenticated encryption
 */
int mbedtls_ccm_encrypt_and_tag(mbedtls_ccm_context *ctx,
                                size_t length,
                                const unsigned char *iv,
                                size_t iv_len,
                                const unsigned char *add,
                                size_t add_len,
                                const unsigned char *input,
                                unsigned char *output,
                                unsigned char *tag,
                                size_t tag_len)
{
    return (ccm_auth_crypt(ctx, CCM_ENCRYPT, length, iv, iv_len, add, add_len, input, output, tag, tag_len));
}

/*
 * Authenticated decryption
 */
int mbedtls_ccm_auth_decrypt(mbedtls_ccm_context *ctx,
                             size_t length,
                             const unsigned char *iv,
                             size_t iv_len,
                             const unsigned char *add,
                             size_t add_len,
                             const unsigned char *input,
                             unsigned char *output,
                             const unsigned char *tag,
                             size_t tag_len)
{
    unsigned char tagCopy[16];
    unsigned char *actTag = NULL;
    if (tag)
    {
        memcpy(tagCopy, tag, tag_len);
        actTag = tagCopy;
    }
    return (ccm_auth_crypt(ctx, CCM_DECRYPT, length, iv, iv_len, add, add_len, input, output, actTag, tag_len));
}
#endif
#endif /* MBEDTLS_FREESCALE_LTC_AES */
#endif /* MBEDTLS_CCM_C */

#if defined(MBEDTLS_GCM_C)
#if defined(MBEDTLS_FREESCALE_LTC_AES_GCM)

#include "mbedtls/gcm.h"
#if 0
int mbedtls_gcm_crypt_and_tag(mbedtls_gcm_context *ctx,
                              int mode,
                              size_t length,
                              const unsigned char *iv,
                              size_t iv_len,
                              const unsigned char *add,
                              size_t add_len,
                              const unsigned char *input,
                              unsigned char *output,
                              size_t tag_len,
                              unsigned char *tag)
{
    status_t status;
    uint8_t *key;
    uint32_t keySize;
    mbedtls_aes_context *aes_ctx;

    ctx->len = length;
    ctx->add_len = add_len;
    aes_ctx = (mbedtls_aes_context *)ctx->cipher_ctx.cipher_ctx;
    key = (uint8_t *)aes_ctx->rk;
    keySize = aes_ctx->nr;
    if (mode == MBEDTLS_GCM_ENCRYPT)
    {
        status = LTC_AES_EncryptTagGcm(LTC_INSTANCE, input, output, length, iv, iv_len, add, add_len, key, keySize, tag,
                                       tag_len);
    }
    else
    {
        status = LTC_AES_DecryptTagGcm(LTC_INSTANCE, input, output, length, iv, iv_len, add, add_len, key, keySize, tag,
                                       tag_len);
    }

    if (status == kStatus_InvalidArgument)
    {
        return MBEDTLS_ERR_GCM_BAD_INPUT;
    }
    else if (status != kStatus_Success)
    {
        return MBEDTLS_ERR_GCM_AUTH_FAILED;
    }

    return 0;
}

int mbedtls_gcm_auth_decrypt(mbedtls_gcm_context *ctx,
                             size_t length,
                             const unsigned char *iv,
                             size_t iv_len,
                             const unsigned char *add,
                             size_t add_len,
                             const unsigned char *tag,
                             size_t tag_len,
                             const unsigned char *input,
                             unsigned char *output)
{
    unsigned char tag_copy[16];
    unsigned char *actTag = NULL;
    if (tag)
    {
        memcpy(tag_copy, tag, tag_len);
        actTag = tag_copy;
    }
    return (mbedtls_gcm_crypt_and_tag(ctx, MBEDTLS_GCM_DECRYPT, length, iv, iv_len, add, add_len, input, output,
                                      tag_len, actTag));
}
#endif
#endif
#endif /* MBEDTLS_GCM_C */

#endif /*MBEDTLS_AES_ALT*/
