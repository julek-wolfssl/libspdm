/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * Internal include file for cryptlib.
 **/

#ifndef __INTERNAL_CRYPT_LIB_H__
#define __INTERNAL_CRYPT_LIB_H__

#include <base.h>
#include "library/memlib.h"
#include "library/malloclib.h"
#include "library/debuglib.h"
#include "library/cryptlib.h"
#include "library/spdm_crypt_lib.h"

//#include "crt_support.h"

#include <wolfssl/options.h>
#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define OBJ_get0_data(o) ((o)->data)
#define OBJ_length(o) ((o)->length)
#endif

#include <wolfssl/ssl.h>
// missing from wolfssl
RSA *d2i_RSA_PUBKEY_bio(BIO *bp, RSA **rsa);
EC_KEY *d2i_EC_PUBKEY_bio(BIO *bp, EC_KEY **eckey);
int EVP_PKEY_is_a(const EVP_PKEY *pkey, const char *name);
#define EVP_PKEY_ED25519 NID_ED25519
#define EVP_PKEY_ED448 NID_ED448
int ECDH_compute_key(void *out, size_t outlen,
                                           const EC_POINT *pub_key,
                                           const EC_KEY *ecdh,
                                           void *(*KDF)(const void *in,
                                                        size_t inlen, void *out,
                                                        size_t *outlen));
int DH_compute_key_padded(unsigned char *key,
                                                const BIGNUM *pub_key, DH *dh);
#define RSA_R_P_NOT_PRIME (-1)
#define RSA_R_Q_NOT_PRIME (-1)
#define RSA_R_N_DOES_NOT_EQUAL_P_Q (-1)
#define RSA_R_D_E_NOT_CONGRUENT_TO_1 (-1)
int ASN1_TIME_set_string_X509(ASN1_TIME *s, const char *str);

struct X509_req_info_st {
//    ASN1_ENCODING enc;          /* cached encoding of signed part */
    ASN1_INTEGER *version;      /* version, defaults to v1(0) so can be NULL */
    X509_NAME *subject;         /* certificate request DN */
    X509_PUBKEY *pubkey;        /* public key of request */
    /*
     * Zero or more attributes.
     * NB: although attributes is a mandatory field some broken
     * encodings omit it so this may be NULL in that case.
     */
    STACK_OF(X509_ATTRIBUTE) *attributes;
};
typedef struct X509_req_info_st X509_REQ_INFO;
X509_REQ_INFO *d2i_X509_REQ_INFO(X509_REQ_INFO **req_info, const unsigned char **ppin, long length);
void X509_REQ_INFO_free(X509_REQ_INFO *req_info);

void sk_X509_EXTENSION_free(STACK_OF(X509_EXTENSION) *exts);

// from os_stub/openssllib/include/crt_support.h */
#define LIBSPDM_VA_LIST va_list
#define LIBSPDM_VA_START(marker, parameter) va_start(marker, parameter)
#define LIBSPDM_VA_ARG(marker, TYPE) va_arg(marker, TYPE)
#define LIBSPDM_VA_END(marker) va_end(marker)


#endif
