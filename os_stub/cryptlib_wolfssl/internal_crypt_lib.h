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
// from os_stub/openssllib/include/crt_support.h
#define LIBSPDM_VA_LIST va_list
#define LIBSPDM_VA_START(marker, parameter) va_start(marker, parameter)
#define LIBSPDM_VA_ARG(marker, TYPE) va_arg(marker, TYPE)
#define LIBSPDM_VA_END(marker) va_end(marker)

#include <wolfssl/options.h>
#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define OBJ_get0_data(o) ((o)->data)
#define OBJ_length(o) ((o)->length)
#endif

#include <wolfssl/ssl.h>
#include <openssl/ecdh.h>

// missing from wolfssl

RSA *d2i_RSA_PUBKEY_bio(BIO *bp, RSA **rsa);
// use wolfSSL_d2i_RSAPrivateKey_bio and wolfSSL_d2i_RSAPublicKey as basis

EC_KEY *d2i_EC_PUBKEY_bio(BIO *bp, EC_KEY **eckey);
// use wolfSSL_d2i_RSAPrivateKey_bio, wolfSSL_d2i_RSAPublicKey, wolfSSL_ECDSA_do_verify, and wolfSSL_d2i_ECDSA_SIG, as guides

int EVP_PKEY_is_a(const EVP_PKEY *pkey, const char *name);
// https://github.com/wolfSSL/wolfssl/pull/7804

int DH_compute_key_padded(unsigned char *key,
                                                const BIGNUM *pub_key, DH *dh);
// may be impossible, or require fakery, due to FIPS requirement.
// see https://github.com/wolfSSL/wolfssl/pull/7802
/* "DH_compute_key() computes the shared secret from the private DH value in dh and the other party’s
       public value in pub_key and stores it in key. key must point to DH_size(dh) bytes of memory.  The
       padding style is RFC 5246 (8.1.2) that strips leading zero bytes.  It is not constant time due to
       the leading zero bytes being stripped.  The return value should be considered public."

   "DH_compute_key_padded() is similar but stores a fixed number of bytes.  The padding style is NIST SP
       800-56A (C.1) that retains leading zero bytes.  It is constant time due to the leading zero bytes
       being retained.  The return value should be considered public."
 */

/*
// not needed -- altered libspdm_rsa_check_key() to return false for any
// RSA_check_key() failure, rather than just these.
#define RSA_R_P_NOT_PRIME (-1)
#define RSA_R_Q_NOT_PRIME (-1)
#define RSA_R_N_DOES_NOT_EQUAL_P_Q (-1)
#define RSA_R_D_E_NOT_CONGRUENT_TO_1 (-1)
*/

int ASN1_TIME_set_string_X509(ASN1_TIME *s, const char *str);
/* "ASN1_TIME_set_string_X509() sets ASN1_TIME structure s to the time represented by string str which
       must be in appropriate time format that RFC 5280 requires, which means it only allows YYMMDDHHMMSSZ
       and YYYYMMDDHHMMSSZ (leap second is rejected), all other ASN.1 time format are not allowed. If s is
       NULL this function performs a format check on str only."
*/

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
// use d2i_X509orX509REQ as a guide

void X509_REQ_INFO_free(X509_REQ_INFO *req_info);
// wrapper around wolfSSL_X509_free();

void sk_X509_EXTENSION_free(STACK_OF(X509_EXTENSION) *exts);
// see wolfSSL_X509_EXTENSION_free and wolfSSL_sk_X509_INFO_free

#endif
