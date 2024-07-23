cmake_minimum_required(VERSION 3.5)

add_library(cryptlib_wolfssl STATIC "")

target_include_directories(cryptlib_wolfssl
    PRIVATE
        ${LIBSPDM_DIR}/include
        ${LIBSPDM_DIR}/include/hal
        ${LIBSPDM_DIR}/os_stub/include
        ${LIBSPDM_DIR}/os_stub/cryptlib_wolfssl
        ${WOLFSSL_INCDIR}/wolfssl/openssl
        ${WOLFSSL_INCDIR}/wolfssl
        ${WOLFSSL_INCDIR}
)

target_sources(cryptlib_wolfssl
    PRIVATE
        cipher/aead_aes_gcm.c
        cipher/aead_chacha20_poly1305.c
#        cipher/aead_sm4_gcm.c
        der/der.c
        hash/sha.c
        hash/sha3.c
#        hash/sm3.c
        hmac/hmac_sha.c
        hmac/hmac_sha3.c
#        hmac/hmac_sm3.c
        kdf/hkdf_sha.c
        kdf/hkdf_sha3.c
#        kdf/hkdf_sm3.c
        pem/pem.c
        pk/ec.c
        pk/ecd.c
        pk/dh.c
#        pk/sm2.c
        pk/rsa_basic.c
        pk/rsa_ext.c
        rand/rand.c
        sys_call/crt_wrapper_host.c
        pk/x509.c
)

target_compile_options(cryptlib_wolfssl PRIVATE ${WOLFSSL_FLAGS})

if(ARCH STREQUAL "x64")
    target_compile_options(cryptlib_wolfssl PRIVATE -DLIBSPDM_CPU_X64)
elseif(ARCH STREQUAL "ia32")
    target_compile_options(cryptlib_wolfssl PRIVATE -DLIBSPDM_CPU_IA32)
elseif(ARCH STREQUAL "aarch64")
    target_compile_options(cryptlib_wolfssl PRIVATE -DLIBSPDM_CPU_AARCH64)
elseif(ARCH STREQUAL "riscv32")
    target_compile_options(cryptlib_wolfssl PRIVATE -DLIBSPDM_CPU_RISCV32)
elseif(ARCH STREQUAL "riscv64")
    target_compile_options(cryptlib_wolfssl PRIVATE -DLIBSPDM_CPU_RISCV64)
elseif((ARCH STREQUAL "arm") OR (ARCH STREQUAL "aarch64"))
    target_compile_options(cryptlib_wolfssl PRIVATE -DLIBSPDM_CPU_ARM)
else()
    message(FATAL_ERROR "Unknown ARCH")
endif()
