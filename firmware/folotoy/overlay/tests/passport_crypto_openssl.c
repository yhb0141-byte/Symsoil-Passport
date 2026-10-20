// Host-only independent crypto backend. Device firmware uses mbedTLS.
#include "passport_crypto.h"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include <string.h>

bool passport_sha256(const uint8_t *message, size_t length,
                     uint8_t output[PASSPORT_SHA256_SIZE])
{
    unsigned int written = 0;
    return message && output &&
        EVP_Digest(message, length, output, &written, EVP_sha256(), NULL) == 1 &&
        written == PASSPORT_SHA256_SIZE;
}

bool passport_p256_verify_p1363(
    const uint8_t public_x[PASSPORT_P256_COORD_SIZE],
    const uint8_t public_y[PASSPORT_P256_COORD_SIZE],
    const uint8_t *message, size_t length,
    const uint8_t signature[PASSPORT_P256_P1363_SIZE])
{
    if (!public_x || !public_y || !message || !signature) return false;
    bool valid = false;
    EVP_PKEY_CTX *key_context = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    EVP_MD_CTX *digest = EVP_MD_CTX_new();
    EVP_PKEY *key = NULL;
    ECDSA_SIG *pair = ECDSA_SIG_new();
    BIGNUM *r = BN_bin2bn(signature, 32, NULL);
    BIGNUM *s = BN_bin2bn(signature + 32, 32, NULL);
    unsigned char *der = NULL;
    uint8_t point[65] = { 4 };
    char group[] = "prime256v1";
    memcpy(point + 1, public_x, 32);
    memcpy(point + 33, public_y, 32);
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group, 0),
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, point, sizeof(point)),
        OSSL_PARAM_construct_end(),
    };
    if (!key_context || !digest || !pair || !r || !s) goto cleanup;
    if (ECDSA_SIG_set0(pair, r, s) != 1) goto cleanup;
    r = NULL;
    s = NULL;
    const int der_length = i2d_ECDSA_SIG(pair, &der);
    if (der_length <= 0 || EVP_PKEY_fromdata_init(key_context) != 1 ||
        EVP_PKEY_fromdata(key_context, &key, EVP_PKEY_PUBLIC_KEY, params) != 1 ||
        EVP_DigestVerifyInit(digest, NULL, EVP_sha256(), NULL, key) != 1) goto cleanup;
    valid = EVP_DigestVerify(digest, der, (size_t)der_length, message, length) == 1;
cleanup:
    OPENSSL_free(der);
    BN_free(r);
    BN_free(s);
    ECDSA_SIG_free(pair);
    EVP_MD_CTX_free(digest);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(key_context);
    return valid;
}
