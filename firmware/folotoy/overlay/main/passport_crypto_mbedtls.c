#include "passport_crypto.h"

#include "mbedtls/bignum.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/sha256.h"

#include <string.h>

bool passport_sha256(const uint8_t *message, size_t length,
                     uint8_t output[PASSPORT_SHA256_SIZE])
{
    return message && output && mbedtls_sha256(message, length, output, 0) == 0;
}

bool passport_p256_verify_p1363(
    const uint8_t public_x[PASSPORT_P256_COORD_SIZE],
    const uint8_t public_y[PASSPORT_P256_COORD_SIZE],
    const uint8_t *message,
    size_t message_length,
    const uint8_t signature[PASSPORT_P256_P1363_SIZE])
{
    if (!public_x || !public_y || !message || !signature) return false;

    bool valid = false;
    uint8_t hash[PASSPORT_SHA256_SIZE];
    mbedtls_ecp_keypair key;
    mbedtls_mpi r;
    mbedtls_mpi s;
    unsigned char public_point[1 + PASSPORT_P256_COORD_SIZE * 2];
    mbedtls_ecp_keypair_init(&key);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    if (!passport_sha256(message, message_length, hash)) goto cleanup;
    mbedtls_ecp_group *group = &key.MBEDTLS_PRIVATE(grp);
    mbedtls_ecp_point *point = &key.MBEDTLS_PRIVATE(Q);
    if (mbedtls_ecp_group_load(group, MBEDTLS_ECP_DP_SECP256R1) != 0) goto cleanup;
    public_point[0] = 0x04;
    memcpy(public_point + 1, public_x, PASSPORT_P256_COORD_SIZE);
    memcpy(public_point + 1 + PASSPORT_P256_COORD_SIZE, public_y, PASSPORT_P256_COORD_SIZE);
    if (mbedtls_ecp_point_read_binary(group, point, public_point, sizeof(public_point)) != 0) goto cleanup;
    if (mbedtls_ecp_check_pubkey(group, point) != 0) goto cleanup;
    if (mbedtls_mpi_read_binary(&r, signature, PASSPORT_P256_COORD_SIZE) != 0) goto cleanup;
    if (mbedtls_mpi_read_binary(&s, signature + PASSPORT_P256_COORD_SIZE,
                                PASSPORT_P256_COORD_SIZE) != 0) goto cleanup;
    valid = mbedtls_ecdsa_verify(group, hash, sizeof(hash), point, &r, &s) == 0;

cleanup:
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    mbedtls_ecp_keypair_free(&key);
    return valid;
}
