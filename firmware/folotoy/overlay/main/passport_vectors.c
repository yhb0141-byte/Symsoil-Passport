#include "passport_vectors.h"

#ifdef ESP_PLATFORM
#include "passport_crypto.h"
#endif

#include <stdint.h>
#include <string.h>

#define SYNTHETIC_PUBLIC_X "JB-jgrJKPFCBj7pMqWBmRvHKELz9NUwPi5cWqFo33uE"
#define SYNTHETIC_PUBLIC_Y "wmp9ser63Tn1lEV-3u15eXXMNGInfx9D5Dz0Fq2VA7s"
#define SYNTHETIC_DEVICE "D-cbe700af1bb3284e386903af"
#define SYNTHETIC_EXPIRES UINT64_C(1925020860000)

static const passport_protocol_vector_t VECTORS[] = {
    {
        .name = "contribution",
        .frame = {
            .community_id = "synthetic-community",
            .counter = 1,
            .decision = "receive",
            .device_id = SYNTHETIC_DEVICE,
            .expires_at = SYNTHETIC_EXPIRES,
            .member_id = "synthetic-member",
            .nonce = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB",
            .request_digest = "bbed7727d04df15a802f9b59206f876d60fd17b3c63e1b0197842d898bfc18c7",
            .request_id = "synthetic-request-1",
            .request_version = 1,
        },
        .canonical_content = "{\"communityId\":\"synthetic-community\",\"kind\":\"contribution\",\"memberId\":\"synthetic-member\",\"payload\":{\"approvedBy\":\"synthetic-admin\",\"points\":30,\"policy\":\"contribution-v1\",\"terminalId\":\"synthetic-terminal\",\"title\":\"维护花园 🌱\\n整理“工具架”\"},\"sourceId\":\"synthetic-source-1\",\"version\":1}",
        .canonical_frame = "{\"communityId\":\"synthetic-community\",\"counter\":1,\"decision\":\"receive\",\"deviceId\":\"D-cbe700af1bb3284e386903af\",\"expiresAt\":1925020860000,\"memberId\":\"synthetic-member\",\"nonce\":\"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB\",\"protocol\":\"symsoil-passport/1\",\"requestDigest\":\"bbed7727d04df15a802f9b59206f876d60fd17b3c63e1b0197842d898bfc18c7\",\"requestId\":\"synthetic-request-1\",\"requestVersion\":1}",
        .public_x = SYNTHETIC_PUBLIC_X,
        .public_y = SYNTHETIC_PUBLIC_Y,
        .signature = "iORbwF-hii-92h05WpsQzMVXXMhjYps7NljUyZYeOPjB39z18rrj2y1SKT8Ng4hkmQU4Xf2HiMN5NA_iMscwjg",
    },
    {
        .name = "order",
        .frame = {
            .community_id = "synthetic-community",
            .counter = 2,
            .decision = "spend",
            .device_id = SYNTHETIC_DEVICE,
            .expires_at = SYNTHETIC_EXPIRES,
            .member_id = "synthetic-member",
            .nonce = "AgICAgICAgICAgICAgICAgICAgICAgIC",
            .request_digest = "731e278c62557023f8272a69f7d8c20071145504d635f0b38d912cdf17988d44",
            .request_id = "synthetic-request-2",
            .request_version = 1,
        },
        .canonical_content = "{\"communityId\":\"synthetic-community\",\"kind\":\"order\",\"memberId\":\"synthetic-member\",\"payload\":{\"itemId\":\"harvest\",\"points\":20,\"terminalId\":\"synthetic-terminal\",\"title\":\"菜园收获包 1 份\"},\"sourceId\":\"synthetic-source-2\",\"version\":1}",
        .canonical_frame = "{\"communityId\":\"synthetic-community\",\"counter\":2,\"decision\":\"spend\",\"deviceId\":\"D-cbe700af1bb3284e386903af\",\"expiresAt\":1925020860000,\"memberId\":\"synthetic-member\",\"nonce\":\"AgICAgICAgICAgICAgICAgICAgICAgIC\",\"protocol\":\"symsoil-passport/1\",\"requestDigest\":\"731e278c62557023f8272a69f7d8c20071145504d635f0b38d912cdf17988d44\",\"requestId\":\"synthetic-request-2\",\"requestVersion\":1}",
        .public_x = SYNTHETIC_PUBLIC_X,
        .public_y = SYNTHETIC_PUBLIC_Y,
        .signature = "cevsLz5SZq54cBmqKulrJXZlNlHDtUDaG0Zfv4DSHZdFYXuxxixV6Pf2HE3yrVCGEc07buswi7kzSjLD9IxnUA",
    },
    {
        .name = "expression",
        .frame = {
            .community_id = "synthetic-community",
            .counter = 3,
            .decision = "original_only",
            .device_id = SYNTHETIC_DEVICE,
            .expires_at = SYNTHETIC_EXPIRES,
            .member_id = "synthetic-member",
            .nonce = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMD",
            .request_digest = "8fb7e851514bb95526b4d5648e63dfde1dd049e5b2cebfa6a0e38c3cf2b33c9f",
            .request_id = "synthetic-request-3",
            .request_version = 1,
        },
        .canonical_content = "{\"communityId\":\"synthetic-community\",\"kind\":\"expression\",\"memberId\":\"synthetic-member\",\"payload\":{\"original\":\"我可以帮忙，但不能超过中午。\",\"retelling\":\"伙伴愿意参与全天维护。\",\"title\":\"核对我的转述\"},\"sourceId\":\"synthetic-source-3\",\"version\":1}",
        .canonical_frame = "{\"communityId\":\"synthetic-community\",\"counter\":3,\"decision\":\"original_only\",\"deviceId\":\"D-cbe700af1bb3284e386903af\",\"expiresAt\":1925020860000,\"memberId\":\"synthetic-member\",\"nonce\":\"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMD\",\"protocol\":\"symsoil-passport/1\",\"requestDigest\":\"8fb7e851514bb95526b4d5648e63dfde1dd049e5b2cebfa6a0e38c3cf2b33c9f\",\"requestId\":\"synthetic-request-3\",\"requestVersion\":1}",
        .public_x = SYNTHETIC_PUBLIC_X,
        .public_y = SYNTHETIC_PUBLIC_Y,
        .signature = "3eBwkop3R-ecp2qXr5b-YQJlXqy8Bq7C5XtHXaZEk5-GrCLZUajyW0fVeK5UivhXFLezplH3E8tk_4ZC8sSy-w",
    },
    {
        .name = "grant",
        .frame = {
            .community_id = "synthetic-community",
            .counter = 4,
            .decision = "approve",
            .device_id = SYNTHETIC_DEVICE,
            .expires_at = SYNTHETIC_EXPIRES,
            .member_id = "synthetic-member",
            .nonce = "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
            .request_digest = "d7876563fd16f58aed0db10fd0eea5be7445ea55355f0097e80c53930f5ed266",
            .request_id = "synthetic-request-4",
            .request_version = 1,
        },
        .canonical_content = "{\"communityId\":\"synthetic-community\",\"kind\":\"grant\",\"memberId\":\"synthetic-member\",\"payload\":{\"action\":{\"action\":\"update\",\"resource\":\"garden-roster\",\"value\":\"周六上午：合成测试成员维护菜园\"},\"agentId\":\"xiaorang\",\"boundaries\":\"不外发 不转授权 不操作其他资源\",\"expiresInHours\":24,\"maxUses\":1,\"title\":\"授权小壤更新菜园排班\"},\"sourceId\":\"synthetic-source-4\",\"version\":1}",
        .canonical_frame = "{\"communityId\":\"synthetic-community\",\"counter\":4,\"decision\":\"approve\",\"deviceId\":\"D-cbe700af1bb3284e386903af\",\"expiresAt\":1925020860000,\"memberId\":\"synthetic-member\",\"nonce\":\"BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE\",\"protocol\":\"symsoil-passport/1\",\"requestDigest\":\"d7876563fd16f58aed0db10fd0eea5be7445ea55355f0097e80c53930f5ed266\",\"requestId\":\"synthetic-request-4\",\"requestVersion\":1}",
        .public_x = SYNTHETIC_PUBLIC_X,
        .public_y = SYNTHETIC_PUBLIC_Y,
        .signature = "X4gsC90Lmvssrhkmo3k2cabQkB0OXBxhn0zzUmiP1k94EBWiGgUbcBh2aI02oAZAjoTLs9vTHM9uVnkm83rCmw",
    },
};

const passport_protocol_vector_t *passport_protocol_vectors(size_t *count)
{
    if (count) *count = sizeof(VECTORS) / sizeof(VECTORS[0]);
    return VECTORS;
}

static int frame_selftest(const passport_protocol_vector_t *vector)
{
    char frame[PASSPORT_CONFIRMATION_FRAME_MAX];
    size_t length = 0;
    if (passport_confirmation_frame_json(&vector->frame, frame, sizeof(frame), &length) !=
        PASSPORT_PROTOCOL_OK) return 1;
    if (length != strlen(vector->canonical_frame) || strcmp(frame, vector->canonical_frame) != 0) return 2;
    return 0;
}

int passport_protocol_vectors_selftest(void)
{
    const size_t count = sizeof(VECTORS) / sizeof(VECTORS[0]);
    for (size_t index = 0; index < count; index++) {
        const int frame_result = frame_selftest(&VECTORS[index]);
        if (frame_result) return -(int)(index * 10 + frame_result);
#ifdef ESP_PLATFORM
        uint8_t public_x[PASSPORT_P256_COORD_SIZE];
        uint8_t public_y[PASSPORT_P256_COORD_SIZE];
        uint8_t signature[PASSPORT_P256_P1363_SIZE];
        uint8_t digest[PASSPORT_SHA256_SIZE];
        size_t public_x_length = 0;
        size_t public_y_length = 0;
        size_t signature_length = 0;
        const passport_protocol_vector_t *vector = &VECTORS[index];
        if (passport_base64url_decode(vector->public_x, public_x, sizeof(public_x), &public_x_length) !=
                PASSPORT_PROTOCOL_OK || public_x_length != sizeof(public_x) ||
            passport_base64url_decode(vector->public_y, public_y, sizeof(public_y), &public_y_length) !=
                PASSPORT_PROTOCOL_OK || public_y_length != sizeof(public_y) ||
            passport_base64url_decode(vector->signature, signature, sizeof(signature), &signature_length) !=
                PASSPORT_PROTOCOL_OK || signature_length != sizeof(signature)) {
            return -(int)(index * 10 + 3);
        }
        if (!passport_sha256((const uint8_t *)vector->canonical_content,
                             strlen(vector->canonical_content), digest)) {
            return -(int)(index * 10 + 4);
        }
        static const char HEX[] = "0123456789abcdef";
        char digest_hex[PASSPORT_SHA256_SIZE * 2 + 1];
        for (size_t byte = 0; byte < sizeof(digest); byte++) {
            digest_hex[byte * 2] = HEX[digest[byte] >> 4];
            digest_hex[byte * 2 + 1] = HEX[digest[byte] & 0x0f];
        }
        digest_hex[sizeof(digest_hex) - 1] = '\0';
        if (strcmp(digest_hex, vector->frame.request_digest) != 0) return -(int)(index * 10 + 5);
        if (!passport_p256_verify_p1363(public_x, public_y,
                (const uint8_t *)vector->canonical_frame, strlen(vector->canonical_frame), signature)) {
            return -(int)(index * 10 + 6);
        }
        passport_confirmation_frame_t tampered = vector->frame;
        tampered.counter++;
        char changed[PASSPORT_CONFIRMATION_FRAME_MAX];
        size_t changed_length = 0;
        if (passport_confirmation_frame_json(&tampered, changed, sizeof(changed), &changed_length) !=
                PASSPORT_PROTOCOL_OK ||
            passport_p256_verify_p1363(public_x, public_y,
                (const uint8_t *)changed, changed_length, signature)) {
            return -(int)(index * 10 + 7);
        }
#endif
    }
    return 0;
}
