#pragma once

#include <stddef.h>
#include <stdint.h>

#define PASSPORT_CONFIRMATION_FRAME_MAX 768
#define PASSPORT_DELIVERY_RESULT_FRAME_MAX 512
#define PASSPORT_JS_SAFE_INTEGER_MAX UINT64_C(9007199254740991)

typedef enum {
    PASSPORT_PROTOCOL_OK = 0,
    PASSPORT_PROTOCOL_INVALID_ARGUMENT,
    PASSPORT_PROTOCOL_INVALID_UTF8,
    PASSPORT_PROTOCOL_INVALID_FIELD,
    PASSPORT_PROTOCOL_BUFFER_TOO_SMALL,
} passport_protocol_result_t;

typedef struct {
    const char *community_id;
    uint64_t counter;
    const char *decision;
    const char *device_id;
    uint64_t expires_at;
    const char *member_id;
    const char *nonce;
    const char *request_digest;
    const char *request_id;
    uint64_t request_version;
} passport_confirmation_frame_t;

typedef struct {
    const char *community_id;
    const char *outcome;
    const char *reply_signature;
    const char *request_id;
    const char *result_id;
    uint32_t transfer_id;
} passport_delivery_result_frame_t;

// Produces the exact canonical UTF-8 JSON signed by symsoil-passport/1.
// Object keys are fixed in UTF-16 sort order. Strings are validated UTF-8 and
// JSON escaped; integers must fit JavaScript's safe-integer range.
passport_protocol_result_t passport_confirmation_frame_json(
    const passport_confirmation_frame_t *frame,
    char *output,
    size_t capacity,
    size_t *length);

// Produces the exact canonical UTF-8 result signed by the community service.
// The service signature is external to this frame. reply_signature binds the
// result to the exact public 64-byte P1363 member signature being finalized.
passport_protocol_result_t passport_delivery_result_frame_json(
    const passport_delivery_result_frame_t *frame,
    char *output,
    size_t capacity,
    size_t *length);

passport_protocol_result_t passport_base64url_decode(
    const char *text,
    uint8_t *output,
    size_t capacity,
    size_t *length);
