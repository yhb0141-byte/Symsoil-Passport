#include <assert.h>
#include <string.h>

#include "passport_core.h"
#include "passport_protocol.h"
#include "passport_vectors.h"

static passport_request_t request(passport_kind_t kind, uint32_t version, uint64_t expiry)
{
    passport_request_t value = { .kind = kind, .version = version, .expires_at_ms = expiry };
    memset(value.digest, (int)version, sizeof(value.digest));
    return value;
}

int main(void)
{
    assert(passport_protocol_vectors_selftest() == 0);
    size_t vector_count = 0;
    assert(passport_protocol_vectors(&vector_count) != NULL);
    assert(vector_count == 4);

    const passport_delivery_result_vector_t *delivery = passport_delivery_result_vector();
    assert(delivery != NULL);
    char delivery_frame[PASSPORT_DELIVERY_RESULT_FRAME_MAX];
    size_t delivery_length = 0;
    assert(passport_delivery_result_frame_json(&delivery->frame, delivery_frame,
        sizeof(delivery_frame), &delivery_length) == PASSPORT_PROTOCOL_OK);
    assert(delivery_length == strlen(delivery->canonical_frame));
    assert(strcmp(delivery_frame, delivery->canonical_frame) == 0);
    passport_delivery_result_frame_t invalid_delivery = delivery->frame;
    invalid_delivery.transfer_id = 0;
    assert(passport_delivery_result_frame_json(&invalid_delivery, delivery_frame,
        sizeof(delivery_frame), &delivery_length) == PASSPORT_PROTOCOL_INVALID_FIELD);
    invalid_delivery = delivery->frame;
    invalid_delivery.outcome = "pending";
    assert(passport_delivery_result_frame_json(&invalid_delivery, delivery_frame,
        sizeof(delivery_frame), &delivery_length) == PASSPORT_PROTOCOL_INVALID_FIELD);
    invalid_delivery = delivery->frame;
    invalid_delivery.reply_signature = "short";
    assert(passport_delivery_result_frame_json(&invalid_delivery, delivery_frame,
        sizeof(delivery_frame), &delivery_length) == PASSPORT_PROTOCOL_INVALID_FIELD);

    uint8_t decoded[64];
    size_t decoded_length = 0;
    assert(passport_base64url_decode(
        "JB-jgrJKPFCBj7pMqWBmRvHKELz9NUwPi5cWqFo33uE",
        decoded, sizeof(decoded), &decoded_length) == PASSPORT_PROTOCOL_OK);
    assert(decoded_length == 32);
    assert(passport_base64url_decode("A", decoded, sizeof(decoded), &decoded_length) ==
           PASSPORT_PROTOCOL_INVALID_FIELD);
    assert(passport_base64url_decode("AQEBAQ", decoded, 2, &decoded_length) ==
           PASSPORT_PROTOCOL_BUFFER_TOO_SMALL);

    passport_confirmation_frame_t escaped = {
        .community_id = "synthetic-community",
        .counter = 1,
        .decision = "line\n\"quote\"\\tab\t🌱",
        .device_id = "synthetic-device",
        .expires_at = 2,
        .member_id = "synthetic-member",
        .nonce = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB",
        .request_digest = "bbed7727d04df15a802f9b59206f876d60fd17b3c63e1b0197842d898bfc18c7",
        .request_id = "synthetic-request",
        .request_version = 3,
    };
    char frame[PASSPORT_CONFIRMATION_FRAME_MAX];
    size_t frame_length = 0;
    assert(passport_confirmation_frame_json(&escaped, frame, sizeof(frame), &frame_length) ==
           PASSPORT_PROTOCOL_OK);
    assert(frame_length == strlen(frame));
    assert(strstr(frame, "\"decision\":\"line\\n\\\"quote\\\"\\\\tab\\t🌱\"") != NULL);
    char tiny[8];
    assert(passport_confirmation_frame_json(&escaped, tiny, sizeof(tiny), &frame_length) ==
           PASSPORT_PROTOCOL_BUFFER_TOO_SMALL);
    escaped.counter = PASSPORT_JS_SAFE_INTEGER_MAX + 1;
    assert(passport_confirmation_frame_json(&escaped, frame, sizeof(frame), &frame_length) ==
           PASSPORT_PROTOCOL_INVALID_FIELD);
    escaped.counter = 1;
    escaped.community_id = "\xc0\xaf";
    assert(passport_confirmation_frame_json(&escaped, frame, sizeof(frame), &frame_length) ==
           PASSPORT_PROTOCOL_INVALID_UTF8);

    assert(strcmp(passport_decision(PASSPORT_KIND_CONTRIBUTION, 0), "receive") == 0);
    assert(strcmp(passport_decision(PASSPORT_KIND_ORDER, 0), "spend") == 0);
    assert(strcmp(passport_decision(PASSPORT_KIND_REFUND, 0), "receive_refund") == 0);
    assert(strcmp(passport_decision(PASSPORT_KIND_BORROW, 0), "accept_task") == 0);
    assert(strcmp(passport_decision(PASSPORT_KIND_EXPRESSION, 2), "original_only") == 0);
    assert(strcmp(passport_decision(PASSPORT_KIND_EXPRESSION, 3), "no_retelling") == 0);
    assert(strcmp(passport_decision(PASSPORT_KIND_GRANT, 0), "approve") == 0);
    assert(passport_decision(PASSPORT_KIND_ORDER, 2) == NULL);

    passport_model_t model;
    passport_model_init(&model);
    passport_request_t v1 = request(PASSPORT_KIND_CONTRIBUTION, 1, 3000);
    assert(passport_model_load(&model, &v1, 1000) == PASSPORT_ACTION_RENDER);
    assert(model.page == PASSPORT_PAGE_REVIEW);
    assert(passport_model_input(&model, PASSPORT_KEY_OK, PASSPORT_PRESS_CLICK, 1100) == PASSPORT_ACTION_RENDER);
    assert(passport_model_input(&model, PASSPORT_KEY_DOWN, PASSPORT_PRESS_CLICK, 1200) == PASSPORT_ACTION_RENDER);
    assert(strcmp(passport_decision(v1.kind, model.choice), "needs_change") == 0);
    assert(passport_model_input(&model, PASSPORT_KEY_OK, PASSPORT_PRESS_CLICK, 1300) == PASSPORT_ACTION_RENDER);
    assert(model.page == PASSPORT_PAGE_CONFIRM);

    // Early release, silence and a different long-pressed key never approve.
    assert(passport_model_input(&model, PASSPORT_KEY_OK, PASSPORT_PRESS_CLICK, 1400) == PASSPORT_ACTION_NONE);
    assert(passport_model_tick(&model, 1800) == PASSPORT_ACTION_NONE);
    assert(passport_model_input(&model, PASSPORT_KEY_DOWN, PASSPORT_PRESS_LONG, 1900) == PASSPORT_ACTION_NONE);
    assert(passport_model_input(&model, PASSPORT_KEY_OK, PASSPORT_PRESS_LONG, 2000) == PASSPORT_ACTION_SIGNATURE_READY);

    passport_model_init(&model);
    assert(passport_model_load(&model, &v1, 1000) == PASSPORT_ACTION_RENDER);
    passport_request_t v2 = request(PASSPORT_KIND_CONTRIBUTION, 2, 4000);
    assert(passport_model_sync(&model, &v2, 1500) == PASSPORT_ACTION_SUPERSEDED);
    assert(!model.request_loaded);
    assert(passport_model_input(&model, PASSPORT_KEY_OK, PASSPORT_PRESS_LONG, 1600) == PASSPORT_ACTION_NONE);

    passport_model_init(&model);
    assert(passport_model_load(&model, &v1, 1000) == PASSPORT_ACTION_RENDER);
    assert(passport_model_tick(&model, 2999) == PASSPORT_ACTION_NONE);
    assert(passport_model_tick(&model, 3000) == PASSPORT_ACTION_EXPIRED);
    assert(!model.request_loaded);
    assert(passport_model_load(&model, &v1, 3000) == PASSPORT_ACTION_EXPIRED);
    return 0;
}
