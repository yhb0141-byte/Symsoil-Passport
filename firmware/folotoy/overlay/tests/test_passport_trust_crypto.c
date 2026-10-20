#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "passport_delivery.h"
#include "trust_fixture.h"

typedef struct {
    uint8_t data[2][PASSPORT_OUTBOX_RECORD_MAX];
    size_t length[2];
    bool present[2];
    unsigned writes;
    unsigned fail_write;
} memory_t;

static passport_store_result_t read_slot(void *context, size_t slot,
    uint8_t *output, size_t capacity, size_t *length)
{
    memory_t *memory = context;
    if (slot >= 2 || memory->length[slot] > capacity) return PASSPORT_STORE_ERROR;
    if (!memory->present[slot]) return PASSPORT_STORE_NOT_FOUND;
    memcpy(output, memory->data[slot], memory->length[slot]);
    *length = memory->length[slot];
    return PASSPORT_STORE_OK;
}

static bool write_slot(void *context, size_t slot, const uint8_t *bytes, size_t length)
{
    memory_t *memory = context;
    memory->writes++;
    if (slot >= 2 || length > sizeof(memory->data[slot]) ||
        memory->writes == memory->fail_write) return false;
    memcpy(memory->data[slot], bytes, length);
    memory->length[slot] = length;
    memory->present[slot] = true;
    return true;
}

static passport_outbox_store_t store_for(memory_t *memory)
{
    return (passport_outbox_store_t) { memory, read_slot, write_slot };
}

static passport_trust_root_t root(void)
{
    passport_trust_root_t pin = { .community_id = "synthetic-community" };
    memcpy(pin.public_x, TRUST_ROOT_X, 32);
    memcpy(pin.public_y, TRUST_ROOT_Y, 32);
    return pin;
}

static passport_trust_manifest_t manifest(unsigned index)
{
    passport_trust_manifest_t value = { .community_id = "synthetic-community",
        .epoch = index + 1, .state = PASSPORT_TRUST_ACTIVE };
    if (index == 2) value.state = PASSPORT_TRUST_SUSPENDED;
    else {
        memcpy(value.service_public_x, index == 0 ? TRUST_SERVICE_X_0 : TRUST_SERVICE_X_1, 32);
        memcpy(value.service_public_y, index == 0 ? TRUST_SERVICE_Y_0 : TRUST_SERVICE_Y_1, 32);
    }
    return value;
}

static const uint8_t *signature(unsigned index)
{
    const uint8_t *values[] = { TRUST_SIGNATURE_0, TRUST_SIGNATURE_1,
        TRUST_SIGNATURE_2, TRUST_SIGNATURE_3 };
    assert(index < 4);
    return values[index];
}

static void verify_vectors(void)
{
    const uint8_t *frames[] = { TRUST_FRAME_0, TRUST_FRAME_1, TRUST_FRAME_2, TRUST_FRAME_3 };
    const size_t lengths[] = { sizeof(TRUST_FRAME_0), sizeof(TRUST_FRAME_1), sizeof(TRUST_FRAME_2), sizeof(TRUST_FRAME_3) };
    for (unsigned index = 0; index < 4; index++) {
        passport_trust_manifest_t value = manifest(index);
        uint8_t encoded[PASSPORT_TRUST_FRAME_MAX];
        size_t length = 0;
        assert(passport_trust_encode(&value, encoded, sizeof(encoded), &length) == PASSPORT_TRUST_OK);
        assert(length == lengths[index] && memcmp(encoded, frames[index], length) == 0);
        assert(passport_p256_verify_p1363(TRUST_ROOT_X, TRUST_ROOT_Y, encoded, length, signature(index)));
        encoded[20] ^= 1;
        assert(!passport_p256_verify_p1363(TRUST_ROOT_X, TRUST_ROOT_Y, encoded, length, signature(index)));
    }
}

static passport_delivery_result_frame_t result_frame(void)
{
    return (passport_delivery_result_frame_t) { .community_id = "synthetic-community",
        .outcome = "accepted",
        .reply_signature = "iORbwF-hii-92h05WpsQzMVXXMhjYps7NljUyZYeOPjB39z18rrj2y1SKT8Ng4hkmQU4Xf2HiMN5NA_iMscwjg",
        .request_id = "synthetic-request", .result_id = "synthetic-result", .transfer_id = 42 };
}

static void queue_reply(passport_delivery_t *delivery, passport_outbox_store_t *store)
{
    passport_delivery_result_frame_t result = result_frame();
    uint8_t member_signature[64];
    size_t length = 0;
    assert(passport_base64url_decode(result.reply_signature, member_signature,
        sizeof(member_signature), &length) == PASSPORT_PROTOCOL_OK && length == 64);
    assert(passport_delivery_open(delivery, store, 64, 3) == PASSPORT_DELIVERY_EMPTY);
    const char frame[] = "{\"synthetic\":true}";
    assert(passport_delivery_queue(delivery, frame, strlen(frame), member_signature, 42) == PASSPORT_DELIVERY_OK);
}

static void test_rotation_and_pending_receipt(void)
{
    memory_t trust_memory = { 0 }, outbox_memory = { 0 };
    passport_outbox_store_t trust_store = store_for(&trust_memory), outbox_store = store_for(&outbox_memory);
    passport_trust_root_t pin = root();
    passport_trust_t trust;
    assert(passport_trust_open(&trust, &trust_store, &pin) == PASSPORT_TRUST_EMPTY);
    passport_delivery_t delivery;
    queue_reply(&delivery, &outbox_store);
    memory_t original_pending = outbox_memory;
    passport_delivery_result_frame_t result = result_frame();
    char canonical[PASSPORT_DELIVERY_RESULT_FRAME_MAX];
    size_t length = 0;
    assert(passport_delivery_result_frame_json(&result, canonical, sizeof(canonical), &length) == PASSPORT_PROTOCOL_OK);
    assert(length == strlen(RESULT_CANONICAL) && memcmp(canonical, RESULT_CANONICAL, length) == 0);
    assert(passport_delivery_finalize_signed(&delivery, &result, &trust, OLD_RESULT_SIGNATURE) == PASSPORT_DELIVERY_UNTRUSTED_RESULT);
    passport_trust_manifest_t initial = manifest(0);
    assert(passport_trust_apply(&trust, &initial, signature(0), false) == PASSPORT_TRUST_LOCAL_CONFIRMATION_REQUIRED);
    uint8_t wrong[64];
    memcpy(wrong, signature(0), sizeof(wrong));
    wrong[0] ^= 1;
    assert(passport_trust_apply(&trust, &initial, wrong, true) == PASSPORT_TRUST_UNTRUSTED);
    assert(passport_trust_apply(&trust, &initial, signature(0), true) == PASSPORT_TRUST_OK);
    assert(passport_p256_verify_p1363(TRUST_SERVICE_X_0, TRUST_SERVICE_Y_0, (uint8_t *)canonical, length, OLD_RESULT_SIGNATURE));
    passport_trust_manifest_t rotation = manifest(1), suspension = manifest(2), resume = manifest(3);
    assert(passport_trust_apply(&trust, &rotation, signature(1), false) == PASSPORT_TRUST_OK);
    assert(passport_trust_apply(&trust, &initial, signature(0), true) == PASSPORT_TRUST_REPLAY);
    assert(passport_delivery_finalize_signed(&delivery, &result, &trust, OLD_RESULT_SIGNATURE) == PASSPORT_DELIVERY_UNTRUSTED_RESULT);
    assert(passport_trust_apply(&trust, &suspension, signature(2), false) == PASSPORT_TRUST_OK);
    assert(passport_delivery_finalize_signed(&delivery, &result, &trust, CURRENT_RESULT_SIGNATURE) == PASSPORT_DELIVERY_UNTRUSTED_RESULT);
    assert(memcmp(&original_pending, &outbox_memory, sizeof(outbox_memory)) == 0);
    assert(passport_trust_apply(&trust, &resume, signature(3), false) == PASSPORT_TRUST_OK);
    assert(passport_delivery_finalize_signed(&delivery, &result, &trust, CURRENT_RESULT_SIGNATURE) == PASSPORT_DELIVERY_OK);
    passport_outbox_message_t pending;
    assert(passport_outbox_load(&outbox_store, &pending) == PASSPORT_OUTBOX_EMPTY);
}

static void test_torn_suspension_fails_closed(void)
{
    memory_t memory = { 0 }, outbox_memory = { 0 };
    passport_outbox_store_t storage = store_for(&memory), outbox_store = store_for(&outbox_memory);
    passport_trust_root_t pin = root();
    passport_trust_t trust;
    assert(passport_trust_open(&trust, &storage, &pin) == PASSPORT_TRUST_EMPTY);
    passport_trust_manifest_t initial = manifest(0), suspension = manifest(2), recovery = manifest(3);
    assert(passport_trust_apply(&trust, &initial, signature(0), true) == PASSPORT_TRUST_OK);
    memory.fail_write = memory.writes + 2;
    assert(passport_trust_apply(&trust, &suspension, signature(2), false) == PASSPORT_TRUST_IO_ERROR);
    assert(trust.state == PASSPORT_TRUST_LOCKED);
    memory.fail_write = 0;
    passport_trust_t reboot;
    assert(passport_trust_open(&reboot, &storage, &pin) == PASSPORT_TRUST_IS_LOCKED);
    assert(reboot.observed_epoch == 3);
    passport_delivery_t delivery;
    queue_reply(&delivery, &outbox_store);
    memory_t original = outbox_memory;
    passport_delivery_result_frame_t result = result_frame();
    assert(passport_delivery_finalize_signed(&delivery, &result, &reboot, OLD_RESULT_SIGNATURE) == PASSPORT_DELIVERY_UNTRUSTED_RESULT);
    assert(memcmp(&original, &outbox_memory, sizeof(original)) == 0);
    assert(passport_trust_apply(&reboot, &recovery, signature(3), true) == PASSPORT_TRUST_IS_LOCKED);
    assert(passport_trust_recover(&reboot, &recovery, signature(3), false, 3) == PASSPORT_TRUST_LOCAL_CONFIRMATION_REQUIRED);
    passport_trust_t too_low = reboot;
    assert(passport_trust_recover(&too_low, &recovery, signature(3), true, 4) == PASSPORT_TRUST_REPLAY);
    assert(passport_trust_recover(&reboot, &recovery, signature(3), true, 3) == PASSPORT_TRUST_OK);
    assert(passport_delivery_finalize_signed(&delivery, &result, &reboot, CURRENT_RESULT_SIGNATURE) == PASSPORT_DELIVERY_OK);
}

int main(void)
{
    verify_vectors();
    test_rotation_and_pending_receipt();
    test_torn_suspension_fails_closed();
    puts("Trust and delivery real P-256 interoperability: PASS");
    return 0;
}
