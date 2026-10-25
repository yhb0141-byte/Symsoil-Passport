#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "passport_delivery.h"
#include "passport_provision.h"
#include "delivery_live_fixture.h"

typedef struct {
    uint8_t bytes[2][PASSPORT_OUTBOX_RECORD_MAX];
    size_t length[2];
    bool present[2];
} memory_t;

static passport_store_result_t read_slot(void *context, size_t slot,
    uint8_t *output, size_t capacity, size_t *length)
{
    memory_t *memory = context;
    if (slot >= 2 || memory->length[slot] > capacity) return PASSPORT_STORE_ERROR;
    if (!memory->present[slot]) return PASSPORT_STORE_NOT_FOUND;
    memcpy(output, memory->bytes[slot], memory->length[slot]);
    *length = memory->length[slot];
    return PASSPORT_STORE_OK;
}

static bool write_slot(void *context, size_t slot, const uint8_t *bytes, size_t length)
{
    memory_t *memory = context;
    if (slot >= 2 || length > sizeof(memory->bytes[slot])) return false;
    memcpy(memory->bytes[slot], bytes, length);
    memory->length[slot] = length;
    memory->present[slot] = true;
    return true;
}

int main(void)
{
    memory_t trust_memory = { 0 }, outbox_memory = { 0 };
    passport_outbox_store_t trust_store = { &trust_memory, read_slot, write_slot };
    passport_outbox_store_t outbox_store = { &outbox_memory, read_slot, write_slot };
    passport_trust_root_t root = { .community_id = "jiuhua-symsoil" };
    memcpy(root.public_x, LIVE_ROOT_X, 32);
    memcpy(root.public_y, LIVE_ROOT_Y, 32);
    passport_trust_manifest_t manifest = { .community_id = "jiuhua-symsoil",
        .epoch = 1, .state = PASSPORT_TRUST_ACTIVE };
    memcpy(manifest.service_public_x, LIVE_SERVICE_X, 32);
    memcpy(manifest.service_public_y, LIVE_SERVICE_Y, 32);
    passport_trust_t trust;
    assert(passport_trust_open(&trust, &trust_store, &root) == PASSPORT_TRUST_EMPTY);
    passport_provision_t local;
    passport_provision_init(&local);
    assert(passport_provision_begin_local(&local, &trust, &manifest, LIVE_TRUST_SIGNATURE,
        PASSPORT_PROVISION_APPLY, NULL, 0, 10000) == PASSPORT_PROVISION_OK);
    passport_provision_view_t view;
    passport_provision_get_view(&local, &view);
    assert(strcmp(view.root_fingerprint, LIVE_ROOT_FINGERPRINT) == 0);
    assert(view.state == PASSPORT_PROVISION_FINGERPRINT);
    (void)passport_provision_local_input(&local, PASSPORT_PROVISION_OK_DOWN, 10);
    (void)passport_provision_local_input(&local, PASSPORT_PROVISION_OK_UP, 11);
    (void)passport_provision_local_input(&local, PASSPORT_PROVISION_OK_DOWN, 20);
    assert(passport_provision_tick(&local, 2019) != PASSPORT_PROVISION_APPLIED);
    assert(passport_provision_tick(&local, 2020) == PASSPORT_PROVISION_APPLIED);
    assert(trust.state == PASSPORT_TRUST_ACTIVE);
    assert(passport_p256_verify_p1363(LIVE_MEMBER_X, LIVE_MEMBER_Y,
        (const uint8_t *)LIVE_CONFIRMATION, strlen(LIVE_CONFIRMATION), LIVE_MEMBER_SIGNATURE));

    passport_delivery_t delivery;
    assert(passport_delivery_open(&delivery, &outbox_store, 64, 3) == PASSPORT_DELIVERY_EMPTY);
    assert(passport_delivery_queue(&delivery, LIVE_CONFIRMATION, strlen(LIVE_CONFIRMATION),
        LIVE_MEMBER_SIGNATURE, 42) == PASSPORT_DELIVERY_OK);
    passport_delivery_result_frame_t result = { .community_id = "jiuhua-symsoil", .outcome = "accepted",
        .reply_signature = LIVE_REPLY_SIGNATURE_TEXT, .request_id = LIVE_REQUEST_ID,
        .result_id = LIVE_RESULT_ID, .transfer_id = 42 };
    char canonical[PASSPORT_DELIVERY_RESULT_FRAME_MAX];
    size_t length = 0;
    assert(passport_delivery_result_frame_json(&result, canonical, sizeof(canonical), &length) == PASSPORT_PROTOCOL_OK);
    assert(length == strlen(LIVE_RESULT_CANONICAL) && memcmp(canonical, LIVE_RESULT_CANONICAL, length) == 0);
    uint8_t modified_signature[64];
    memcpy(modified_signature, LIVE_SERVICE_SIGNATURE, 64);
    modified_signature[0] ^= 1;
    assert(passport_delivery_finalize_signed(&delivery, &result, &trust, modified_signature) == PASSPORT_DELIVERY_UNTRUSTED_RESULT);
    passport_outbox_message_t still_pending;
    assert(passport_outbox_load(&outbox_store, &still_pending) == PASSPORT_OUTBOX_READY);
    assert(passport_delivery_finalize_signed(&delivery, &result, &trust, LIVE_SERVICE_SIGNATURE) == PASSPORT_DELIVERY_OK);
    assert(passport_outbox_load(&outbox_store, &still_pending) == PASSPORT_OUTBOX_EMPTY);
    puts("Live HTTP receipt -> local provisioning -> firmware result verification: PASS");
    return 0;
}
