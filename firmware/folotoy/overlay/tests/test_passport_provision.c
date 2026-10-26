#include <assert.h>
#include <string.h>

#include "passport_provision.h"

static const passport_trust_root_t ROOT = {
    .community_id = "synthetic-community", .public_x = { 0x11 }, .public_y = { 0x22 },
};
static bool fail_hash;
static unsigned hash_calls;
static uint8_t hash_input[65];

/* State/fault tests use doubles. Real crypto is checked separately by the
 * repository's OpenSSL/P-256 interoperability test. */
static void sign_frame(const uint8_t *message, size_t length, uint8_t signature[64])
{
    const uint32_t crc = passport_crc32(message, length);
    for (size_t index = 0; index < 64; index++) {
        signature[index] = (uint8_t)(crc >> ((index % 4) * 8)) ^ (uint8_t)index;
    }
}

bool passport_p256_verify_p1363(const uint8_t x[32], const uint8_t y[32],
    const uint8_t *message, size_t length, const uint8_t signature[64])
{
    uint8_t expected[64];
    sign_frame(message, length, expected);
    return memcmp(x, ROOT.public_x, 32) == 0 &&
        memcmp(y, ROOT.public_y, 32) == 0 && memcmp(signature, expected, 64) == 0;
}

bool passport_sha256(const uint8_t *message, size_t length, uint8_t output[32])
{
    hash_calls++;
    if (fail_hash || length != sizeof(hash_input)) return false;
    memcpy(hash_input, message, length);
    for (size_t index = 0; index < 32; index++) output[index] = (uint8_t)index;
    return true;
}

typedef struct {
    uint8_t bytes[2][PASSPORT_TRUST_RECORD_MAX];
    size_t lengths[2];
    bool present[2];
    unsigned writes;
    unsigned fail_write;
} memory_t;

static passport_store_result_t read_slot(void *context, size_t slot,
    uint8_t *output, size_t capacity, size_t *length)
{
    memory_t *memory = context;
    if (slot >= 2 || memory->lengths[slot] > capacity) return PASSPORT_STORE_ERROR;
    if (!memory->present[slot]) return PASSPORT_STORE_NOT_FOUND;
    memcpy(output, memory->bytes[slot], memory->lengths[slot]);
    *length = memory->lengths[slot];
    return PASSPORT_STORE_OK;
}

static bool write_slot(void *context, size_t slot, const uint8_t *bytes, size_t length)
{
    memory_t *memory = context;
    memory->writes++;
    if (slot >= 2 || length > PASSPORT_TRUST_RECORD_MAX ||
        memory->writes == memory->fail_write) return false;
    memcpy(memory->bytes[slot], bytes, length);
    memory->lengths[slot] = length;
    memory->present[slot] = true;
    return true;
}

static passport_outbox_store_t store_for(memory_t *memory)
{
    return (passport_outbox_store_t) { memory, read_slot, write_slot };
}

static void setup(memory_t *memory, passport_trust_t *trust)
{
    memset(memory, 0, sizeof(*memory));
    passport_outbox_store_t storage = store_for(memory);
    assert(passport_trust_open(trust, &storage, &ROOT) == PASSPORT_TRUST_EMPTY);
    fail_hash = false;
}

static passport_trust_manifest_t candidate(uint32_t epoch)
{
    passport_trust_manifest_t result = { .community_id = "synthetic-community",
        .epoch = epoch, .state = PASSPORT_TRUST_ACTIVE,
        .service_public_x = { 0x33 }, .service_public_y = { 0x44 } };
    return result;
}

static void signature_for(const passport_trust_manifest_t *value, uint8_t signature[64])
{
    uint8_t frame[PASSPORT_TRUST_FRAME_MAX];
    size_t length = 0;
    assert(passport_trust_encode(value, frame, sizeof(frame), &length) == PASSPORT_TRUST_OK);
    sign_frame(frame, length, signature);
}

static void begin(passport_provision_t *p, passport_trust_t *trust, uint32_t epoch, uint64_t now)
{
    passport_trust_manifest_t value = candidate(epoch);
    uint8_t signature[64];
    signature_for(&value, signature);
    assert(passport_provision_begin_local(p, trust, &value, signature,
        PASSPORT_PROVISION_APPLY, NULL, now, 10000) == PASSPORT_PROVISION_OK);
    assert(p->view.state == PASSPORT_PROVISION_FINGERPRINT);
}

static void review(passport_provision_t *p, uint64_t now)
{
    assert(passport_provision_sample(p, 0, now - 1) == PASSPORT_PROVISION_NO_CHANGE);
    assert(passport_provision_sample(p, 1, now) == PASSPORT_PROVISION_NO_CHANGE);
    assert(passport_provision_sample(p, 0, now + 1) == PASSPORT_PROVISION_OK);
    assert(p->view.state == PASSPORT_PROVISION_REVIEW);
}

static void hold(passport_provision_t *p, uint64_t now)
{
    (void)passport_provision_sample(p, 0, now - 1);
    assert(passport_provision_sample(p, 1, now) == PASSPORT_PROVISION_OK);
    assert(p->view.state == PASSPORT_PROVISION_HOLDING);
}

static passport_provision_result_t finish_hold(passport_provision_t *p)
{
    const uint64_t start = p->hold_started_ms;
    for (uint64_t offset = 200; offset < PASSPORT_PROVISION_HOLD_MS; offset += 200)
        assert(passport_provision_sample(p, 1, start + offset) == PASSPORT_PROVISION_NO_CHANGE);
    return passport_provision_sample(p, 1, start + PASSPORT_PROVISION_HOLD_MS);
}

static void test_complete_once_and_fingerprint(void)
{
    memory_t memory;
    passport_trust_t trust;
    setup(&memory, &trust);
    passport_provision_t p;
    passport_provision_init(&p);
    assert(p.view.state == PASSPORT_PROVISION_IDLE);
    assert(passport_provision_tick(&p, 0) == PASSPORT_PROVISION_NO_CHANGE);
    begin(&p, &trust, 1, 100);
    passport_provision_view_t view;
    passport_provision_get_view(&p, &view);
    assert(strcmp(view.root_fingerprint,
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f") == 0);
    assert(hash_calls > 0 && hash_input[0] == 4 &&
        memcmp(hash_input + 1, ROOT.public_x, 32) == 0 &&
        memcmp(hash_input + 33, ROOT.public_y, 32) == 0);
    assert(strcmp(view.community_id, ROOT.community_id) == 0 && view.epoch == 1 &&
        view.requested_state == PASSPORT_TRUST_ACTIVE);
    assert(memory.writes == 0);
    /* Initial held key cannot stand in for a fresh local press/release. */
    assert(passport_provision_sample(&p, 1, 110) == PASSPORT_PROVISION_NO_CHANGE);
    assert(passport_provision_tick(&p, 4110) == PASSPORT_PROVISION_NO_CHANGE);
    assert(memory.writes == 0 && p.view.state == PASSPORT_PROVISION_FINGERPRINT);
    assert(passport_provision_sample(&p, 0, 4111) == PASSPORT_PROVISION_NO_CHANGE);
    review(&p, 4200);
    assert(passport_provision_tick(&p, 4300) == PASSPORT_PROVISION_NO_CHANGE);
    hold(&p, 4400);
    assert(finish_hold(&p) == PASSPORT_PROVISION_APPLIED);
    assert(p.view.state == PASSPORT_PROVISION_COMPLETE && trust.state == PASSPORT_TRUST_ACTIVE);
    const unsigned writes = memory.writes;
    assert(passport_provision_tick(&p, 8300) == PASSPORT_PROVISION_NO_CHANGE);
    assert(passport_provision_sample(&p, 0, 8301) == PASSPORT_PROVISION_NO_CHANGE);
    assert(memory.writes == writes);
}

static void test_early_release_and_wrong_key(void)
{
    memory_t memory;
    passport_trust_t trust;
    setup(&memory, &trust);
    passport_provision_t p;
    begin(&p, &trust, 1, 0);
    assert(passport_provision_sample(&p, 0, 1) == PASSPORT_PROVISION_NO_CHANGE);
    assert(p.view.state == PASSPORT_PROVISION_FINGERPRINT);
    review(&p, 2);
    hold(&p, 10);
    assert(passport_provision_sample(&p, 0, 2009) == PASSPORT_PROVISION_NO_CHANGE);
    assert(memory.writes == 0 && p.view.state == PASSPORT_PROVISION_REVIEW);
    hold(&p, 2010);
    assert(passport_provision_sample(&p, 1, 2020) == PASSPORT_PROVISION_NO_CHANGE);
    assert(passport_provision_local_input(&p, PASSPORT_PROVISION_OTHER_DOWN, 4010) == PASSPORT_PROVISION_WAS_CANCELLED);
    assert(passport_provision_tick(&p, 4011) == PASSPORT_PROVISION_NO_CHANGE && memory.writes == 0);
    begin(&p, &trust, 1, 5000);
    assert(passport_provision_local_input(&p, PASSPORT_PROVISION_CANCEL, 5001) == PASSPORT_PROVISION_WAS_CANCELLED);
    assert(memory.writes == 0);
    begin(&p, &trust, 1, 6000);
    review(&p, 6001);
    hold(&p, 6010);
    assert(finish_hold(&p) == PASSPORT_PROVISION_APPLIED);
}

static void test_preflight_and_candidate_updates(void)
{
    memory_t memory;
    passport_trust_t trust;
    setup(&memory, &trust);
    passport_provision_t p;
    passport_trust_manifest_t value = candidate(1);
    uint8_t signature[64];
    signature_for(&value, signature);
    signature[0] ^= 1;
    assert(passport_provision_begin_local(&p, &trust, &value, signature,
        PASSPORT_PROVISION_APPLY, NULL, 0, 10000) == PASSPORT_PROVISION_UNTRUSTED);
    assert(memory.writes == 0 && trust.state == PASSPORT_TRUST_UNPROVISIONED);
    strcpy(value.community_id, "another-community");
    signature_for(&value, signature);
    assert(passport_provision_begin_local(&p, &trust, &value, signature,
        PASSPORT_PROVISION_APPLY, NULL, 0, 10000) == PASSPORT_PROVISION_UNTRUSTED);
    value = candidate(1);
    memcpy(value.service_public_x, ROOT.public_x, 32);
    memcpy(value.service_public_y, ROOT.public_y, 32);
    signature_for(&value, signature);
    assert(passport_provision_begin_local(&p, &trust, &value, signature,
        PASSPORT_PROVISION_APPLY, NULL, 0, 10000) == PASSPORT_PROVISION_UNTRUSTED);
    assert(memory.writes == 0);
    value = candidate(1);
    signature_for(&value, signature);
    fail_hash = true;
    assert(passport_provision_begin_local(&p, &trust, &value, signature,
        PASSPORT_PROVISION_APPLY, NULL, 0, 10000) == PASSPORT_PROVISION_UNTRUSTED);
    fail_hash = false;
    begin(&p, &trust, 1, 0);
    review(&p, 1);
    hold(&p, 10);
    assert(passport_provision_sync_candidate(&p, &value, signature, 1000) == PASSPORT_PROVISION_NO_CHANGE);
    assert(p.view.state == PASSPORT_PROVISION_HOLDING && memory.writes == 0);
    value.epoch = 2;
    signature_for(&value, signature);
    assert(passport_provision_sync_candidate(&p, &value, signature, 2010) == PASSPORT_PROVISION_WAS_STALE);
    assert(memory.writes == 0);
    begin(&p, &trust, 1, 3000);
    trust.root.public_x[0] ^= 1;
    assert(passport_provision_tick(&p, 3001) == PASSPORT_PROVISION_WAS_STALE);
    assert(memory.writes == 0);
    trust.root = ROOT;
    begin(&p, &trust, 1, 4000);
    review(&p, 4001);
    hold(&p, 4010);
    /* Explicitly restarting even the identical proposal loses its old hold. */
    assert(passport_provision_begin_local(&p, &trust, &p.candidate, p.root_signature,
        PASSPORT_PROVISION_APPLY, NULL, 5000, 10000) == PASSPORT_PROVISION_OK);
    assert(passport_provision_tick(&p, 6010) == PASSPORT_PROVISION_NO_CHANGE);
    assert(p.view.state == PASSPORT_PROVISION_FINGERPRINT && memory.writes == 0);
    value = candidate(1);
    signature_for(&value, signature);
    signature[63] ^= 1;
    assert(passport_provision_sync_candidate(&p, &value, signature, 6011) == PASSPORT_PROVISION_WAS_STALE);
    assert(memory.writes == 0);
}

static void test_time_and_overflow(void)
{
    memory_t memory;
    passport_trust_t trust;
    setup(&memory, &trust);
    passport_provision_t p;
    begin(&p, &trust, 1, 0);
    review(&p, 1);
    hold(&p, 8000);
    /* At the global expiry boundary, timeout wins over a completed hold. */
    assert(passport_provision_tick(&p, 10000) == PASSPORT_PROVISION_TIMED_OUT);
    assert(memory.writes == 0);
    begin(&p, &trust, 1, 100);
    assert(passport_provision_tick(&p, 99) == PASSPORT_PROVISION_TIMED_OUT);
    begin(&p, &trust, 1, UINT64_MAX - 5000);
    review(&p, UINT64_MAX - 4999);
    hold(&p, UINT64_MAX - 4000);
    assert(finish_hold(&p) == PASSPORT_PROVISION_APPLIED);
    begin(&p, &trust, 2, UINT64_MAX - 1000);
    assert(passport_provision_tick(&p, 0) == PASSPORT_PROVISION_TIMED_OUT);
    assert(trust.manifest.epoch == 1);
}

static void test_failed_store_and_recovery(void)
{
    memory_t memory;
    passport_trust_t trust;
    setup(&memory, &trust);
    passport_provision_t p;
    begin(&p, &trust, 1, 0);
    review(&p, 1);
    hold(&p, 10);
    memory.fail_write = 2;
    assert(finish_hold(&p) == PASSPORT_PROVISION_TRUST_ERROR);
    assert(p.view.state == PASSPORT_PROVISION_FAILED &&
        p.view.trust_result == PASSPORT_TRUST_IO_ERROR && trust.state == PASSPORT_TRUST_LOCKED);
    const unsigned writes = memory.writes;
    memory.fail_write = 0;
    assert(passport_provision_tick(&p, 3000) == PASSPORT_PROVISION_NO_CHANGE && memory.writes == writes);
    passport_trust_manifest_t value = candidate(2);
    uint8_t signature[64];
    signature_for(&value, signature);
    assert(passport_provision_begin_local(&p, &trust, &value, signature,
        PASSPORT_PROVISION_RECOVER, NULL, 4000, 10000) == PASSPORT_PROVISION_BAD_ARGUMENT);
    uint32_t floor = 2;
    assert(passport_provision_begin_local(&p, &trust, &value, signature,
        PASSPORT_PROVISION_RECOVER, &floor, 4000, 10000) == PASSPORT_PROVISION_TRUST_ERROR);
    assert(memory.writes == writes);
    floor = 1;
    assert(passport_provision_begin_local(&p, &trust, &value, signature,
        PASSPORT_PROVISION_RECOVER, &floor, 4000, 10000) == PASSPORT_PROVISION_OK);
    assert(p.view.authoritative_minimum_epoch == 1 && p.view.mode == PASSPORT_PROVISION_RECOVER);
    review(&p, 4001);
    hold(&p, 4010);
    assert(finish_hold(&p) == PASSPORT_PROVISION_APPLIED);
    assert(trust.state == PASSPORT_TRUST_ACTIVE && trust.manifest.epoch == 2);
    value.epoch = 1;
    signature_for(&value, signature);
    assert(passport_provision_begin_local(&p, &trust, &value, signature,
        PASSPORT_PROVISION_APPLY, NULL, 7000, 10000) == PASSPORT_PROVISION_TRUST_ERROR);
    assert(p.view.trust_result == PASSPORT_TRUST_REPLAY);
}

static void test_stop_and_changed_trust_during_review(void)
{
    memory_t memory;
    passport_trust_t trust;
    setup(&memory, &trust);
    passport_provision_t p;
    begin(&p, &trust, 1, 0);
    review(&p, 1);
    hold(&p, 10);
    /* Another serialized maintenance action makes this reviewed version old.
     * A completed hold must be consumed without replacing the newer setting. */
    passport_trust_manifest_t next = candidate(2);
    uint8_t signature[64];
    signature_for(&next, signature);
    assert(passport_trust_apply(&trust, &next, signature, true) == PASSPORT_TRUST_OK);
    const unsigned before = memory.writes;
    assert(finish_hold(&p) == PASSPORT_PROVISION_TRUST_ERROR);
    assert(p.view.trust_result == PASSPORT_TRUST_REPLAY && memory.writes == before);
    assert(passport_provision_tick(&p, 2011) == PASSPORT_PROVISION_NO_CHANGE);
    next = candidate(3);
    next.state = PASSPORT_TRUST_SUSPENDED;
    memset(next.service_public_x, 0, sizeof(next.service_public_x));
    memset(next.service_public_y, 0, sizeof(next.service_public_y));
    signature_for(&next, signature);
    assert(passport_provision_begin_local(&p, &trust, &next, signature,
        PASSPORT_PROVISION_APPLY, NULL, 3000, 10000) == PASSPORT_PROVISION_OK);
    assert(p.view.requested_state == PASSPORT_TRUST_SUSPENDED);
    review(&p, 3001);
    hold(&p, 3010);
    assert(finish_hold(&p) == PASSPORT_PROVISION_APPLIED);
    assert(trust.state == PASSPORT_TRUST_SUSPENDED && trust.manifest.epoch == 3);
}

static void test_timer_cannot_prove_contact(void)
{
    memory_t memory;
    passport_trust_t trust;
    setup(&memory, &trust);
    passport_provision_t p;
    begin(&p, &trust, 1, 0);
    review(&p, 1);
    hold(&p, 10);
    assert(passport_provision_tick(&p, 2010) != PASSPORT_PROVISION_APPLIED);
    assert(memory.writes == 0);
}

static void test_sampling_boundaries_and_nonphysical_updates(void)
{
    for (unsigned gap = 250; gap <= 251; ++gap) {
        memory_t memory;
        passport_trust_t trust;
        setup(&memory, &trust);
        passport_provision_t p;
        begin(&p, &trust, 1, 0);
        review(&p, 1);
        hold(&p, 10);
        passport_trust_manifest_t value = candidate(1);
        uint8_t signature[64];
        signature_for(&value, signature);
        /* Neither timer nor an unchanged candidate refresh is a key sample. */
        assert(passport_provision_tick(&p, 200) == PASSPORT_PROVISION_NO_CHANGE);
        assert(passport_provision_sync_candidate(&p, &value, signature, 259) == PASSPORT_PROVISION_NO_CHANGE);
        assert(passport_provision_sample(&p, 1, 10 + gap) == PASSPORT_PROVISION_NO_CHANGE);
        if (gap == 250) {
            for (uint64_t now = 510; now <= 2010; now += 250) {
                passport_provision_result_t result = passport_provision_sample(&p, 1, now);
                assert(result == (now == 2010 ? PASSPORT_PROVISION_APPLIED : PASSPORT_PROVISION_NO_CHANGE));
            }
            assert(memory.writes == 2);
        } else {
            for (uint64_t now = 511; now <= 2261; now += 250)
                assert(passport_provision_sample(&p, 1, now) == PASSPORT_PROVISION_NO_CHANGE);
            assert(memory.writes == 0 && p.view.state == PASSPORT_PROVISION_REVIEW);
            hold(&p, 2300); /* explicitly release, then press afresh */
            assert(finish_hold(&p) == PASSPORT_PROVISION_APPLIED);
        }
    }
}

static void test_release_and_legacy_edges_do_not_apply(void)
{
    memory_t memory;
    passport_trust_t trust;
    setup(&memory, &trust);
    passport_provision_t p;
    begin(&p, &trust, 1, 0);
    review(&p, 1);
    hold(&p, 10);
    for (uint64_t now = 210; now < 2010; now += 200)
        assert(passport_provision_sample(&p, 1, now) == PASSPORT_PROVISION_NO_CHANGE);
    assert(passport_provision_sample(&p, 0, 2010) == PASSPORT_PROVISION_OK);
    assert(passport_provision_tick(&p, 2011) == PASSPORT_PROVISION_NO_CHANGE);
    assert(memory.writes == 0);
    hold(&p, 2020);
    assert(passport_provision_sample(&p, 3, 2021) == PASSPORT_PROVISION_WAS_CANCELLED);
    assert(memory.writes == 0);
    begin(&p, &trust, 1, 3000);
    assert(passport_provision_local_input(&p, PASSPORT_PROVISION_OK_DOWN, 3001) == PASSPORT_PROVISION_BAD_ARGUMENT);
    assert(p.view.state == PASSPORT_PROVISION_CANCELLED && memory.writes == 0);
}

int main(void)
{
    test_sampling_boundaries_and_nonphysical_updates();
    test_release_and_legacy_edges_do_not_apply();
    test_timer_cannot_prove_contact();
    test_complete_once_and_fingerprint();
    test_early_release_and_wrong_key();
    test_preflight_and_candidate_updates();
    test_time_and_overflow();
    test_failed_store_and_recovery();
    test_stop_and_changed_trust_during_review();
    return 0;
}
