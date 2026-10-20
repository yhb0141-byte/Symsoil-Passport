#include <assert.h>
#include <string.h>

#include "passport_trust.h"

static const passport_trust_root_t ROOT = {
    .community_id = "synthetic-community",
    .public_x = { 0x11 },
    .public_y = { 0x22 },
};

/* Non-cryptographic host double. Real P-256 interoperability is tested
 * separately; this suite only injects persistence and state-machine faults. */
static void sign_frame(const uint8_t *message, size_t length, uint8_t signature[64])
{
    uint32_t checksum = passport_crc32(message, length);
    for (size_t index = 0; index < 64; index++) {
        signature[index] = (uint8_t)(checksum >> ((index % 4) * 8)) ^ (uint8_t)index;
    }
}

bool passport_p256_verify_p1363(
    const uint8_t public_x[32], const uint8_t public_y[32],
    const uint8_t *message, size_t length, const uint8_t signature[64])
{
    uint8_t expected[64];
    sign_frame(message, length, expected);
    return memcmp(public_x, ROOT.public_x, 32) == 0 &&
           memcmp(public_y, ROOT.public_y, 32) == 0 &&
           memcmp(signature, expected, 64) == 0;
}

typedef struct {
    uint8_t data[2][PASSPORT_TRUST_RECORD_MAX];
    size_t length[2];
    bool present[2];
    bool fail_read;
    size_t writes;
    size_t fail_on_write;
    bool corrupt_write;
} memory_t;

static passport_store_result_t read_slot(
    void *context, size_t slot, uint8_t *output, size_t capacity, size_t *length)
{
    memory_t *memory = context;
    if (slot >= 2 || memory->fail_read) return PASSPORT_STORE_ERROR;
    if (!memory->present[slot]) return PASSPORT_STORE_NOT_FOUND;
    if (memory->length[slot] > capacity) return PASSPORT_STORE_ERROR;
    memcpy(output, memory->data[slot], memory->length[slot]);
    *length = memory->length[slot];
    return PASSPORT_STORE_OK;
}

static bool write_slot(void *context, size_t slot, const uint8_t *data, size_t length)
{
    memory_t *memory = context;
    memory->writes++;
    if (slot >= 2 || length > PASSPORT_TRUST_RECORD_MAX || memory->writes == memory->fail_on_write) return false;
    memcpy(memory->data[slot], data, length);
    if (memory->corrupt_write) memory->data[slot][0] ^= 1;
    memory->length[slot] = length;
    memory->present[slot] = true;
    return true;
}

static passport_outbox_store_t store_for(memory_t *memory)
{
    return (passport_outbox_store_t) { .context = memory, .read = read_slot, .write = write_slot };
}

static passport_trust_manifest_t manifest(uint32_t epoch, passport_trust_state_t state)
{
    passport_trust_manifest_t result = { .epoch = epoch, .state = state };
    memcpy(result.community_id, ROOT.community_id, sizeof(ROOT.community_id));
    if (state == PASSPORT_TRUST_ACTIVE) {
        result.service_public_x[0] = (uint8_t)(epoch | 0x80);
        result.service_public_y[0] = 0x44;
    }
    return result;
}

static void signature_for(const passport_trust_manifest_t *value, uint8_t signature[64])
{
    uint8_t frame[PASSPORT_TRUST_FRAME_MAX];
    size_t length = 0;
    assert(passport_trust_encode(value, frame, sizeof(frame), &length) == PASSPORT_TRUST_OK);
    sign_frame(frame, length, signature);
}

static passport_trust_result_t apply(passport_trust_t *trust, uint32_t epoch, passport_trust_state_t state)
{
    passport_trust_manifest_t next = manifest(epoch, state);
    uint8_t signature[64];
    signature_for(&next, signature);
    return passport_trust_apply(trust, &next, signature, true);
}

static passport_trust_result_t recover(passport_trust_t *trust, uint32_t epoch, uint32_t floor, bool confirmed)
{
    passport_trust_manifest_t next = manifest(epoch, PASSPORT_TRUST_ACTIVE);
    uint8_t signature[64];
    signature_for(&next, signature);
    return passport_trust_recover(trust, &next, signature, confirmed, floor);
}

static void assert_selection(passport_trust_t *trust, passport_trust_result_t expected, uint32_t wanted_epoch)
{
    uint8_t x[32], y[32];
    memset(x, 0xff, sizeof(x));
    memset(y, 0xff, sizeof(y));
    uint32_t epoch = UINT32_MAX;
    assert(passport_trust_get_service(trust, ROOT.community_id, x, y, &epoch) == expected);
    if (expected == PASSPORT_TRUST_OK) {
        const passport_trust_manifest_t wanted = manifest(wanted_epoch, PASSPORT_TRUST_ACTIVE);
        assert(epoch == wanted_epoch && memcmp(x, wanted.service_public_x, 32) == 0 &&
               memcmp(y, wanted.service_public_y, 32) == 0);
    } else {
        static const uint8_t ZERO[32] = { 0 };
        assert(epoch == 0 && memcmp(x, ZERO, 32) == 0 && memcmp(y, ZERO, 32) == 0);
    }
}

static void initialize(memory_t *memory, passport_trust_t *trust)
{
    passport_outbox_store_t store = store_for(memory);
    assert(passport_trust_open(trust, &store, &ROOT) == PASSPORT_TRUST_EMPTY);
    assert_selection(trust, PASSPORT_TRUST_EMPTY, 0);
}

static void test_encoding(void)
{
    passport_trust_manifest_t next = manifest(UINT32_C(0x12345678), PASSPORT_TRUST_ACTIVE);
    uint8_t bytes[PASSPORT_TRUST_FRAME_MAX];
    size_t length = 0;
    assert(passport_trust_encode(&next, bytes, sizeof(bytes), &length) == PASSPORT_TRUST_OK);
    assert(memcmp(bytes, "symsoil-trust/1", 16) == 0);
    assert(bytes[16] == 1 && bytes[17] == strlen(next.community_id) && bytes[18] == 0 && bytes[19] == 0);
    assert(bytes[20] == 0x78 && bytes[21] == 0x56 && bytes[22] == 0x34 && bytes[23] == 0x12);
    assert(length == 88 + strlen(next.community_id));
    next.epoch = 0;
    assert(passport_trust_encode(&next, bytes, sizeof(bytes), &length) == PASSPORT_TRUST_BAD_DATA);
    next.epoch = 1;
    next.state = PASSPORT_TRUST_LOCKED;
    assert(passport_trust_encode(&next, bytes, sizeof(bytes), &length) == PASSPORT_TRUST_BAD_DATA);
    next = manifest(1, PASSPORT_TRUST_SUSPENDED);
    next.service_public_x[0] = 1;
    assert(passport_trust_encode(&next, bytes, sizeof(bytes), &length) == PASSPORT_TRUST_BAD_DATA);
    next = manifest(1, PASSPORT_TRUST_ACTIVE);
    strcpy(next.community_id, "invalid community");
    assert(passport_trust_encode(&next, bytes, sizeof(bytes), &length) == PASSPORT_TRUST_BAD_DATA);
    strcpy(next.community_id, "a:b_c-0");
    assert(passport_trust_encode(&next, bytes, sizeof(bytes), &length) == PASSPORT_TRUST_OK);
    memset(next.community_id, 'a', sizeof(next.community_id));
    assert(passport_trust_encode(&next, bytes, sizeof(bytes), &length) == PASSPORT_TRUST_BAD_DATA);
}

static void test_lifecycle(void)
{
    memory_t memory = { 0 };
    passport_trust_t trust;
    initialize(&memory, &trust);
    passport_trust_manifest_t next = manifest(1, PASSPORT_TRUST_ACTIVE);
    uint8_t signature[64];
    signature_for(&next, signature);
    assert(passport_trust_apply(&trust, &next, signature, false) == PASSPORT_TRUST_LOCAL_CONFIRMATION_REQUIRED);
    assert(memory.writes == 0);
    assert(passport_trust_apply(&trust, &next, signature, true) == PASSPORT_TRUST_OK);
    assert_selection(&trust, PASSPORT_TRUST_OK, 1);
    assert(apply(&trust, 1, PASSPORT_TRUST_ACTIVE) == PASSPORT_TRUST_REPLAY);
    assert(apply(&trust, 2, PASSPORT_TRUST_ACTIVE) == PASSPORT_TRUST_OK);
    assert_selection(&trust, PASSPORT_TRUST_OK, 2);
    assert(apply(&trust, 3, PASSPORT_TRUST_SUSPENDED) == PASSPORT_TRUST_OK);
    assert_selection(&trust, PASSPORT_TRUST_IS_SUSPENDED, 0);
    assert(apply(&trust, 2, PASSPORT_TRUST_ACTIVE) == PASSPORT_TRUST_REPLAY);
    assert(apply(&trust, 4, PASSPORT_TRUST_ACTIVE) == PASSPORT_TRUST_OK);
    assert_selection(&trust, PASSPORT_TRUST_OK, 4);
    passport_trust_t reopened;
    passport_outbox_store_t store = store_for(&memory);
    assert(passport_trust_open(&reopened, &store, &ROOT) == PASSPORT_TRUST_OK);
    assert_selection(&reopened, PASSPORT_TRUST_OK, 4);
}

static void test_untrusted_inputs(void)
{
    memory_t memory = { 0 };
    passport_trust_t trust;
    initialize(&memory, &trust);
    assert(apply(&trust, 1, PASSPORT_TRUST_ACTIVE) == PASSPORT_TRUST_OK);
    const size_t writes = memory.writes;
    passport_trust_manifest_t next = manifest(2, PASSPORT_TRUST_ACTIVE);
    uint8_t signature[64];
    signature_for(&next, signature);
    signature[0] ^= 1;
    assert(passport_trust_apply(&trust, &next, signature, false) == PASSPORT_TRUST_UNTRUSTED);
    signature_for(&next, signature);
    next.epoch = 3;
    assert(passport_trust_apply(&trust, &next, signature, false) == PASSPORT_TRUST_UNTRUSTED);
    strcpy(next.community_id, "other-community");
    signature_for(&next, signature);
    assert(passport_trust_apply(&trust, &next, signature, false) == PASSPORT_TRUST_UNTRUSTED);
    next = manifest(2, PASSPORT_TRUST_ACTIVE);
    memcpy(next.service_public_x, ROOT.public_x, 32);
    memcpy(next.service_public_y, ROOT.public_y, 32);
    signature_for(&next, signature);
    assert(passport_trust_apply(&trust, &next, signature, false) == PASSPORT_TRUST_UNTRUSTED);
    uint8_t x[32], y[32];
    uint32_t epoch;
    assert(passport_trust_get_service(&trust, "other-community", x, y, &epoch) == PASSPORT_TRUST_UNTRUSTED);
    assert(memory.writes == writes);
    assert_selection(&trust, PASSPORT_TRUST_OK, 1);
    passport_trust_root_t wrong = ROOT;
    wrong.public_x[0] ^= 1;
    passport_outbox_store_t store = store_for(&memory);
    assert(passport_trust_open(&trust, &store, &wrong) == PASSPORT_TRUST_IS_LOCKED);
    assert_selection(&trust, PASSPORT_TRUST_IS_LOCKED, 0);
}

static void test_mirror_failure_and_recovery(void)
{
    memory_t memory = { 0 };
    passport_trust_t trust;
    initialize(&memory, &trust);
    assert(apply(&trust, 1, PASSPORT_TRUST_ACTIVE) == PASSPORT_TRUST_OK);
    memory.fail_on_write = memory.writes + 2;
    assert(apply(&trust, 2, PASSPORT_TRUST_SUSPENDED) == PASSPORT_TRUST_IO_ERROR);
    assert_selection(&trust, PASSPORT_TRUST_IS_LOCKED, 0);
    assert(apply(&trust, 3, PASSPORT_TRUST_ACTIVE) == PASSPORT_TRUST_IS_LOCKED);
    passport_outbox_store_t store = store_for(&memory);
    assert(passport_trust_open(&trust, &store, &ROOT) == PASSPORT_TRUST_IS_LOCKED);
    assert(trust.observed_epoch == 2);
    assert(recover(&trust, 3, 2, false) == PASSPORT_TRUST_LOCAL_CONFIRMATION_REQUIRED);
    assert(recover(&trust, 2, 2, true) == PASSPORT_TRUST_REPLAY);
    assert(recover(&trust, 3, 7, true) == PASSPORT_TRUST_REPLAY);
    assert_selection(&trust, PASSPORT_TRUST_IS_LOCKED, 0);
    assert(recover(&trust, 8, 7, true) == PASSPORT_TRUST_OK);
    assert_selection(&trust, PASSPORT_TRUST_OK, 8);
}

static void test_corrupt_and_missing(void)
{
    memory_t memory = { 0 };
    passport_trust_t trust;
    initialize(&memory, &trust);
    assert(apply(&trust, 1, PASSPORT_TRUST_ACTIVE) == PASSPORT_TRUST_OK);
    memory.data[0][0] ^= 1;
    assert_selection(&trust, PASSPORT_TRUST_IS_LOCKED, 0);
    assert(recover(&trust, 2, 1, true) == PASSPORT_TRUST_OK);
    memory.present[1] = false;
    assert_selection(&trust, PASSPORT_TRUST_IS_LOCKED, 0);
    assert(recover(&trust, 3, 2, true) == PASSPORT_TRUST_OK);
    memory.length[0] = 3;
    memory.length[1] = 3;
    passport_outbox_store_t store = store_for(&memory);
    assert(passport_trust_open(&trust, &store, &ROOT) == PASSPORT_TRUST_IS_LOCKED);
    assert(trust.observed_epoch == 0);
    assert(recover(&trust, 3, 3, true) == PASSPORT_TRUST_REPLAY);
    assert(recover(&trust, 4, 3, true) == PASSPORT_TRUST_OK);
    memory.fail_read = true;
    assert_selection(&trust, PASSPORT_TRUST_IO_ERROR, 0);
    memory.fail_read = false;
    assert_selection(&trust, PASSPORT_TRUST_IS_LOCKED, 0);
}

static void test_persistent_tamper_and_stale_owner(void)
{
    memory_t memory = { 0 };
    passport_trust_t first, second;
    initialize(&memory, &first);
    assert(apply(&first, 1, PASSPORT_TRUST_ACTIVE) == PASSPORT_TRUST_OK);
    passport_outbox_store_t store = store_for(&memory);
    assert(passport_trust_open(&second, &store, &ROOT) == PASSPORT_TRUST_OK);
    assert(apply(&first, 3, PASSPORT_TRUST_ACTIVE) == PASSPORT_TRUST_OK);
    assert(apply(&second, 2, PASSPORT_TRUST_ACTIVE) == PASSPORT_TRUST_REPLAY);
    assert_selection(&second, PASSPORT_TRUST_OK, 3);
    /* A valid CRC must not make a forged stored signature trusted. */
    const size_t signature_offset = memory.length[0] - 68;
    memory.data[0][signature_offset] ^= 1;
    const uint32_t crc = passport_crc32(memory.data[0], memory.length[0] - 4);
    for (unsigned index = 0; index < 4; index++) memory.data[0][memory.length[0] - 4 + index] = (uint8_t)(crc >> (index * 8));
    assert_selection(&second, PASSPORT_TRUST_IS_LOCKED, 0);
    assert(recover(&second, 4, 3, true) == PASSPORT_TRUST_OK);
    memory_t old_memory = memory;
    assert(apply(&second, 5, PASSPORT_TRUST_SUSPENDED) == PASSPORT_TRUST_OK);
    memory = old_memory; /* In-session rollback is detected by cached epoch floor. */
    assert_selection(&second, PASSPORT_TRUST_IS_LOCKED, 0);
}

static void test_write_faults_and_epoch_exhaustion(void)
{
    memory_t memory = { 0 };
    passport_trust_t trust;
    initialize(&memory, &trust);
    memory.corrupt_write = true;
    assert(apply(&trust, 1, PASSPORT_TRUST_ACTIVE) == PASSPORT_TRUST_IO_ERROR);
    assert_selection(&trust, PASSPORT_TRUST_IS_LOCKED, 0);
    memory.corrupt_write = false;
    assert(recover(&trust, 2, 1, true) == PASSPORT_TRUST_OK);
    memory.fail_on_write = memory.writes + 1;
    assert(apply(&trust, 3, PASSPORT_TRUST_ACTIVE) == PASSPORT_TRUST_IO_ERROR);
    assert_selection(&trust, PASSPORT_TRUST_IS_LOCKED, 0);
    assert(recover(&trust, UINT32_MAX, 3, true) == PASSPORT_TRUST_OK);
    assert(apply(&trust, 1, PASSPORT_TRUST_ACTIVE) == PASSPORT_TRUST_REPLAY);
    assert(apply(&trust, UINT32_MAX, PASSPORT_TRUST_ACTIVE) == PASSPORT_TRUST_REPLAY);
}

int main(void)
{
    test_encoding();
    test_lifecycle();
    test_untrusted_inputs();
    test_mirror_failure_and_recovery();
    test_corrupt_and_missing();
    test_persistent_tamper_and_stale_owner();
    test_write_faults_and_epoch_exhaustion();
    return 0;
}
