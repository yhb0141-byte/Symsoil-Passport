#include "passport_trust.h"

#include <string.h>

static const uint8_t DOMAIN[16] = "symsoil-trust/1";
#define FRAME_HEADER 24
#define RECORD_TRAILER (PASSPORT_P256_P1363_SIZE + 4)

typedef struct {
    bool present;
    bool valid;
    bool io_error;
    size_t length;
    uint8_t bytes[PASSPORT_TRUST_RECORD_MAX];
    passport_trust_manifest_t manifest;
} trust_slot_t;

static uint32_t get_u32(const uint8_t *input)
{
    return (uint32_t)input[0] | ((uint32_t)input[1] << 8) |
           ((uint32_t)input[2] << 16) | ((uint32_t)input[3] << 24);
}

static void put_u32(uint8_t *output, uint32_t value)
{
    output[0] = (uint8_t)value;
    output[1] = (uint8_t)(value >> 8);
    output[2] = (uint8_t)(value >> 16);
    output[3] = (uint8_t)(value >> 24);
}

static size_t community_length(const char *text)
{
    if (!text) return 0;
    for (size_t index = 0; index <= PASSPORT_TRUST_COMMUNITY_MAX; index++) {
        const unsigned char value = (unsigned char)text[index];
        if (!value) return index;
        if (!((value >= 'a' && value <= 'z') ||
              (value >= 'A' && value <= 'Z') ||
              (value >= '0' && value <= '9') || value == '-' ||
              value == '_' || value == ':')) return 0;
    }
    return 0;
}

static bool all_zero(const uint8_t *bytes, size_t length)
{
    uint8_t combined = 0;
    for (size_t index = 0; index < length; index++) combined |= bytes[index];
    return combined == 0;
}

passport_trust_result_t passport_trust_encode(
    const passport_trust_manifest_t *manifest,
    uint8_t *output, size_t capacity, size_t *length)
{
    if (length) *length = 0;
    if (!manifest || !output || !length) return PASSPORT_TRUST_BAD_ARGUMENT;
    const size_t id_length = community_length(manifest->community_id);
    if (!id_length || !manifest->epoch ||
        (manifest->state != PASSPORT_TRUST_ACTIVE &&
         manifest->state != PASSPORT_TRUST_SUSPENDED)) return PASSPORT_TRUST_BAD_DATA;
    const bool x_zero = all_zero(manifest->service_public_x, PASSPORT_P256_COORD_SIZE);
    const bool y_zero = all_zero(manifest->service_public_y, PASSPORT_P256_COORD_SIZE);
    if ((manifest->state == PASSPORT_TRUST_ACTIVE && (x_zero || y_zero)) ||
        (manifest->state == PASSPORT_TRUST_SUSPENDED && (!x_zero || !y_zero))) {
        return PASSPORT_TRUST_BAD_DATA;
    }
    const size_t frame_length = FRAME_HEADER + id_length + PASSPORT_P256_COORD_SIZE * 2;
    if (capacity < frame_length) return PASSPORT_TRUST_BAD_ARGUMENT;
    memcpy(output, DOMAIN, sizeof(DOMAIN));
    output[16] = (uint8_t)manifest->state;
    output[17] = (uint8_t)id_length;
    output[18] = 0;
    output[19] = 0;
    put_u32(output + 20, manifest->epoch);
    memcpy(output + FRAME_HEADER, manifest->community_id, id_length);
    memcpy(output + FRAME_HEADER + id_length, manifest->service_public_x,
           PASSPORT_P256_COORD_SIZE);
    memcpy(output + FRAME_HEADER + id_length + PASSPORT_P256_COORD_SIZE,
           manifest->service_public_y, PASSPORT_P256_COORD_SIZE);
    *length = frame_length;
    return PASSPORT_TRUST_OK;
}

static bool decode_record(const passport_trust_root_t *root, trust_slot_t *slot)
{
    if (slot->length < FRAME_HEADER + 1 + PASSPORT_P256_COORD_SIZE * 2 + RECORD_TRAILER ||
        slot->length > PASSPORT_TRUST_RECORD_MAX) return false;
    const uint8_t *record = slot->bytes;
    if (memcmp(record, DOMAIN, sizeof(DOMAIN)) != 0 || record[18] || record[19]) return false;
    const size_t id_length = record[17];
    const size_t frame_length = FRAME_HEADER + id_length + PASSPORT_P256_COORD_SIZE * 2;
    if (!id_length || id_length > PASSPORT_TRUST_COMMUNITY_MAX ||
        slot->length != frame_length + RECORD_TRAILER ||
        get_u32(record + slot->length - 4) != passport_crc32(record, slot->length - 4)) return false;
    passport_trust_manifest_t manifest = { 0 };
    memcpy(manifest.community_id, record + FRAME_HEADER, id_length);
    manifest.epoch = get_u32(record + 20);
    manifest.state = (passport_trust_state_t)record[16];
    memcpy(manifest.service_public_x, record + FRAME_HEADER + id_length,
           PASSPORT_P256_COORD_SIZE);
    memcpy(manifest.service_public_y, record + FRAME_HEADER + id_length + PASSPORT_P256_COORD_SIZE,
           PASSPORT_P256_COORD_SIZE);
    uint8_t encoded[PASSPORT_TRUST_FRAME_MAX];
    size_t encoded_length = 0;
    if ((manifest.state == PASSPORT_TRUST_ACTIVE &&
         memcmp(manifest.service_public_x, root->public_x, PASSPORT_P256_COORD_SIZE) == 0 &&
         memcmp(manifest.service_public_y, root->public_y, PASSPORT_P256_COORD_SIZE) == 0) ||
        strcmp(manifest.community_id, root->community_id) != 0 ||
        passport_trust_encode(&manifest, encoded, sizeof(encoded), &encoded_length) != PASSPORT_TRUST_OK ||
        encoded_length != frame_length || memcmp(encoded, record, frame_length) != 0 ||
        !passport_p256_verify_p1363(root->public_x, root->public_y, record,
                                   frame_length, record + frame_length)) return false;
    slot->manifest = manifest;
    return true;
}

static passport_trust_result_t reload(passport_trust_t *trust)
{
    trust_slot_t slots[2] = { 0 };
    for (size_t index = 0; index < 2; index++) {
        const passport_store_result_t read = trust->store.read(trust->store.context, index,
            slots[index].bytes, sizeof(slots[index].bytes), &slots[index].length);
        slots[index].io_error = read != PASSPORT_STORE_OK && read != PASSPORT_STORE_NOT_FOUND;
        slots[index].present = read == PASSPORT_STORE_OK;
        if (slots[index].present) slots[index].valid = decode_record(&trust->root, &slots[index]);
        if (slots[index].valid && slots[index].manifest.epoch > trust->observed_epoch) {
            trust->observed_epoch = slots[index].manifest.epoch;
        }
    }
    memset(&trust->manifest, 0, sizeof(trust->manifest));
    if (!slots[0].present && !slots[1].present &&
        !slots[0].io_error && !slots[1].io_error && !trust->observed_epoch) {
        trust->state = PASSPORT_TRUST_UNPROVISIONED;
        return PASSPORT_TRUST_EMPTY;
    }
    if (slots[0].valid && slots[1].valid &&
        slots[0].length == slots[1].length &&
        memcmp(slots[0].bytes, slots[1].bytes, slots[0].length) == 0 &&
        slots[0].manifest.epoch >= trust->observed_epoch) {
        trust->manifest = slots[0].manifest;
        trust->state = trust->manifest.state;
        return PASSPORT_TRUST_OK;
    }
    trust->state = PASSPORT_TRUST_LOCKED;
    return slots[0].io_error || slots[1].io_error ? PASSPORT_TRUST_IO_ERROR : PASSPORT_TRUST_IS_LOCKED;
}

passport_trust_result_t passport_trust_open(
    passport_trust_t *trust, const passport_outbox_store_t *store,
    const passport_trust_root_t *root)
{
    if (!trust || !store || !store->read || !store->write || !root ||
        !community_length(root->community_id) ||
        all_zero(root->public_x, PASSPORT_P256_COORD_SIZE) ||
        all_zero(root->public_y, PASSPORT_P256_COORD_SIZE)) return PASSPORT_TRUST_BAD_ARGUMENT;
    const passport_outbox_store_t storage = *store;
    const passport_trust_root_t pinned = *root;
    memset(trust, 0, sizeof(*trust));
    trust->store = storage;
    trust->root = pinned;
    trust->initialized = true;
    return reload(trust);
}

static passport_trust_result_t verify_candidate(
    passport_trust_t *trust, const passport_trust_manifest_t *manifest,
    const uint8_t signature[PASSPORT_P256_P1363_SIZE],
    uint8_t output[PASSPORT_TRUST_RECORD_MAX], size_t *length)
{
    if (!manifest || !signature) return PASSPORT_TRUST_BAD_ARGUMENT;
    size_t frame_length = 0;
    const passport_trust_result_t encoded = passport_trust_encode(manifest, output,
        PASSPORT_TRUST_FRAME_MAX, &frame_length);
    if (encoded != PASSPORT_TRUST_OK) return encoded;
    if (strcmp(manifest->community_id, trust->root.community_id) != 0 ||
        (manifest->state == PASSPORT_TRUST_ACTIVE &&
         memcmp(manifest->service_public_x, trust->root.public_x, PASSPORT_P256_COORD_SIZE) == 0 &&
         memcmp(manifest->service_public_y, trust->root.public_y, PASSPORT_P256_COORD_SIZE) == 0)) {
        return PASSPORT_TRUST_UNTRUSTED;
    }
    if (manifest->epoch <= trust->observed_epoch) return PASSPORT_TRUST_REPLAY;
    if (!passport_p256_verify_p1363(trust->root.public_x, trust->root.public_y,
        output, frame_length, signature)) return PASSPORT_TRUST_UNTRUSTED;
    memcpy(output + frame_length, signature, PASSPORT_P256_P1363_SIZE);
    *length = frame_length + RECORD_TRAILER;
    put_u32(output + *length - 4, passport_crc32(output, *length - 4));
    return PASSPORT_TRUST_OK;
}

static passport_trust_result_t persist(
    passport_trust_t *trust, const uint8_t *record, size_t length, uint32_t epoch)
{
    /* Once a signed epoch starts persistence, any failure closes service use.
     * Remember the candidate floor even if a callback reports an uncertain write. */
    trust->observed_epoch = epoch;
    trust->state = PASSPORT_TRUST_LOCKED;
    memset(&trust->manifest, 0, sizeof(trust->manifest));
    for (size_t slot = 0; slot < 2; slot++) {
        uint8_t verify[PASSPORT_TRUST_RECORD_MAX];
        size_t verify_length = 0;
        if (!trust->store.write(trust->store.context, slot, record, length) ||
            trust->store.read(trust->store.context, slot, verify, sizeof(verify), &verify_length) != PASSPORT_STORE_OK ||
            verify_length != length || memcmp(verify, record, length) != 0) return PASSPORT_TRUST_IO_ERROR;
    }
    return reload(trust);
}

passport_trust_result_t passport_trust_apply(
    passport_trust_t *trust, const passport_trust_manifest_t *manifest,
    const uint8_t root_signature[PASSPORT_P256_P1363_SIZE],
    bool locally_confirmed)
{
    if (!trust || !trust->initialized || !manifest) return PASSPORT_TRUST_BAD_ARGUMENT;
    const passport_trust_manifest_t candidate = *manifest;
    if (trust->state == PASSPORT_TRUST_LOCKED) return PASSPORT_TRUST_IS_LOCKED;
    const passport_trust_result_t loaded = reload(trust);
    if (loaded != PASSPORT_TRUST_OK && loaded != PASSPORT_TRUST_EMPTY) return loaded;
    if (trust->state == PASSPORT_TRUST_UNPROVISIONED && !locally_confirmed) {
        return PASSPORT_TRUST_LOCAL_CONFIRMATION_REQUIRED;
    }
    uint8_t record[PASSPORT_TRUST_RECORD_MAX];
    size_t length = 0;
    const passport_trust_result_t verified = verify_candidate(trust, &candidate, root_signature, record, &length);
    if (verified != PASSPORT_TRUST_OK) return verified;
    return persist(trust, record, length, candidate.epoch);
}

passport_trust_result_t passport_trust_recover(
    passport_trust_t *trust, const passport_trust_manifest_t *manifest,
    const uint8_t root_signature[PASSPORT_P256_P1363_SIZE],
    bool locally_confirmed, uint32_t authoritative_minimum_epoch)
{
    if (!trust || !trust->initialized || !manifest) return PASSPORT_TRUST_BAD_ARGUMENT;
    const passport_trust_manifest_t candidate = *manifest;
    if (trust->state != PASSPORT_TRUST_LOCKED) return PASSPORT_TRUST_BAD_ARGUMENT;
    if (!locally_confirmed) return PASSPORT_TRUST_LOCAL_CONFIRMATION_REQUIRED;
    /* Observe any surviving valid record, but never unlock as a side effect. */
    (void)reload(trust);
    trust->state = PASSPORT_TRUST_LOCKED;
    memset(&trust->manifest, 0, sizeof(trust->manifest));
    if (authoritative_minimum_epoch > trust->observed_epoch) {
        trust->observed_epoch = authoritative_minimum_epoch;
    }
    uint8_t record[PASSPORT_TRUST_RECORD_MAX];
    size_t length = 0;
    const passport_trust_result_t verified = verify_candidate(trust, &candidate, root_signature, record, &length);
    if (verified != PASSPORT_TRUST_OK) return verified;
    return persist(trust, record, length, candidate.epoch);
}

passport_trust_result_t passport_trust_get_service(
    passport_trust_t *trust, const char *community_id,
    uint8_t public_x[PASSPORT_P256_COORD_SIZE],
    uint8_t public_y[PASSPORT_P256_COORD_SIZE], uint32_t *epoch)
{
    if (public_x) memset(public_x, 0, PASSPORT_P256_COORD_SIZE);
    if (public_y) memset(public_y, 0, PASSPORT_P256_COORD_SIZE);
    if (epoch) *epoch = 0;
    if (!trust || !trust->initialized || !community_id || !public_x || !public_y || !epoch) {
        return PASSPORT_TRUST_BAD_ARGUMENT;
    }
    if (trust->state == PASSPORT_TRUST_LOCKED) return PASSPORT_TRUST_IS_LOCKED;
    const passport_trust_result_t loaded = reload(trust);
    if (loaded != PASSPORT_TRUST_OK) return loaded;
    if (strcmp(community_id, trust->root.community_id) != 0) return PASSPORT_TRUST_UNTRUSTED;
    if (trust->state == PASSPORT_TRUST_SUSPENDED) return PASSPORT_TRUST_IS_SUSPENDED;
    if (trust->state != PASSPORT_TRUST_ACTIVE) return PASSPORT_TRUST_IS_LOCKED;
    memcpy(public_x, trust->manifest.service_public_x, PASSPORT_P256_COORD_SIZE);
    memcpy(public_y, trust->manifest.service_public_y, PASSPORT_P256_COORD_SIZE);
    *epoch = trust->manifest.epoch;
    return PASSPORT_TRUST_OK;
}
