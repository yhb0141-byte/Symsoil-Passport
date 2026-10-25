#include "passport_signer.h"

#include <string.h>

static void encode_counter(const passport_counter_t *counter, uint64_t value,
                           uint8_t bytes[PASSPORT_COUNTER_RECORD_SIZE])
{
    memcpy(bytes, "SPC1", 4);
    memcpy(bytes + 4, counter->key_hash, 32);
    for (size_t i = 0; i < 8; ++i) bytes[36 + i] = (uint8_t)(value >> (8 * i));
    memset(bytes + 44, 0, 4); // Reserved, bound by CRC.
    uint32_t crc = passport_crc32(bytes, 48);
    for (size_t i = 0; i < 4; ++i) bytes[48 + i] = (uint8_t)(crc >> (8 * i));
}

static bool counter_setup(passport_counter_t *counter,
    const passport_outbox_store_t *store, const uint8_t key_hash[32], uint64_t floor)
{
    if (!counter) return false;
    memset(counter, 0, sizeof(*counter));
    if (!store || !store->read || !store->write || !key_hash ||
        floor > PASSPORT_JS_SAFE_INTEGER_MAX) return false;
    counter->store = *store;
    memcpy(counter->key_hash, key_hash, 32);
    return true;
}

static bool counter_write(passport_counter_t *counter, uint64_t value)
{
    uint8_t bytes[PASSPORT_COUNTER_RECORD_SIZE], check[PASSPORT_COUNTER_RECORD_SIZE];
    encode_counter(counter, value, bytes);
    counter->ready = false;
    for (size_t slot = 0; slot < 2; ++slot) {
        size_t length = 0;
        if (!counter->store.write(counter->store.context, slot, bytes, sizeof(bytes)) ||
            counter->store.read(counter->store.context, slot, check, sizeof(check), &length) != PASSPORT_STORE_OK ||
            length != sizeof(bytes) || memcmp(bytes, check, sizeof(bytes)) != 0) return false;
    }
    counter->last_reserved = value;
    counter->ready = true;
    return true;
}

bool passport_counter_enroll(passport_counter_t *counter,
    const passport_outbox_store_t *store, const uint8_t key_hash[32], uint64_t floor)
{
    if (!counter_setup(counter, store, key_hash, floor)) return false;
    uint8_t bytes[PASSPORT_COUNTER_RECORD_SIZE];
    for (size_t slot = 0; slot < 2; ++slot) {
        size_t length = 0;
        if (store->read(store->context, slot, bytes, sizeof(bytes), &length) != PASSPORT_STORE_NOT_FOUND) return false;
    }
    return counter_write(counter, floor);
}

bool passport_counter_open(passport_counter_t *counter,
    const passport_outbox_store_t *store, const uint8_t key_hash[32], uint64_t floor)
{
    if (!counter_setup(counter, store, key_hash, floor)) return false;
    uint8_t bytes[2][PASSPORT_COUNTER_RECORD_SIZE], expected[PASSPORT_COUNTER_RECORD_SIZE];
    for (size_t slot = 0; slot < 2; ++slot) {
        size_t length = 0;
        if (store->read(store->context, slot, bytes[slot], sizeof(bytes[slot]), &length) != PASSPORT_STORE_OK ||
            length != sizeof(bytes[slot])) return false;
    }
    if (memcmp(bytes[0], bytes[1], sizeof(bytes[0])) != 0) return false;
    uint64_t value = 0;
    for (size_t i = 0; i < 8; ++i) value |= (uint64_t)bytes[0][36 + i] << (8 * i);
    if (value < floor || value > PASSPORT_JS_SAFE_INTEGER_MAX) return false;
    encode_counter(counter, value, expected);
    if (memcmp(bytes[0], expected, sizeof(expected)) != 0) return false;
    counter->last_reserved = value;
    counter->ready = true;
    return true;
}

bool passport_counter_reserve(passport_counter_t *counter, uint64_t *reserved)
{
    if (!counter || !counter->ready || !reserved ||
        counter->last_reserved >= PASSPORT_JS_SAFE_INTEGER_MAX) return false;
    passport_counter_t current;
    if (!passport_counter_open(&current, &counter->store, counter->key_hash,
                               counter->last_reserved) ||
        current.last_reserved != counter->last_reserved) {
        counter->ready = false;
        return false;
    }
    if (!counter_write(counter, counter->last_reserved + 1)) return false;
    *reserved = counter->last_reserved;
    return true;
}

bool passport_signer_open(passport_signer_t *signer, passport_counter_t *counter,
    passport_delivery_t *delivery, const passport_sign_provider_t *provider)
{
    if (!signer) return false;
    memset(signer, 0, sizeof(*signer));
    if (!counter || !counter->ready || !delivery || !provider || !provider->sign) return false;
    uint8_t point[65] = { 4 }, hash[32];
    memcpy(point + 1, provider->public_x, 32);
    memcpy(point + 33, provider->public_y, 32);
    if (!passport_sha256(point, sizeof(point), hash) ||
        memcmp(hash, counter->key_hash, sizeof(hash)) != 0) return false;
    signer->counter = counter;
    signer->delivery = delivery;
    signer->provider = *provider;
    return true;
}

passport_sign_result_t passport_signer_retry_save(passport_signer_t *signer)
{
    if (!signer || !signer->delivery || !signer->staged || signer->active) return PASSPORT_SIGN_INVALID;
    signer->active = true;
    if (signer->delivery->state == PASSPORT_DELIVERY_STORAGE_ERROR) {
        // Reload durable state after an uncertain write. A different recovered
        // reply remains busy; corruption is never erased to make room.
        passport_outbox_store_t store = signer->delivery->store;
        size_t packet_size = signer->delivery->packet_size;
        uint8_t attempts = signer->delivery->max_attempts;
        passport_delivery_result_t opened = passport_delivery_open(
            signer->delivery, &store, packet_size, attempts);
        if (opened != PASSPORT_DELIVERY_OK && opened != PASSPORT_DELIVERY_EMPTY) {
            signer->active = false;
            return PASSPORT_SIGN_NOT_DURABLE;
        }
    }
    passport_delivery_result_t result = passport_delivery_queue(signer->delivery,
        signer->frame, signer->frame_length, signer->signature, signer->transfer_id);
    signer->active = false;
    if (result != PASSPORT_DELIVERY_OK) return PASSPORT_SIGN_NOT_DURABLE;
    signer->staged = false;
    memset(signer->signature, 0, sizeof(signer->signature));
    return PASSPORT_SIGN_OK;
}

passport_sign_result_t passport_signer_submit(passport_signer_t *signer,
    const passport_confirmation_frame_t *confirmed_frame, uint32_t transfer_id)
{
    if (!signer || !signer->counter || !signer->delivery || !confirmed_frame ||
        confirmed_frame->counter != 0 || !transfer_id) return PASSPORT_SIGN_INVALID;
    if (signer->active || signer->staged || signer->delivery->state != PASSPORT_DELIVERY_IDLE) return PASSPORT_SIGN_BUSY;
    // Validate inputs before invoking storage or burning a counter.
    passport_confirmation_frame_t frame = *confirmed_frame;
    frame.counter = 1;
    if (passport_confirmation_frame_json(&frame, signer->frame, sizeof(signer->frame),
                                        &signer->frame_length) != PASSPORT_PROTOCOL_OK) return PASSPORT_SIGN_INVALID;
    signer->active = true;
    uint64_t reserved = 0;
    // Reservation may call platform storage; caller must serialize callbacks
    // and must keep the confirmed input immutable for this synchronous call.
    if (!passport_counter_reserve(signer->counter, &reserved)) {
        signer->active = false;
        return PASSPORT_SIGN_COUNTER_LOCKED;
    }
    frame.counter = reserved;
    if (passport_confirmation_frame_json(&frame, signer->frame, sizeof(signer->frame),
                                        &signer->frame_length) != PASSPORT_PROTOCOL_OK) {
        signer->active = false;
        return PASSPORT_SIGN_INVALID;
    }
    bool signed_ok = signer->provider.sign(signer->provider.context,
        (const uint8_t *)signer->frame, signer->frame_length, signer->signature);
    bool verified = signed_ok && passport_p256_verify_p1363(signer->provider.public_x,
        signer->provider.public_y, (const uint8_t *)signer->frame,
        signer->frame_length, signer->signature);
    signer->active = false;
    if (!verified) {
        memset(signer->signature, 0, sizeof(signer->signature));
        return PASSPORT_SIGN_PROVIDER_FAILED; // Counter stays consumed.
    }
    signer->transfer_id = transfer_id;
    signer->staged = true;
    return passport_signer_retry_save(signer);
}
