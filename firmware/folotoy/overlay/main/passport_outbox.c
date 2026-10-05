#include "passport_outbox.h"

#include <string.h>

#define RECORD_HEADER_SIZE 20
#define RECORD_TRAILER_SIZE 4
#define RECORD_VERSION 1
#define RECORD_TOMBSTONE 0
#define RECORD_READY 1
#define ENVELOPE_HEADER_SIZE 8
#define ENVELOPE_TRAILER_SIZE 4

static const uint8_t MAGIC[4] = { 'S', 'P', 'O', '1' };

typedef struct {
    bool present;
    bool valid;
    bool ready;
    uint32_t generation;
    size_t slot;
} slot_record_t;

static void put_u16(uint8_t *output, uint16_t value)
{
    output[0] = (uint8_t)value;
    output[1] = (uint8_t)(value >> 8);
}

static void put_u32(uint8_t *output, uint32_t value)
{
    output[0] = (uint8_t)value;
    output[1] = (uint8_t)(value >> 8);
    output[2] = (uint8_t)(value >> 16);
    output[3] = (uint8_t)(value >> 24);
}

static uint16_t get_u16(const uint8_t *input)
{
    return (uint16_t)input[0] | ((uint16_t)input[1] << 8);
}

static uint32_t get_u32(const uint8_t *input)
{
    return (uint32_t)input[0] | ((uint32_t)input[1] << 8) |
           ((uint32_t)input[2] << 16) | ((uint32_t)input[3] << 24);
}

uint32_t passport_crc32(const uint8_t *data, size_t length)
{
    uint32_t crc = UINT32_C(0xffffffff);
    for (size_t index = 0; index < length; index++) {
        crc ^= data[index];
        for (unsigned bit = 0; bit < 8; bit++) {
            const uint32_t mask = (uint32_t)-(int32_t)(crc & 1);
            crc = (crc >> 1) ^ (UINT32_C(0xedb88320) & mask);
        }
    }
    return ~crc;
}

static bool encode_record(
    uint8_t state,
    uint32_t generation,
    uint32_t transfer_id,
    const char *frame,
    size_t frame_length,
    const uint8_t *signature,
    uint8_t output[PASSPORT_OUTBOX_RECORD_MAX],
    size_t *length)
{
    if (!generation || (state != RECORD_READY && state != RECORD_TOMBSTONE)) return false;
    if (state == RECORD_READY &&
        (!transfer_id || !frame || !frame_length || frame_length > PASSPORT_OUTBOX_FRAME_MAX || !signature)) {
        return false;
    }
    if (state == RECORD_TOMBSTONE) {
        transfer_id = 0;
        frame_length = 0;
    }
    const size_t signature_length = state == RECORD_READY ? PASSPORT_OUTBOX_SIGNATURE_SIZE : 0;
    const size_t record_length = RECORD_HEADER_SIZE + frame_length + signature_length + RECORD_TRAILER_SIZE;
    if (record_length > PASSPORT_OUTBOX_RECORD_MAX) return false;

    memcpy(output, MAGIC, sizeof(MAGIC));
    output[4] = RECORD_VERSION;
    output[5] = state;
    output[6] = 0;
    output[7] = 0;
    put_u32(output + 8, generation);
    put_u32(output + 12, transfer_id);
    put_u16(output + 16, (uint16_t)frame_length);
    put_u16(output + 18, (uint16_t)signature_length);
    if (frame_length) memcpy(output + RECORD_HEADER_SIZE, frame, frame_length);
    if (signature_length) memcpy(output + RECORD_HEADER_SIZE + frame_length, signature, signature_length);
    put_u32(output + record_length - RECORD_TRAILER_SIZE,
            passport_crc32(output, record_length - RECORD_TRAILER_SIZE));
    *length = record_length;
    return true;
}

static bool decode_record(
    const uint8_t *input,
    size_t length,
    slot_record_t *record,
    passport_outbox_message_t *message)
{
    if (length < RECORD_HEADER_SIZE + RECORD_TRAILER_SIZE ||
        memcmp(input, MAGIC, sizeof(MAGIC)) != 0 || input[4] != RECORD_VERSION ||
        input[6] != 0 || input[7] != 0) return false;
    const uint8_t state = input[5];
    const uint32_t generation = get_u32(input + 8);
    const uint32_t transfer_id = get_u32(input + 12);
    const size_t frame_length = get_u16(input + 16);
    const size_t signature_length = get_u16(input + 18);
    const size_t expected = RECORD_HEADER_SIZE + frame_length + signature_length + RECORD_TRAILER_SIZE;
    if (!generation || expected != length || expected > PASSPORT_OUTBOX_RECORD_MAX ||
        get_u32(input + length - RECORD_TRAILER_SIZE) != passport_crc32(input, length - RECORD_TRAILER_SIZE)) {
        return false;
    }
    if (state == RECORD_TOMBSTONE) {
        if (transfer_id || frame_length || signature_length) return false;
        record->ready = false;
    } else if (state == RECORD_READY) {
        if (!transfer_id || !frame_length || frame_length > PASSPORT_OUTBOX_FRAME_MAX ||
            signature_length != PASSPORT_OUTBOX_SIGNATURE_SIZE) return false;
        record->ready = true;
        if (message) {
            message->generation = generation;
            message->transfer_id = transfer_id;
            message->frame_length = frame_length;
            memcpy(message->frame, input + RECORD_HEADER_SIZE, frame_length);
            message->frame[frame_length] = '\0';
            memcpy(message->signature,
                   input + RECORD_HEADER_SIZE + frame_length, PASSPORT_OUTBOX_SIGNATURE_SIZE);
        }
    } else {
        return false;
    }
    record->generation = generation;
    record->valid = true;
    return true;
}

static passport_outbox_result_t read_slots(
    const passport_outbox_store_t *store, slot_record_t slots[PASSPORT_OUTBOX_SLOT_COUNT])
{
    if (!store || !store->read || !store->write) return PASSPORT_OUTBOX_INVALID;
    memset(slots, 0, sizeof(slot_record_t) * PASSPORT_OUTBOX_SLOT_COUNT);
    for (size_t slot = 0; slot < PASSPORT_OUTBOX_SLOT_COUNT; slot++) {
        uint8_t buffer[PASSPORT_OUTBOX_RECORD_MAX];
        size_t length = 0;
        const passport_store_result_t result =
            store->read(store->context, slot, buffer, sizeof(buffer), &length);
        if (result == PASSPORT_STORE_ERROR) return PASSPORT_OUTBOX_IO_ERROR;
        if (result == PASSPORT_STORE_NOT_FOUND) continue;
        slots[slot].present = true;
        slots[slot].slot = slot;
        if (length <= sizeof(buffer)) (void)decode_record(buffer, length, &slots[slot], NULL);
    }
    return PASSPORT_OUTBOX_EMPTY;
}

static const slot_record_t *newest_valid(const slot_record_t slots[PASSPORT_OUTBOX_SLOT_COUNT])
{
    const slot_record_t *newest = NULL;
    for (size_t slot = 0; slot < PASSPORT_OUTBOX_SLOT_COUNT; slot++) {
        if (slots[slot].valid && (!newest || slots[slot].generation > newest->generation)) {
            newest = &slots[slot];
        }
    }
    return newest;
}

passport_outbox_result_t passport_outbox_load(
    const passport_outbox_store_t *store, passport_outbox_message_t *message)
{
    slot_record_t slots[PASSPORT_OUTBOX_SLOT_COUNT];
    const passport_outbox_result_t read = read_slots(store, slots);
    if (read != PASSPORT_OUTBOX_EMPTY) return read;
    const slot_record_t *newest = newest_valid(slots);
    if (!newest) {
        return slots[0].present || slots[1].present ? PASSPORT_OUTBOX_CORRUPT : PASSPORT_OUTBOX_EMPTY;
    }
    if (!newest->ready) return PASSPORT_OUTBOX_EMPTY;
    if (!message) return PASSPORT_OUTBOX_INVALID;
    uint8_t buffer[PASSPORT_OUTBOX_RECORD_MAX];
    size_t length = 0;
    slot_record_t decoded = { .slot = newest->slot };
    if (store->read(store->context, newest->slot, buffer, sizeof(buffer), &length) != PASSPORT_STORE_OK ||
        !decode_record(buffer, length, &decoded, message) || !decoded.ready ||
        decoded.generation != newest->generation) return PASSPORT_OUTBOX_IO_ERROR;
    return PASSPORT_OUTBOX_READY;
}

static passport_outbox_result_t write_next(
    const passport_outbox_store_t *store,
    uint8_t state,
    const char *frame,
    size_t frame_length,
    const uint8_t *signature,
    uint32_t transfer_id,
    passport_outbox_message_t *saved)
{
    slot_record_t slots[PASSPORT_OUTBOX_SLOT_COUNT];
    const passport_outbox_result_t read = read_slots(store, slots);
    if (read != PASSPORT_OUTBOX_EMPTY) return read;
    const slot_record_t *newest = newest_valid(slots);
    const uint32_t generation = newest ? newest->generation + 1 : 1;
    if (!generation) return PASSPORT_OUTBOX_INVALID;
    uint8_t record[PASSPORT_OUTBOX_RECORD_MAX];
    size_t length = 0;
    if (!encode_record(state, generation, transfer_id, frame, frame_length,
                       signature, record, &length)) return PASSPORT_OUTBOX_INVALID;
    const size_t target = generation % PASSPORT_OUTBOX_SLOT_COUNT;
    if (!store->write(store->context, target, record, length)) return PASSPORT_OUTBOX_IO_ERROR;

    uint8_t verify[PASSPORT_OUTBOX_RECORD_MAX];
    size_t verify_length = 0;
    if (store->read(store->context, target, verify, sizeof(verify), &verify_length) != PASSPORT_STORE_OK ||
        verify_length != length || memcmp(verify, record, length) != 0) return PASSPORT_OUTBOX_IO_ERROR;
    slot_record_t decoded = { 0 };
    if (!decode_record(verify, verify_length, &decoded, NULL) || decoded.generation != generation) {
        return PASSPORT_OUTBOX_IO_ERROR;
    }
    // Mirror only after the first copy is verified. A reset during either
    // write therefore leaves at least one complete newest-or-previous record.
    const size_t mirror = (target + 1) % PASSPORT_OUTBOX_SLOT_COUNT;
    if (!store->write(store->context, mirror, record, length)) return PASSPORT_OUTBOX_IO_ERROR;
    verify_length = 0;
    if (store->read(store->context, mirror, verify, sizeof(verify), &verify_length) != PASSPORT_STORE_OK ||
        verify_length != length || memcmp(verify, record, length) != 0) return PASSPORT_OUTBOX_IO_ERROR;
    if (saved && decoded.ready) {
        saved->generation = generation;
        saved->transfer_id = transfer_id;
        saved->frame_length = frame_length;
        memcpy(saved->frame, frame, frame_length);
        saved->frame[frame_length] = '\0';
        memcpy(saved->signature, signature, PASSPORT_OUTBOX_SIGNATURE_SIZE);
    }
    return decoded.ready ? PASSPORT_OUTBOX_READY : PASSPORT_OUTBOX_EMPTY;
}

passport_outbox_result_t passport_outbox_save(
    const passport_outbox_store_t *store,
    const char *canonical_frame,
    size_t frame_length,
    const uint8_t signature[PASSPORT_OUTBOX_SIGNATURE_SIZE],
    uint32_t transfer_id,
    passport_outbox_message_t *saved)
{
    passport_outbox_message_t existing;
    const passport_outbox_result_t loaded = passport_outbox_load(store, &existing);
    if (loaded == PASSPORT_OUTBOX_READY) {
        const bool same = existing.transfer_id == transfer_id && existing.frame_length == frame_length &&
                          frame_length <= PASSPORT_OUTBOX_FRAME_MAX && canonical_frame && signature &&
                          memcmp(existing.frame, canonical_frame, frame_length) == 0 &&
                          memcmp(existing.signature, signature, PASSPORT_OUTBOX_SIGNATURE_SIZE) == 0;
        if (!same) return PASSPORT_OUTBOX_BUSY;
        if (saved) *saved = existing;
        return PASSPORT_OUTBOX_READY;
    }
    if (loaded != PASSPORT_OUTBOX_EMPTY) return loaded;
    return write_next(store, RECORD_READY, canonical_frame, frame_length,
                      signature, transfer_id, saved);
}

passport_outbox_result_t passport_outbox_clear(const passport_outbox_store_t *store)
{
    slot_record_t slots[PASSPORT_OUTBOX_SLOT_COUNT];
    const passport_outbox_result_t read = read_slots(store, slots);
    if (read != PASSPORT_OUTBOX_EMPTY) return read;
    const slot_record_t *newest = newest_valid(slots);
    if (!newest) {
        return slots[0].present || slots[1].present ? PASSPORT_OUTBOX_CORRUPT : PASSPORT_OUTBOX_EMPTY;
    }
    if (!newest->ready) return PASSPORT_OUTBOX_EMPTY;
    return write_next(store, RECORD_TOMBSTONE, NULL, 0, NULL, 0, NULL);
}

bool passport_outbox_envelope_encode(
    const passport_outbox_message_t *message,
    uint8_t *output,
    size_t capacity,
    size_t *length)
{
    if (length) *length = 0;
    if (!message || !output || !length || !message->transfer_id || !message->frame_length ||
        message->frame_length > PASSPORT_OUTBOX_FRAME_MAX) return false;
    const size_t envelope_length = ENVELOPE_HEADER_SIZE + message->frame_length +
                                   PASSPORT_OUTBOX_SIGNATURE_SIZE + ENVELOPE_TRAILER_SIZE;
    if (capacity < envelope_length) return false;
    output[0] = 'S';
    output[1] = 'P';
    output[2] = 'R';
    output[3] = '1';
    put_u16(output + 4, (uint16_t)message->frame_length);
    put_u16(output + 6, PASSPORT_OUTBOX_SIGNATURE_SIZE);
    memcpy(output + ENVELOPE_HEADER_SIZE, message->frame, message->frame_length);
    memcpy(output + ENVELOPE_HEADER_SIZE + message->frame_length,
           message->signature, PASSPORT_OUTBOX_SIGNATURE_SIZE);
    put_u32(output + envelope_length - ENVELOPE_TRAILER_SIZE,
            passport_crc32(output, envelope_length - ENVELOPE_TRAILER_SIZE));
    *length = envelope_length;
    return true;
}

bool passport_outbox_envelope_decode(
    const uint8_t *input,
    size_t length,
    passport_outbox_message_t *message)
{
    if (!input || !message || length < ENVELOPE_HEADER_SIZE + ENVELOPE_TRAILER_SIZE ||
        input[0] != 'S' || input[1] != 'P' || input[2] != 'R' || input[3] != '1') return false;
    const size_t frame_length = get_u16(input + 4);
    const size_t signature_length = get_u16(input + 6);
    const size_t expected = ENVELOPE_HEADER_SIZE + frame_length + signature_length + ENVELOPE_TRAILER_SIZE;
    if (!frame_length || frame_length > PASSPORT_OUTBOX_FRAME_MAX ||
        signature_length != PASSPORT_OUTBOX_SIGNATURE_SIZE || expected != length ||
        get_u32(input + length - ENVELOPE_TRAILER_SIZE) !=
            passport_crc32(input, length - ENVELOPE_TRAILER_SIZE)) return false;
    memset(message, 0, sizeof(*message));
    message->frame_length = frame_length;
    memcpy(message->frame, input + ENVELOPE_HEADER_SIZE, frame_length);
    message->frame[frame_length] = '\0';
    memcpy(message->signature, input + ENVELOPE_HEADER_SIZE + frame_length,
           PASSPORT_OUTBOX_SIGNATURE_SIZE);
    return true;
}
