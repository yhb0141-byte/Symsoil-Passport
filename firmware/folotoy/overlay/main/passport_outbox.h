#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PASSPORT_OUTBOX_FRAME_MAX 768
#define PASSPORT_OUTBOX_SIGNATURE_SIZE 64
#define PASSPORT_OUTBOX_RECORD_MAX 856
#define PASSPORT_OUTBOX_ENVELOPE_MAX 844
#define PASSPORT_OUTBOX_SLOT_COUNT 2

typedef enum {
    PASSPORT_STORE_OK = 0,
    PASSPORT_STORE_NOT_FOUND,
    PASSPORT_STORE_ERROR,
} passport_store_result_t;

typedef passport_store_result_t (*passport_store_read_fn)(
    void *context, size_t slot, uint8_t *output, size_t capacity, size_t *length);
typedef bool (*passport_store_write_fn)(
    void *context, size_t slot, const uint8_t *data, size_t length);

typedef struct {
    void *context;
    passport_store_read_fn read;
    passport_store_write_fn write;
} passport_outbox_store_t;

typedef struct {
    uint32_t generation;
    uint32_t transfer_id;
    size_t frame_length;
    char frame[PASSPORT_OUTBOX_FRAME_MAX + 1];
    uint8_t signature[PASSPORT_OUTBOX_SIGNATURE_SIZE];
} passport_outbox_message_t;

typedef enum {
    PASSPORT_OUTBOX_EMPTY = 0,
    PASSPORT_OUTBOX_READY,
    PASSPORT_OUTBOX_CORRUPT,
    PASSPORT_OUTBOX_IO_ERROR,
    PASSPORT_OUTBOX_INVALID,
    PASSPORT_OUTBOX_BUSY,
} passport_outbox_result_t;

// Two alternating records form a journal. Clearing writes a newer tombstone;
// it never erases the only known-good record in place. CRC detects torn or
// corrupt storage but is not an authenticity check.
passport_outbox_result_t passport_outbox_load(
    const passport_outbox_store_t *store, passport_outbox_message_t *message);
passport_outbox_result_t passport_outbox_save(
    const passport_outbox_store_t *store,
    const char *canonical_frame,
    size_t frame_length,
    const uint8_t signature[PASSPORT_OUTBOX_SIGNATURE_SIZE],
    uint32_t transfer_id,
    passport_outbox_message_t *saved);
passport_outbox_result_t passport_outbox_clear(const passport_outbox_store_t *store);

// Versioned transfer envelope reconstructed from the journal after a reboot.
// It contains only the already-signed canonical frame and P1363 signature.
bool passport_outbox_envelope_encode(
    const passport_outbox_message_t *message,
    uint8_t *output,
    size_t capacity,
    size_t *length);
bool passport_outbox_envelope_decode(
    const uint8_t *input,
    size_t length,
    passport_outbox_message_t *message);

uint32_t passport_crc32(const uint8_t *data, size_t length);
