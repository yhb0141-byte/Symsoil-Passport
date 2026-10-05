#pragma once

#include "passport_outbox.h"
#include "passport_transport.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    PASSPORT_DELIVERY_IDLE = 0,
    PASSPORT_DELIVERY_READY,
    PASSPORT_DELIVERY_WAITING_ACK,
    PASSPORT_DELIVERY_DISCONNECTED,
    PASSPORT_DELIVERY_AWAITING_RESULT,
    PASSPORT_DELIVERY_EXHAUSTED,
    PASSPORT_DELIVERY_STORAGE_ERROR,
    PASSPORT_DELIVERY_CORRUPT,
    PASSPORT_DELIVERY_INVALID,
} passport_delivery_state_t;

typedef enum {
    PASSPORT_DELIVERY_OK = 0,
    PASSPORT_DELIVERY_EMPTY,
    PASSPORT_DELIVERY_BUSY,
    PASSPORT_DELIVERY_MISMATCH,
    PASSPORT_DELIVERY_IO_ERROR,
    PASSPORT_DELIVERY_BAD_DATA,
    PASSPORT_DELIVERY_BAD_ARGUMENT,
} passport_delivery_result_t;

typedef enum {
    PASSPORT_DELIVERY_ACCEPTED = 1,
    PASSPORT_DELIVERY_REJECTED,
} passport_delivery_final_t;

typedef struct {
    passport_outbox_store_t store;
    passport_outbox_message_t pending;
    uint8_t envelope[PASSPORT_OUTBOX_ENVELOPE_MAX];
    size_t envelope_length;
    size_t packet_size;
    uint8_t max_attempts;
    passport_transport_t transport;
    passport_delivery_state_t state;
} passport_delivery_t;

// Opens the persistent outbox. A recovered reply is immediately prepared for
// retransmission with the same signed bytes and transfer ID.
passport_delivery_result_t passport_delivery_open(
    passport_delivery_t *delivery,
    const passport_outbox_store_t *store,
    size_t packet_size,
    uint8_t max_attempts);

// Persists a completed signature before making any packet available. A
// different signed reply cannot replace a pending one.
passport_delivery_result_t passport_delivery_queue(
    passport_delivery_t *delivery,
    const char *canonical_frame,
    size_t frame_length,
    const uint8_t signature[PASSPORT_OUTBOX_SIGNATURE_SIZE],
    uint32_t transfer_id);

passport_delivery_state_t passport_delivery_next_packet(
    passport_delivery_t *delivery,
    uint8_t *packet,
    size_t capacity,
    size_t *length);
passport_delivery_state_t passport_delivery_ack(
    passport_delivery_t *delivery,
    uint32_t transfer_id,
    uint16_t chunk_index,
    bool accepted);
passport_delivery_state_t passport_delivery_timeout(passport_delivery_t *delivery);
passport_delivery_state_t passport_delivery_disconnect(passport_delivery_t *delivery);
passport_delivery_state_t passport_delivery_reconnect(passport_delivery_t *delivery);

// Starts a new bounded packet attempt over the exact persisted envelope after
// an exhausted send or a lost business result. It never signs again.
passport_delivery_result_t passport_delivery_retry(passport_delivery_t *delivery);

// Packet ACKs only prove fragment delivery and never clear the journal. An
// authenticated application result must echo both transfer ID and the exact
// public signature before an accepted or rejected reply is cleared.
passport_delivery_result_t passport_delivery_finalize(
    passport_delivery_t *delivery,
    uint32_t transfer_id,
    const uint8_t signature[PASSPORT_OUTBOX_SIGNATURE_SIZE],
    passport_delivery_final_t final_result);
