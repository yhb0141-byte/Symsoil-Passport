#pragma once

#include "passport_transport.h"

// RAM-only, one message per locally opened authenticated session. No pairing,
// identity verification, JSON interpretation, signing or journal mutation here.
#define PASSPORT_RECEIVER_MESSAGE_MAX 4096
#define PASSPORT_RECEIVER_TIMEOUT_MAX_MS 30000

typedef enum {
    PASSPORT_RECEIVER_CLOSED = 0,
    PASSPORT_RECEIVER_READY,
    PASSPORT_RECEIVER_PARTIAL,
    PASSPORT_RECEIVER_COMPLETE,
    PASSPORT_RECEIVER_REJECTED,
    PASSPORT_RECEIVER_EXPIRED,
    PASSPORT_RECEIVER_STALE_SESSION,
    PASSPORT_RECEIVER_DUPLICATE,
    PASSPORT_RECEIVER_BAD_ARGUMENT,
} passport_receiver_state_t;

typedef struct {
    uint8_t message[PASSPORT_RECEIVER_MESSAGE_MAX];
    size_t length;
    size_t packet_size;
    uint64_t session;
    uint64_t opened_ms;
    uint64_t last_ms;
    uint32_t timeout_ms;
    uint32_t transfer_id;
    uint16_t chunk_count;
    uint16_t next_chunk;
    size_t last_offset;
    size_t last_length;
    passport_receiver_state_t state;
} passport_receiver_t;

// Initialize to {0}. Caller owns unique nonzero, never-reused local session
// generations; the wire cannot choose them. Open refuses an occupied receiver.
passport_receiver_state_t passport_receiver_open(passport_receiver_t *receiver,
    uint64_t session, size_t packet_size, uint64_t now_ms, uint32_t timeout_ms);
passport_receiver_state_t passport_receiver_receive(passport_receiver_t *receiver,
    uint64_t session, const uint8_t *packet, size_t length, uint64_t now_ms);
passport_receiver_state_t passport_receiver_tick(passport_receiver_t *receiver,
    uint64_t session, uint64_t now_ms);
// Copy out only a complete, unexpired message. Insufficient capacity preserves
// it until the same deadline. Success consumes the session and wipes RAM.
bool passport_receiver_take(passport_receiver_t *receiver, uint64_t session,
    uint64_t now_ms, uint8_t *output, size_t capacity, size_t *length,
    uint32_t *transfer_id);
// Local disconnect/queue overflow/cancellation must call close. No ACK should
// be sent until receive returns PARTIAL, COMPLETE or DUPLICATE.
void passport_receiver_close(passport_receiver_t *receiver);
