#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PASSPORT_TRANSPORT_HEADER_SIZE 18
#define PASSPORT_TRANSPORT_PACKET_MAX 512

typedef enum {
    PASSPORT_TRANSPORT_IDLE = 0,
    PASSPORT_TRANSPORT_READY,
    PASSPORT_TRANSPORT_WAITING_ACK,
    PASSPORT_TRANSPORT_DISCONNECTED,
    PASSPORT_TRANSPORT_COMPLETE,
    PASSPORT_TRANSPORT_EXHAUSTED,
    PASSPORT_TRANSPORT_INVALID,
} passport_transport_state_t;

typedef struct {
    const uint8_t *message;
    size_t message_length;
    size_t packet_size;
    size_t chunk_payload;
    uint32_t transfer_id;
    uint16_t chunk_index;
    uint16_t chunk_count;
    uint8_t attempts;
    uint8_t max_attempts;
    passport_transport_state_t state;
} passport_transport_t;

typedef struct {
    uint32_t transfer_id;
    uint16_t chunk_index;
    uint16_t chunk_count;
    bool final_chunk;
    const uint8_t *payload;
    size_t payload_length;
} passport_transport_packet_t;

// CRC covers the packet header and payload to detect torn/corrupt frames. It
// is not a MAC: callers must carry these packets over an authenticated session.

passport_transport_state_t passport_transport_begin(
    passport_transport_t *transport,
    const uint8_t *message,
    size_t message_length,
    uint32_t transfer_id,
    size_t packet_size,
    uint8_t max_attempts);
passport_transport_state_t passport_transport_next(
    passport_transport_t *transport, uint8_t *packet, size_t capacity, size_t *length);
passport_transport_state_t passport_transport_ack(
    passport_transport_t *transport, uint32_t transfer_id, uint16_t chunk_index, bool accepted);
passport_transport_state_t passport_transport_timeout(passport_transport_t *transport);
passport_transport_state_t passport_transport_disconnect(passport_transport_t *transport);
passport_transport_state_t passport_transport_reconnect(passport_transport_t *transport);
bool passport_transport_parse(
    const uint8_t *packet, size_t length, passport_transport_packet_t *parsed);
