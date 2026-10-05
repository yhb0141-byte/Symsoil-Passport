#include "passport_transport.h"

#include <string.h>

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

static uint32_t crc_update(uint32_t crc, const uint8_t *data, size_t length)
{
    for (size_t index = 0; index < length; index++) {
        crc ^= data[index];
        for (unsigned bit = 0; bit < 8; bit++) {
            const uint32_t mask = (uint32_t)-(int32_t)(crc & 1);
            crc = (crc >> 1) ^ (UINT32_C(0xedb88320) & mask);
        }
    }
    return crc;
}

static uint32_t packet_crc(const uint8_t *packet, size_t payload_length)
{
    uint32_t crc = crc_update(UINT32_C(0xffffffff), packet, 14);
    crc = crc_update(crc, packet + PASSPORT_TRANSPORT_HEADER_SIZE, payload_length);
    return ~crc;
}

passport_transport_state_t passport_transport_begin(
    passport_transport_t *transport,
    const uint8_t *message,
    size_t message_length,
    uint32_t transfer_id,
    size_t packet_size,
    uint8_t max_attempts)
{
    if (!transport || !message || !message_length || !transfer_id || !max_attempts ||
        packet_size <= PASSPORT_TRANSPORT_HEADER_SIZE || packet_size > PASSPORT_TRANSPORT_PACKET_MAX) {
        return PASSPORT_TRANSPORT_INVALID;
    }
    const size_t payload = packet_size - PASSPORT_TRANSPORT_HEADER_SIZE;
    const size_t chunks = message_length / payload + (message_length % payload != 0);
    if (!chunks || chunks > UINT16_MAX) return PASSPORT_TRANSPORT_INVALID;
    *transport = (passport_transport_t) {
        .message = message,
        .message_length = message_length,
        .packet_size = packet_size,
        .chunk_payload = payload,
        .transfer_id = transfer_id,
        .chunk_count = (uint16_t)chunks,
        .max_attempts = max_attempts,
        .state = PASSPORT_TRANSPORT_READY,
    };
    return transport->state;
}

passport_transport_state_t passport_transport_next(
    passport_transport_t *transport, uint8_t *packet, size_t capacity, size_t *length)
{
    if (length) *length = 0;
    if (!transport || !packet || !length || transport->state != PASSPORT_TRANSPORT_READY) {
        return transport ? transport->state : PASSPORT_TRANSPORT_INVALID;
    }
    if (transport->attempts >= transport->max_attempts) {
        transport->state = PASSPORT_TRANSPORT_EXHAUSTED;
        return transport->state;
    }
    const size_t offset = (size_t)transport->chunk_index * transport->chunk_payload;
    const size_t remaining = transport->message_length - offset;
    const size_t payload_length = remaining < transport->chunk_payload ? remaining : transport->chunk_payload;
    const size_t packet_length = PASSPORT_TRANSPORT_HEADER_SIZE + payload_length;
    if (capacity < packet_length) return PASSPORT_TRANSPORT_INVALID;

    packet[0] = 'S';
    packet[1] = 'P';
    packet[2] = 1;
    packet[3] = transport->chunk_index + 1 == transport->chunk_count ? 1 : 0;
    put_u32(packet + 4, transport->transfer_id);
    put_u16(packet + 8, transport->chunk_index);
    put_u16(packet + 10, transport->chunk_count);
    put_u16(packet + 12, (uint16_t)payload_length);
    memcpy(packet + PASSPORT_TRANSPORT_HEADER_SIZE, transport->message + offset, payload_length);
    put_u32(packet + 14, packet_crc(packet, payload_length));
    transport->attempts++;
    transport->state = PASSPORT_TRANSPORT_WAITING_ACK;
    *length = packet_length;
    return transport->state;
}

passport_transport_state_t passport_transport_ack(
    passport_transport_t *transport, uint32_t transfer_id, uint16_t chunk_index, bool accepted)
{
    if (!transport || transport->state != PASSPORT_TRANSPORT_WAITING_ACK) {
        return transport ? transport->state : PASSPORT_TRANSPORT_INVALID;
    }
    if (transfer_id != transport->transfer_id || chunk_index != transport->chunk_index) {
        return transport->state;
    }
    if (!accepted) {
        transport->state = transport->attempts >= transport->max_attempts ?
            PASSPORT_TRANSPORT_EXHAUSTED : PASSPORT_TRANSPORT_READY;
        return transport->state;
    }
    transport->chunk_index++;
    transport->attempts = 0;
    transport->state = transport->chunk_index == transport->chunk_count ?
        PASSPORT_TRANSPORT_COMPLETE : PASSPORT_TRANSPORT_READY;
    return transport->state;
}

passport_transport_state_t passport_transport_timeout(passport_transport_t *transport)
{
    if (!transport || transport->state != PASSPORT_TRANSPORT_WAITING_ACK) {
        return transport ? transport->state : PASSPORT_TRANSPORT_INVALID;
    }
    transport->state = transport->attempts >= transport->max_attempts ?
        PASSPORT_TRANSPORT_EXHAUSTED : PASSPORT_TRANSPORT_READY;
    return transport->state;
}

passport_transport_state_t passport_transport_disconnect(passport_transport_t *transport)
{
    if (!transport || transport->state == PASSPORT_TRANSPORT_IDLE ||
        transport->state == PASSPORT_TRANSPORT_COMPLETE || transport->state == PASSPORT_TRANSPORT_INVALID) {
        return transport ? transport->state : PASSPORT_TRANSPORT_INVALID;
    }
    transport->state = PASSPORT_TRANSPORT_DISCONNECTED;
    return transport->state;
}

passport_transport_state_t passport_transport_reconnect(passport_transport_t *transport)
{
    if (!transport || transport->state != PASSPORT_TRANSPORT_DISCONNECTED) {
        return transport ? transport->state : PASSPORT_TRANSPORT_INVALID;
    }
    transport->attempts = 0;
    transport->state = PASSPORT_TRANSPORT_READY;
    return transport->state;
}

bool passport_transport_parse(
    const uint8_t *packet, size_t length, passport_transport_packet_t *parsed)
{
    if (!packet || !parsed || length < PASSPORT_TRANSPORT_HEADER_SIZE ||
        packet[0] != 'S' || packet[1] != 'P' || packet[2] != 1 || (packet[3] & ~1u)) return false;
    const size_t payload_length = get_u16(packet + 12);
    if (length != PASSPORT_TRANSPORT_HEADER_SIZE + payload_length) return false;
    const uint16_t chunk_index = get_u16(packet + 8);
    const uint16_t chunk_count = get_u16(packet + 10);
    if (!chunk_count || chunk_index >= chunk_count ||
        ((packet[3] & 1u) != 0) != (chunk_index + 1 == chunk_count) ||
        get_u32(packet + 14) != packet_crc(packet, payload_length)) {
        return false;
    }
    *parsed = (passport_transport_packet_t) {
        .transfer_id = get_u32(packet + 4),
        .chunk_index = chunk_index,
        .chunk_count = chunk_count,
        .final_chunk = (packet[3] & 1u) != 0,
        .payload = packet + PASSPORT_TRANSPORT_HEADER_SIZE,
        .payload_length = payload_length,
    };
    return parsed->transfer_id != 0;
}
