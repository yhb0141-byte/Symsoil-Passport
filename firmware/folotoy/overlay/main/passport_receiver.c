#include "passport_receiver.h"

#include <string.h>

void passport_receiver_close(passport_receiver_t *receiver)
{
    if (receiver) memset(receiver, 0, sizeof(*receiver));
}

static passport_receiver_state_t fail(passport_receiver_t *r, passport_receiver_state_t state)
{
    passport_receiver_close(r);
    r->state = state;
    return state;
}

passport_receiver_state_t passport_receiver_open(passport_receiver_t *r,
    uint64_t session, size_t packet_size, uint64_t now_ms, uint32_t timeout_ms)
{
    if (!r || !session || packet_size <= PASSPORT_TRANSPORT_HEADER_SIZE ||
        packet_size > PASSPORT_TRANSPORT_PACKET_MAX || !timeout_ms ||
        timeout_ms > PASSPORT_RECEIVER_TIMEOUT_MAX_MS) return PASSPORT_RECEIVER_BAD_ARGUMENT;
    if (r->state == PASSPORT_RECEIVER_READY || r->state == PASSPORT_RECEIVER_PARTIAL ||
        r->state == PASSPORT_RECEIVER_COMPLETE || r->state == PASSPORT_RECEIVER_CONSUMED)
        return PASSPORT_RECEIVER_BAD_ARGUMENT;
    passport_receiver_close(r);
    r->session = session;
    r->packet_size = packet_size;
    r->opened_ms = r->last_ms = now_ms;
    r->timeout_ms = timeout_ms;
    return r->state = PASSPORT_RECEIVER_READY;
}

passport_receiver_state_t passport_receiver_tick(passport_receiver_t *r,
    uint64_t session, uint64_t now_ms)
{
    if (!r) return PASSPORT_RECEIVER_BAD_ARGUMENT;
    if (!session || session != r->session) return PASSPORT_RECEIVER_STALE_SESSION;
    if (now_ms < r->last_ms || now_ms - r->opened_ms >= r->timeout_ms)
        return fail(r, PASSPORT_RECEIVER_EXPIRED);
    r->last_ms = now_ms;
    return r->state;
}

passport_receiver_state_t passport_receiver_receive(passport_receiver_t *r,
    uint64_t session, const uint8_t *packet, size_t length, uint64_t now_ms)
{
    passport_receiver_state_t state = passport_receiver_tick(r, session, now_ms);
    if (state != PASSPORT_RECEIVER_READY && state != PASSPORT_RECEIVER_PARTIAL &&
        state != PASSPORT_RECEIVER_COMPLETE && state != PASSPORT_RECEIVER_CONSUMED) return state;
    passport_transport_packet_t p;
    if (!packet || length > r->packet_size || !passport_transport_parse(packet, length, &p) ||
        !p.payload_length) return fail(r, PASSPORT_RECEIVER_REJECTED);
    const size_t chunk_size = r->packet_size - PASSPORT_TRANSPORT_HEADER_SIZE;
    // All non-final chunks have the negotiated size. Preflight the maximum
    // possible final byte before accepting even the first fragment.
    if ((!p.final_chunk && p.payload_length != chunk_size) ||
        (size_t)(p.chunk_count - 1) > (PASSPORT_RECEIVER_MESSAGE_MAX - 1) / chunk_size ||
        (p.final_chunk && (size_t)(p.chunk_count - 1) * chunk_size + p.payload_length >
            PASSPORT_RECEIVER_MESSAGE_MAX)) return fail(r, PASSPORT_RECEIVER_REJECTED);
    if (r->next_chunk) {
        if (p.transfer_id != r->transfer_id || p.chunk_count != r->chunk_count)
            return fail(r, PASSPORT_RECEIVER_REJECTED);
        if (p.chunk_index == r->next_chunk - 1) {
            if (p.payload_length == r->last_length &&
                memcmp(r->message + r->last_offset, p.payload, p.payload_length) == 0)
                return PASSPORT_RECEIVER_DUPLICATE;
            return fail(r, PASSPORT_RECEIVER_REJECTED);
        }
    }
    if (state == PASSPORT_RECEIVER_COMPLETE || state == PASSPORT_RECEIVER_CONSUMED || p.chunk_index != r->next_chunk ||
        p.payload_length > PASSPORT_RECEIVER_MESSAGE_MAX - r->length)
        return fail(r, PASSPORT_RECEIVER_REJECTED);
    r->transfer_id = p.transfer_id;
    r->chunk_count = p.chunk_count;
    r->last_offset = r->length;
    r->last_length = p.payload_length;
    memcpy(r->message + r->length, p.payload, p.payload_length);
    r->length += p.payload_length;
    r->next_chunk++;
    return r->state = p.final_chunk ? PASSPORT_RECEIVER_COMPLETE : PASSPORT_RECEIVER_PARTIAL;
}

bool passport_receiver_take(passport_receiver_t *r, uint64_t session,
    uint64_t now_ms, uint8_t *output, size_t capacity, size_t *length, uint32_t *transfer_id)
{
    if (length) *length = 0;
    if (transfer_id) *transfer_id = 0;
    if (passport_receiver_tick(r, session, now_ms) != PASSPORT_RECEIVER_COMPLETE ||
        !output || !length || !transfer_id || capacity < r->length) return false;
    memcpy(output, r->message, r->length);
    *length = r->length;
    *transfer_id = r->transfer_id;
    // Retain only the exact final payload for lost-final-ACK retries. Header
    // identity/shape is reconstructed and checked above; CRC is never an identity
    // proof. A single-fragment message retains its entire payload until expiry;
    // CONSUMED cannot be taken again.
    memmove(r->message, r->message + r->last_offset, r->last_length);
    memset(r->message + r->last_length, 0, sizeof(r->message) - r->last_length);
    r->length = 0;
    r->last_offset = 0;
    r->state = PASSPORT_RECEIVER_CONSUMED;
    return true;
}
