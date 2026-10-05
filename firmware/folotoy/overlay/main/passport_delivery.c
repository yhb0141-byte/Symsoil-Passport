#include "passport_delivery.h"

#include <string.h>

static passport_delivery_state_t map_transport(passport_transport_state_t state)
{
    switch (state) {
    case PASSPORT_TRANSPORT_READY: return PASSPORT_DELIVERY_READY;
    case PASSPORT_TRANSPORT_WAITING_ACK: return PASSPORT_DELIVERY_WAITING_ACK;
    case PASSPORT_TRANSPORT_DISCONNECTED: return PASSPORT_DELIVERY_DISCONNECTED;
    case PASSPORT_TRANSPORT_COMPLETE: return PASSPORT_DELIVERY_AWAITING_RESULT;
    case PASSPORT_TRANSPORT_EXHAUSTED: return PASSPORT_DELIVERY_EXHAUSTED;
    case PASSPORT_TRANSPORT_IDLE: return PASSPORT_DELIVERY_IDLE;
    case PASSPORT_TRANSPORT_INVALID: return PASSPORT_DELIVERY_INVALID;
    }
    return PASSPORT_DELIVERY_INVALID;
}

static passport_delivery_result_t prepare(passport_delivery_t *delivery)
{
    if (!passport_outbox_envelope_encode(&delivery->pending, delivery->envelope,
                                         sizeof(delivery->envelope),
                                         &delivery->envelope_length)) {
        delivery->state = PASSPORT_DELIVERY_CORRUPT;
        return PASSPORT_DELIVERY_BAD_DATA;
    }
    delivery->state = map_transport(passport_transport_begin(
        &delivery->transport, delivery->envelope, delivery->envelope_length,
        delivery->pending.transfer_id, delivery->packet_size,
        delivery->max_attempts));
    return delivery->state == PASSPORT_DELIVERY_READY ?
        PASSPORT_DELIVERY_OK : PASSPORT_DELIVERY_BAD_ARGUMENT;
}

passport_delivery_result_t passport_delivery_open(
    passport_delivery_t *delivery,
    const passport_outbox_store_t *store,
    size_t packet_size,
    uint8_t max_attempts)
{
    if (!delivery || !store || !store->read || !store->write ||
        packet_size <= PASSPORT_TRANSPORT_HEADER_SIZE ||
        packet_size > PASSPORT_TRANSPORT_PACKET_MAX || !max_attempts) {
        if (delivery) delivery->state = PASSPORT_DELIVERY_INVALID;
        return PASSPORT_DELIVERY_BAD_ARGUMENT;
    }
    memset(delivery, 0, sizeof(*delivery));
    delivery->store = *store;
    delivery->packet_size = packet_size;
    delivery->max_attempts = max_attempts;
    const passport_outbox_result_t loaded =
        passport_outbox_load(&delivery->store, &delivery->pending);
    if (loaded == PASSPORT_OUTBOX_EMPTY) {
        delivery->state = PASSPORT_DELIVERY_IDLE;
        return PASSPORT_DELIVERY_EMPTY;
    }
    if (loaded == PASSPORT_OUTBOX_CORRUPT) {
        delivery->state = PASSPORT_DELIVERY_CORRUPT;
        return PASSPORT_DELIVERY_BAD_DATA;
    }
    if (loaded != PASSPORT_OUTBOX_READY) {
        delivery->state = PASSPORT_DELIVERY_STORAGE_ERROR;
        return PASSPORT_DELIVERY_IO_ERROR;
    }
    return prepare(delivery);
}

passport_delivery_result_t passport_delivery_queue(
    passport_delivery_t *delivery,
    const char *canonical_frame,
    size_t frame_length,
    const uint8_t signature[PASSPORT_OUTBOX_SIGNATURE_SIZE],
    uint32_t transfer_id)
{
    if (!delivery || delivery->state == PASSPORT_DELIVERY_INVALID ||
        delivery->state == PASSPORT_DELIVERY_CORRUPT ||
        delivery->state == PASSPORT_DELIVERY_STORAGE_ERROR) {
        return PASSPORT_DELIVERY_BAD_ARGUMENT;
    }
    const passport_outbox_result_t saved = passport_outbox_save(
        &delivery->store, canonical_frame, frame_length, signature,
        transfer_id, &delivery->pending);
    if (saved == PASSPORT_OUTBOX_BUSY) return PASSPORT_DELIVERY_BUSY;
    if (saved == PASSPORT_OUTBOX_INVALID) return PASSPORT_DELIVERY_BAD_ARGUMENT;
    if (saved != PASSPORT_OUTBOX_READY) {
        delivery->state = PASSPORT_DELIVERY_STORAGE_ERROR;
        return PASSPORT_DELIVERY_IO_ERROR;
    }
    return prepare(delivery);
}

passport_delivery_state_t passport_delivery_next_packet(
    passport_delivery_t *delivery,
    uint8_t *packet,
    size_t capacity,
    size_t *length)
{
    if (!delivery) return PASSPORT_DELIVERY_INVALID;
    delivery->state = map_transport(passport_transport_next(
        &delivery->transport, packet, capacity, length));
    return delivery->state;
}

passport_delivery_state_t passport_delivery_ack(
    passport_delivery_t *delivery,
    uint32_t transfer_id,
    uint16_t chunk_index,
    bool accepted)
{
    if (!delivery) return PASSPORT_DELIVERY_INVALID;
    delivery->state = map_transport(passport_transport_ack(
        &delivery->transport, transfer_id, chunk_index, accepted));
    return delivery->state;
}

passport_delivery_state_t passport_delivery_timeout(passport_delivery_t *delivery)
{
    if (!delivery) return PASSPORT_DELIVERY_INVALID;
    delivery->state = map_transport(passport_transport_timeout(&delivery->transport));
    return delivery->state;
}

passport_delivery_state_t passport_delivery_disconnect(passport_delivery_t *delivery)
{
    if (!delivery) return PASSPORT_DELIVERY_INVALID;
    delivery->state = map_transport(passport_transport_disconnect(&delivery->transport));
    return delivery->state;
}

passport_delivery_state_t passport_delivery_reconnect(passport_delivery_t *delivery)
{
    if (!delivery) return PASSPORT_DELIVERY_INVALID;
    delivery->state = map_transport(passport_transport_reconnect(&delivery->transport));
    return delivery->state;
}

passport_delivery_result_t passport_delivery_retry(passport_delivery_t *delivery)
{
    if (!delivery || (delivery->state != PASSPORT_DELIVERY_AWAITING_RESULT &&
                      delivery->state != PASSPORT_DELIVERY_EXHAUSTED)) {
        return PASSPORT_DELIVERY_BAD_ARGUMENT;
    }
    return prepare(delivery);
}

passport_delivery_result_t passport_delivery_finalize_signed(
    passport_delivery_t *delivery,
    const passport_delivery_result_frame_t *result,
    const char *trusted_community_id,
    const uint8_t service_public_x[PASSPORT_P256_COORD_SIZE],
    const uint8_t service_public_y[PASSPORT_P256_COORD_SIZE],
    const uint8_t service_signature[PASSPORT_P256_P1363_SIZE])
{
    if (!delivery || !result || !trusted_community_id || !service_public_x ||
        !service_public_y || !service_signature) {
        return PASSPORT_DELIVERY_BAD_ARGUMENT;
    }
    if (delivery->state == PASSPORT_DELIVERY_IDLE) return PASSPORT_DELIVERY_EMPTY;
    if (!result->community_id || strcmp(result->community_id, trusted_community_id) != 0 ||
        result->transfer_id != delivery->pending.transfer_id) {
        return PASSPORT_DELIVERY_MISMATCH;
    }

    uint8_t reply_signature[PASSPORT_OUTBOX_SIGNATURE_SIZE];
    size_t reply_signature_length = 0;
    if (passport_base64url_decode(result->reply_signature, reply_signature,
            sizeof(reply_signature), &reply_signature_length) != PASSPORT_PROTOCOL_OK ||
        reply_signature_length != sizeof(reply_signature)) {
        return PASSPORT_DELIVERY_BAD_DATA;
    }
    if (memcmp(reply_signature, delivery->pending.signature,
               PASSPORT_OUTBOX_SIGNATURE_SIZE) != 0) {
        return PASSPORT_DELIVERY_MISMATCH;
    }

    char canonical[PASSPORT_DELIVERY_RESULT_FRAME_MAX];
    size_t canonical_length = 0;
    if (passport_delivery_result_frame_json(result, canonical, sizeof(canonical),
            &canonical_length) != PASSPORT_PROTOCOL_OK) {
        return PASSPORT_DELIVERY_BAD_DATA;
    }
    if (!passport_p256_verify_p1363(service_public_x, service_public_y,
            (const uint8_t *)canonical, canonical_length, service_signature)) {
        return PASSPORT_DELIVERY_UNTRUSTED_RESULT;
    }

    const passport_outbox_result_t cleared = passport_outbox_clear(&delivery->store);
    if (cleared != PASSPORT_OUTBOX_EMPTY) {
        delivery->state = PASSPORT_DELIVERY_STORAGE_ERROR;
        return PASSPORT_DELIVERY_IO_ERROR;
    }
    memset(&delivery->pending, 0, sizeof(delivery->pending));
    memset(delivery->envelope, 0, sizeof(delivery->envelope));
    delivery->envelope_length = 0;
    memset(&delivery->transport, 0, sizeof(delivery->transport));
    delivery->state = PASSPORT_DELIVERY_IDLE;
    return PASSPORT_DELIVERY_OK;
}
