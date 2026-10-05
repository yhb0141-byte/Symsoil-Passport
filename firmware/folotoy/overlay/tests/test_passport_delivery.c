#include <assert.h>
#include <string.h>

#include "passport_delivery.h"

typedef struct {
    uint8_t data[PASSPORT_OUTBOX_SLOT_COUNT][PASSPORT_OUTBOX_RECORD_MAX];
    size_t length[PASSPORT_OUTBOX_SLOT_COUNT];
    bool present[PASSPORT_OUTBOX_SLOT_COUNT];
    bool fail_read;
    size_t writes;
    size_t fail_on_write;
} memory_store_t;

static passport_store_result_t memory_read(
    void *context, size_t slot, uint8_t *output, size_t capacity, size_t *length)
{
    memory_store_t *memory = context;
    if (!memory || memory->fail_read || slot >= PASSPORT_OUTBOX_SLOT_COUNT) {
        return PASSPORT_STORE_ERROR;
    }
    if (!memory->present[slot]) return PASSPORT_STORE_NOT_FOUND;
    if (memory->length[slot] > capacity) return PASSPORT_STORE_ERROR;
    memcpy(output, memory->data[slot], memory->length[slot]);
    *length = memory->length[slot];
    return PASSPORT_STORE_OK;
}

static bool memory_write(void *context, size_t slot, const uint8_t *data, size_t length)
{
    memory_store_t *memory = context;
    if (!memory) return false;
    memory->writes++;
    if (slot >= PASSPORT_OUTBOX_SLOT_COUNT || length > PASSPORT_OUTBOX_RECORD_MAX ||
        memory->writes == memory->fail_on_write) return false;
    memcpy(memory->data[slot], data, length);
    memory->length[slot] = length;
    memory->present[slot] = true;
    return true;
}

static passport_outbox_store_t store_for(memory_store_t *memory)
{
    return (passport_outbox_store_t) {
        .context = memory,
        .read = memory_read,
        .write = memory_write,
    };
}

static void finish_packets(passport_delivery_t *delivery)
{
    uint8_t packet[PASSPORT_TRANSPORT_PACKET_MAX];
    size_t length = 0;
    while (delivery->state != PASSPORT_DELIVERY_AWAITING_RESULT) {
        assert(passport_delivery_next_packet(delivery, packet, sizeof(packet), &length) ==
               PASSPORT_DELIVERY_WAITING_ACK);
        passport_transport_packet_t parsed;
        assert(passport_transport_parse(packet, length, &parsed));
        assert(passport_delivery_ack(delivery, parsed.transfer_id,
                                     parsed.chunk_index, true) ==
               (parsed.final_chunk ? PASSPORT_DELIVERY_AWAITING_RESULT :
                                     PASSPORT_DELIVERY_READY));
    }
}

static void test_reboot_and_final_result(void)
{
    memory_store_t memory = { 0 };
    passport_outbox_store_t store = store_for(&memory);
    passport_delivery_t delivery;
    assert(passport_delivery_open(&delivery, &store, 64, 3) == PASSPORT_DELIVERY_EMPTY);
    assert(delivery.state == PASSPORT_DELIVERY_IDLE);

    const char frame[] =
        "{\"counter\":8,\"protocol\":\"symsoil-passport/1\",\"requestId\":\"synthetic-delivery\"}";
    uint8_t signature[PASSPORT_OUTBOX_SIGNATURE_SIZE];
    memset(signature, 0x5a, sizeof(signature));
    const uint32_t transfer_id = UINT32_C(0x10293847);
    assert(passport_delivery_queue(&delivery, frame, strlen(frame), signature,
                                   transfer_id) == PASSPORT_DELIVERY_OK);
    assert(delivery.state == PASSPORT_DELIVERY_READY);

    uint8_t before[PASSPORT_TRANSPORT_PACKET_MAX];
    size_t before_length = 0;
    assert(passport_delivery_next_packet(&delivery, before, sizeof(before), &before_length) ==
           PASSPORT_DELIVERY_WAITING_ACK);

    // Simulate power loss before ACK. Reopening must emit the exact same first
    // packet; it must not request a new approval or signature.
    passport_delivery_t rebooted;
    assert(passport_delivery_open(&rebooted, &store, 64, 3) == PASSPORT_DELIVERY_OK);
    uint8_t after[PASSPORT_TRANSPORT_PACKET_MAX];
    size_t after_length = 0;
    assert(passport_delivery_next_packet(&rebooted, after, sizeof(after), &after_length) ==
           PASSPORT_DELIVERY_WAITING_ACK);
    assert(after_length == before_length && memcmp(after, before, before_length) == 0);
    assert(passport_delivery_disconnect(&rebooted) == PASSPORT_DELIVERY_DISCONNECTED);
    assert(passport_delivery_reconnect(&rebooted) == PASSPORT_DELIVERY_READY);
    assert(passport_delivery_next_packet(&rebooted, after, sizeof(after), &after_length) ==
           PASSPORT_DELIVERY_WAITING_ACK);
    assert(after_length == before_length && memcmp(after, before, before_length) == 0);

    passport_transport_packet_t parsed;
    assert(passport_transport_parse(after, after_length, &parsed));
    assert(passport_delivery_ack(&rebooted, parsed.transfer_id, parsed.chunk_index, true) ==
           PASSPORT_DELIVERY_READY);
    finish_packets(&rebooted);

    passport_outbox_message_t still_pending;
    assert(passport_outbox_load(&store, &still_pending) == PASSPORT_OUTBOX_READY);
    assert(still_pending.transfer_id == transfer_id);

    // Fragment completion is not a business result. A retry after a lost
    // response starts at the same first packet over the same signed envelope.
    assert(passport_delivery_retry(&rebooted) == PASSPORT_DELIVERY_OK);
    assert(passport_delivery_next_packet(&rebooted, after, sizeof(after), &after_length) ==
           PASSPORT_DELIVERY_WAITING_ACK);
    assert(after_length == before_length && memcmp(after, before, before_length) == 0);

    uint8_t wrong_signature[PASSPORT_OUTBOX_SIGNATURE_SIZE];
    memcpy(wrong_signature, signature, sizeof(signature));
    wrong_signature[0] ^= 1;
    assert(passport_delivery_finalize(&rebooted, transfer_id + 1, signature,
                                      PASSPORT_DELIVERY_ACCEPTED) ==
           PASSPORT_DELIVERY_MISMATCH);
    assert(passport_delivery_finalize(&rebooted, transfer_id, wrong_signature,
                                      PASSPORT_DELIVERY_ACCEPTED) ==
           PASSPORT_DELIVERY_MISMATCH);
    assert(passport_outbox_load(&store, &still_pending) == PASSPORT_OUTBOX_READY);

    // A matching final rejection is authoritative too: it closes this exact
    // reply but never converts it into acceptance.
    assert(passport_delivery_finalize(&rebooted, transfer_id, signature,
                                      PASSPORT_DELIVERY_REJECTED) == PASSPORT_DELIVERY_OK);
    assert(rebooted.state == PASSPORT_DELIVERY_IDLE);
    assert(passport_outbox_load(&store, &still_pending) == PASSPORT_OUTBOX_EMPTY);
}

static void test_busy_exhaustion_and_recovery(void)
{
    memory_store_t memory = { 0 };
    passport_outbox_store_t store = store_for(&memory);
    passport_delivery_t delivery;
    assert(passport_delivery_open(&delivery, &store, 48, 2) == PASSPORT_DELIVERY_EMPTY);
    const char first[] = "{\"counter\":1}";
    const char second[] = "{\"counter\":2}";
    uint8_t signature1[PASSPORT_OUTBOX_SIGNATURE_SIZE];
    uint8_t signature2[PASSPORT_OUTBOX_SIGNATURE_SIZE];
    memset(signature1, 1, sizeof(signature1));
    memset(signature2, 2, sizeof(signature2));
    assert(passport_delivery_queue(&delivery, first, strlen(first), signature1, 11) ==
           PASSPORT_DELIVERY_OK);
    assert(passport_delivery_queue(&delivery, second, strlen(second), signature2, 12) ==
           PASSPORT_DELIVERY_BUSY);

    uint8_t packet[PASSPORT_TRANSPORT_PACKET_MAX];
    size_t length = 0;
    assert(passport_delivery_next_packet(&delivery, packet, sizeof(packet), &length) ==
           PASSPORT_DELIVERY_WAITING_ACK);
    assert(passport_delivery_timeout(&delivery) == PASSPORT_DELIVERY_READY);
    assert(passport_delivery_next_packet(&delivery, packet, sizeof(packet), &length) ==
           PASSPORT_DELIVERY_WAITING_ACK);
    assert(passport_delivery_timeout(&delivery) == PASSPORT_DELIVERY_EXHAUSTED);
    assert(passport_delivery_retry(&delivery) == PASSPORT_DELIVERY_OK);

    // A server may have committed before the device rebooted. A matching
    // authenticated final result can therefore clear before another send.
    assert(passport_delivery_finalize(&delivery, 11, signature1,
                                      PASSPORT_DELIVERY_ACCEPTED) == PASSPORT_DELIVERY_OK);
    assert(passport_delivery_queue(&delivery, second, strlen(second), signature2, 12) ==
           PASSPORT_DELIVERY_OK);
}

static void test_storage_faults(void)
{
    const char frame[] = "{\"counter\":3}";
    uint8_t signature[PASSPORT_OUTBOX_SIGNATURE_SIZE];
    memset(signature, 3, sizeof(signature));

    memory_store_t primary_failure = { .fail_on_write = 1 };
    passport_outbox_store_t primary_store = store_for(&primary_failure);
    passport_delivery_t delivery;
    assert(passport_delivery_open(&delivery, &primary_store, 64, 3) ==
           PASSPORT_DELIVERY_EMPTY);
    assert(passport_delivery_queue(&delivery, frame, strlen(frame), signature, 31) ==
           PASSPORT_DELIVERY_IO_ERROR);
    passport_delivery_t rebooted;
    primary_failure.fail_on_write = 0;
    assert(passport_delivery_open(&rebooted, &primary_store, 64, 3) ==
           PASSPORT_DELIVERY_EMPTY);

    memory_store_t mirror_failure = { .fail_on_write = 2 };
    passport_outbox_store_t mirror_store = store_for(&mirror_failure);
    assert(passport_delivery_open(&delivery, &mirror_store, 64, 3) ==
           PASSPORT_DELIVERY_EMPTY);
    assert(passport_delivery_queue(&delivery, frame, strlen(frame), signature, 32) ==
           PASSPORT_DELIVERY_IO_ERROR);
    mirror_failure.fail_on_write = 0;
    assert(passport_delivery_open(&rebooted, &mirror_store, 64, 3) ==
           PASSPORT_DELIVERY_OK);
    assert(rebooted.pending.transfer_id == 32);

    mirror_failure.data[0][0] ^= 1;
    mirror_failure.data[1][0] ^= 1;
    assert(passport_delivery_open(&rebooted, &mirror_store, 64, 3) ==
           PASSPORT_DELIVERY_BAD_DATA);
    assert(rebooted.state == PASSPORT_DELIVERY_CORRUPT);

    memory_store_t clear_failure = { 0 };
    passport_outbox_store_t clear_store = store_for(&clear_failure);
    assert(passport_delivery_open(&delivery, &clear_store, 64, 3) ==
           PASSPORT_DELIVERY_EMPTY);
    assert(passport_delivery_queue(&delivery, frame, strlen(frame), signature, 33) ==
           PASSPORT_DELIVERY_OK);
    clear_failure.writes = 0;
    clear_failure.fail_on_write = 1;
    assert(passport_delivery_finalize(&delivery, 33, signature,
                                      PASSPORT_DELIVERY_ACCEPTED) ==
           PASSPORT_DELIVERY_IO_ERROR);
    passport_outbox_message_t pending;
    assert(passport_outbox_load(&clear_store, &pending) == PASSPORT_OUTBOX_READY);
    assert(pending.transfer_id == 33);
    clear_failure.writes = 0;
    clear_failure.fail_on_write = 0;
    assert(passport_delivery_finalize(&delivery, 33, signature,
                                      PASSPORT_DELIVERY_ACCEPTED) ==
           PASSPORT_DELIVERY_OK);
    assert(passport_outbox_load(&clear_store, &pending) == PASSPORT_OUTBOX_EMPTY);
}

int main(void)
{
    test_reboot_and_final_result();
    test_busy_exhaustion_and_recovery();
    test_storage_faults();
    return 0;
}
