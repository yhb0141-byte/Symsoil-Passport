#include <assert.h>
#include <string.h>

#include "passport_delivery.h"

static const char MEMBER_SIGNATURE_TEXT[] =
    "iORbwF-hii-92h05WpsQzMVXXMhjYps7NljUyZYeOPjB39z18rrj2y1SKT8Ng4hkmQU4Xf2HiMN5NA_iMscwjg";
static const uint8_t SERVICE_PUBLIC_X[PASSPORT_P256_COORD_SIZE] = { 0x11 };
static const uint8_t SERVICE_PUBLIC_Y[PASSPORT_P256_COORD_SIZE] = { 0x22 };
static const uint8_t SERVICE_SIGNATURE[PASSPORT_P256_P1363_SIZE] = { 0x33 };
static char expected_service_message[PASSPORT_DELIVERY_RESULT_FRAME_MAX];
static size_t expected_service_message_length;

// Host-only trust-boundary double. ESP-IDF links the mbedTLS implementation;
// this double accepts only the exact canonical bytes prepared by the test.
bool passport_p256_verify_p1363(
    const uint8_t public_x[PASSPORT_P256_COORD_SIZE],
    const uint8_t public_y[PASSPORT_P256_COORD_SIZE],
    const uint8_t *message,
    size_t message_length,
    const uint8_t signature[PASSPORT_P256_P1363_SIZE])
{
    return memcmp(public_x, SERVICE_PUBLIC_X, sizeof(SERVICE_PUBLIC_X)) == 0 &&
        memcmp(public_y, SERVICE_PUBLIC_Y, sizeof(SERVICE_PUBLIC_Y)) == 0 &&
        memcmp(signature, SERVICE_SIGNATURE, sizeof(SERVICE_SIGNATURE)) == 0 &&
        message_length == expected_service_message_length &&
        memcmp(message, expected_service_message, message_length) == 0;
}

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

static void member_signature(uint8_t output[PASSPORT_OUTBOX_SIGNATURE_SIZE])
{
    size_t length = 0;
    assert(passport_base64url_decode(MEMBER_SIGNATURE_TEXT, output,
        PASSPORT_OUTBOX_SIGNATURE_SIZE, &length) == PASSPORT_PROTOCOL_OK);
    assert(length == PASSPORT_OUTBOX_SIGNATURE_SIZE);
}

static passport_delivery_result_frame_t result_frame(
    uint32_t transfer_id, const char *outcome)
{
    return (passport_delivery_result_frame_t) {
        .community_id = "synthetic-community",
        .outcome = outcome,
        .reply_signature = MEMBER_SIGNATURE_TEXT,
        .request_id = "synthetic-request",
        .result_id = "synthetic-result",
        .transfer_id = transfer_id,
    };
}

static void trust_exact_result(const passport_delivery_result_frame_t *result)
{
    assert(passport_delivery_result_frame_json(result, expected_service_message,
        sizeof(expected_service_message), &expected_service_message_length) ==
        PASSPORT_PROTOCOL_OK);
}

static passport_delivery_result_t finalize_signed(
    passport_delivery_t *delivery,
    const passport_delivery_result_frame_t *result)
{
    return passport_delivery_finalize_signed(delivery, result,
        "synthetic-community", SERVICE_PUBLIC_X, SERVICE_PUBLIC_Y,
        SERVICE_SIGNATURE);
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
    member_signature(signature);
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

    passport_delivery_result_frame_t result = result_frame(transfer_id, "accepted");
    trust_exact_result(&result);
    result.transfer_id++;
    assert(finalize_signed(&rebooted, &result) == PASSPORT_DELIVERY_MISMATCH);
    result = result_frame(transfer_id, "accepted");
    result.reply_signature =
        "cevsLz5SZq54cBmqKulrJXZlNlHDtUDaG0Zfv4DSHZdFYXuxxixV6Pf2HE3yrVCGEc07buswi7kzSjLD9IxnUA";
    assert(finalize_signed(&rebooted, &result) == PASSPORT_DELIVERY_MISMATCH);
    result = result_frame(transfer_id, "accepted");
    result.reply_signature = "short";
    assert(finalize_signed(&rebooted, &result) == PASSPORT_DELIVERY_BAD_DATA);
    result = result_frame(transfer_id, "accepted");
    result.community_id = "other-community";
    assert(finalize_signed(&rebooted, &result) == PASSPORT_DELIVERY_MISMATCH);
    result = result_frame(transfer_id, "accepted");
    result.request_id = "changed-request";
    assert(finalize_signed(&rebooted, &result) == PASSPORT_DELIVERY_UNTRUSTED_RESULT);
    result = result_frame(transfer_id, "accepted");
    result.result_id = "changed-result";
    assert(finalize_signed(&rebooted, &result) == PASSPORT_DELIVERY_UNTRUSTED_RESULT);
    result = result_frame(transfer_id, "rejected");
    assert(finalize_signed(&rebooted, &result) == PASSPORT_DELIVERY_UNTRUSTED_RESULT);
    result = result_frame(transfer_id, "pending");
    assert(finalize_signed(&rebooted, &result) == PASSPORT_DELIVERY_BAD_DATA);
    result = result_frame(transfer_id, "accepted");
    uint8_t wrong_service_signature[PASSPORT_P256_P1363_SIZE];
    memcpy(wrong_service_signature, SERVICE_SIGNATURE, sizeof(wrong_service_signature));
    wrong_service_signature[0] ^= 1;
    assert(passport_delivery_finalize_signed(&rebooted, &result,
        "synthetic-community", SERVICE_PUBLIC_X, SERVICE_PUBLIC_Y,
        wrong_service_signature) == PASSPORT_DELIVERY_UNTRUSTED_RESULT);
    uint8_t wrong_public_x[PASSPORT_P256_COORD_SIZE];
    memcpy(wrong_public_x, SERVICE_PUBLIC_X, sizeof(wrong_public_x));
    wrong_public_x[0] ^= 1;
    assert(passport_delivery_finalize_signed(&rebooted, &result,
        "synthetic-community", wrong_public_x, SERVICE_PUBLIC_Y,
        SERVICE_SIGNATURE) == PASSPORT_DELIVERY_UNTRUSTED_RESULT);
    assert(passport_outbox_load(&store, &still_pending) == PASSPORT_OUTBOX_READY);

    // A matching final rejection is authoritative too: it closes this exact
    // reply but never converts it into acceptance.
    result = result_frame(transfer_id, "rejected");
    trust_exact_result(&result);
    assert(finalize_signed(&rebooted, &result) == PASSPORT_DELIVERY_OK);
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
    member_signature(signature1);
    memcpy(signature2, signature1, sizeof(signature2));
    signature2[0] ^= 1;
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
    passport_delivery_result_frame_t result = result_frame(11, "accepted");
    trust_exact_result(&result);
    assert(finalize_signed(&delivery, &result) == PASSPORT_DELIVERY_OK);
    assert(passport_delivery_queue(&delivery, second, strlen(second), signature2, 12) ==
           PASSPORT_DELIVERY_OK);
}

static void test_storage_faults(void)
{
    const char frame[] = "{\"counter\":3}";
    uint8_t signature[PASSPORT_OUTBOX_SIGNATURE_SIZE];
    member_signature(signature);

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
    passport_delivery_result_frame_t result = result_frame(33, "accepted");
    trust_exact_result(&result);
    assert(finalize_signed(&delivery, &result) == PASSPORT_DELIVERY_IO_ERROR);
    passport_outbox_message_t pending;
    assert(passport_outbox_load(&clear_store, &pending) == PASSPORT_OUTBOX_READY);
    assert(pending.transfer_id == 33);
    clear_failure.writes = 0;
    clear_failure.fail_on_write = 0;
    assert(finalize_signed(&delivery, &result) == PASSPORT_DELIVERY_OK);
    assert(passport_outbox_load(&clear_store, &pending) == PASSPORT_OUTBOX_EMPTY);
}

int main(void)
{
    test_reboot_and_final_result();
    test_busy_exhaustion_and_recovery();
    test_storage_faults();
    return 0;
}
