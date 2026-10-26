#include <assert.h>
#include <string.h>

#include "passport_outbox.h"
#include "passport_transport.h"

typedef struct {
    uint8_t data[PASSPORT_OUTBOX_SLOT_COUNT][PASSPORT_OUTBOX_RECORD_MAX];
    size_t length[PASSPORT_OUTBOX_SLOT_COUNT];
    bool present[PASSPORT_OUTBOX_SLOT_COUNT];
    bool fail_read;
    size_t write_calls;
    size_t fail_on_write;
} memory_store_t;

static passport_store_result_t memory_read(
    void *context, size_t slot, uint8_t *output, size_t capacity, size_t *length)
{
    memory_store_t *store = context;
    if (store->fail_read || slot >= PASSPORT_OUTBOX_SLOT_COUNT) return PASSPORT_STORE_ERROR;
    if (!store->present[slot]) return PASSPORT_STORE_NOT_FOUND;
    if (store->length[slot] > capacity) return PASSPORT_STORE_ERROR;
    memcpy(output, store->data[slot], store->length[slot]);
    *length = store->length[slot];
    return PASSPORT_STORE_OK;
}

static bool memory_write(void *context, size_t slot, const uint8_t *data, size_t length)
{
    memory_store_t *store = context;
    store->write_calls++;
    if (slot >= PASSPORT_OUTBOX_SLOT_COUNT || length > PASSPORT_OUTBOX_RECORD_MAX ||
        store->write_calls == store->fail_on_write) return false;
    memcpy(store->data[slot], data, length);
    store->length[slot] = length;
    store->present[slot] = true;
    return true;
}

static passport_outbox_store_t adapter(memory_store_t *memory)
{
    return (passport_outbox_store_t) {
        .context = memory,
        .read = memory_read,
        .write = memory_write,
    };
}

static void reset_fault(memory_store_t *store, size_t fail_on_write)
{
    store->write_calls = 0;
    store->fail_on_write = fail_on_write;
}

static void test_outbox(void)
{
    memory_store_t memory = { 0 };
    passport_outbox_store_t store = adapter(&memory);
    passport_outbox_message_t loaded;
    assert(passport_outbox_load(&store, &loaded) == PASSPORT_OUTBOX_EMPTY);
    assert(passport_crc32((const uint8_t *)"123456789", 9) == UINT32_C(0xcbf43926));

    const char frame1[] = "{\"counter\":1,\"protocol\":\"symsoil-passport/1\"}";
    uint8_t signature1[PASSPORT_OUTBOX_SIGNATURE_SIZE];
    memset(signature1, 0x11, sizeof(signature1));
    assert(passport_outbox_save(&store, frame1, strlen(frame1), signature1,
                                UINT32_C(0x10203040), &loaded) == PASSPORT_OUTBOX_READY);
    assert(loaded.generation == 1);
    assert(loaded.transfer_id == UINT32_C(0x10203040));
    assert(strcmp(loaded.frame, frame1) == 0);
    assert(memcmp(loaded.signature, signature1, sizeof(signature1)) == 0);
    assert(memory.present[0] && memory.present[1]);
    uint8_t envelope[PASSPORT_OUTBOX_ENVELOPE_MAX];
    size_t envelope_length = 0;
    assert(passport_outbox_envelope_encode(&loaded, envelope, sizeof(envelope), &envelope_length));
    passport_outbox_message_t decoded;
    assert(passport_outbox_envelope_decode(envelope, envelope_length, &decoded));
    assert(decoded.generation == 0 && decoded.transfer_id == 0);
    assert(strcmp(decoded.frame, frame1) == 0);
    assert(memcmp(decoded.signature, signature1, sizeof(signature1)) == 0);
    envelope[envelope_length - 1] ^= 1;
    assert(!passport_outbox_envelope_decode(envelope, envelope_length, &decoded));
    envelope[envelope_length - 1] ^= 1;

    const char frame2[] = "{\"counter\":2,\"protocol\":\"symsoil-passport/1\"}";
    uint8_t signature2[PASSPORT_OUTBOX_SIGNATURE_SIZE];
    memset(signature2, 0x22, sizeof(signature2));
    const size_t writes_after_first_save = memory.write_calls;
    assert(passport_outbox_save(&store, frame1, strlen(frame1), signature1,
                                UINT32_C(0x10203040), &loaded) == PASSPORT_OUTBOX_READY);
    assert(loaded.generation == 1 && memory.write_calls == writes_after_first_save);
    assert(passport_outbox_save(&store, frame2, strlen(frame2), signature2,
                                UINT32_C(0x50607080), NULL) == PASSPORT_OUTBOX_BUSY);
    assert(passport_outbox_load(&store, &loaded) == PASSPORT_OUTBOX_READY);
    assert(loaded.generation == 1 && strcmp(loaded.frame, frame1) == 0);

    assert(passport_outbox_clear(&store) == PASSPORT_OUTBOX_EMPTY);
    assert(passport_outbox_load(&store, &loaded) == PASSPORT_OUTBOX_EMPTY);

    reset_fault(&memory, 1);
    assert(passport_outbox_save(&store, frame2, strlen(frame2), signature2,
                                UINT32_C(0x50607080), NULL) == PASSPORT_OUTBOX_IO_ERROR);
    assert(passport_outbox_load(&store, &loaded) == PASSPORT_OUTBOX_EMPTY);

    // Primary committed but mirror failed: reboot still recovers the exact
    // newer reply. The caller must query/retry it, never sign again.
    reset_fault(&memory, 2);
    assert(passport_outbox_save(&store, frame2, strlen(frame2), signature2,
                                UINT32_C(0x50607080), NULL) == PASSPORT_OUTBOX_IO_ERROR);
    assert(passport_outbox_load(&store, &loaded) == PASSPORT_OUTBOX_READY);
    assert(loaded.generation == 3 && strcmp(loaded.frame, frame2) == 0);
    assert(memcmp(loaded.signature, signature2, sizeof(signature2)) == 0);

    reset_fault(&memory, 0);
    assert(passport_outbox_save(&store, loaded.frame, loaded.frame_length, loaded.signature,
                                loaded.transfer_id, &loaded) == PASSPORT_OUTBOX_READY);
    assert(loaded.generation == 3);
    memory.data[0][7] ^= 1;
    assert(passport_outbox_load(&store, &loaded) == PASSPORT_OUTBOX_READY);
    assert(loaded.generation == 3 && strcmp(loaded.frame, frame2) == 0);

    reset_fault(&memory, 0);
    assert(passport_outbox_clear(&store) == PASSPORT_OUTBOX_EMPTY);
    assert(passport_outbox_load(&store, &loaded) == PASSPORT_OUTBOX_EMPTY);
    memory.data[0][8] ^= 1;
    assert(passport_outbox_load(&store, &loaded) == PASSPORT_OUTBOX_EMPTY);
    memory.data[1][9] ^= 1;
    assert(passport_outbox_load(&store, &loaded) == PASSPORT_OUTBOX_CORRUPT);
    memory.fail_read = true;
    assert(passport_outbox_load(&store, &loaded) == PASSPORT_OUTBOX_IO_ERROR);

    memory_store_t empty = { 0 };
    passport_outbox_store_t empty_store = adapter(&empty);
    assert(passport_outbox_save(&empty_store, frame1, 0, signature1, 1, NULL) ==
           PASSPORT_OUTBOX_INVALID);
    assert(passport_outbox_save(&empty_store, frame1, strlen(frame1), signature1, 0, NULL) ==
           PASSPORT_OUTBOX_INVALID);
}

static void test_transport(void)
{
    uint8_t message[650];
    for (size_t index = 0; index < sizeof(message); index++) message[index] = (uint8_t)(index * 17u);
    passport_transport_t transport;
    assert(passport_transport_begin(&transport, message, sizeof(message),
                                    UINT32_C(0xdecafbad), 64, 3) == PASSPORT_TRANSPORT_READY);
    assert(transport.chunk_count == 15);

    uint8_t packet[PASSPORT_TRANSPORT_PACKET_MAX];
    uint8_t first_packet[PASSPORT_TRANSPORT_PACKET_MAX];
    uint8_t rebuilt[sizeof(message)];
    size_t rebuilt_length = 0;
    size_t packet_length = 0;
    assert(passport_transport_next(&transport, packet, sizeof(packet), &packet_length) ==
           PASSPORT_TRANSPORT_WAITING_ACK);
    memcpy(first_packet, packet, packet_length);
    const size_t first_length = packet_length;
    passport_transport_packet_t parsed;
    assert(passport_transport_parse(packet, packet_length, &parsed));
    assert(parsed.chunk_index == 0 && !parsed.final_chunk);

    assert(passport_transport_ack(&transport, 1, 0, true) == PASSPORT_TRANSPORT_WAITING_ACK);
    assert(passport_transport_ack(&transport, transport.transfer_id, 0, false) ==
           PASSPORT_TRANSPORT_READY);
    assert(passport_transport_next(&transport, packet, sizeof(packet), &packet_length) ==
           PASSPORT_TRANSPORT_WAITING_ACK);
    assert(packet_length == first_length && memcmp(packet, first_packet, first_length) == 0);

    assert(passport_transport_disconnect(&transport) == PASSPORT_TRANSPORT_DISCONNECTED);
    assert(passport_transport_reconnect(&transport) == PASSPORT_TRANSPORT_READY);
    assert(passport_transport_next(&transport, packet, sizeof(packet), &packet_length) ==
           PASSPORT_TRANSPORT_WAITING_ACK);
    assert(packet_length == first_length && memcmp(packet, first_packet, first_length) == 0);

    while (transport.state != PASSPORT_TRANSPORT_COMPLETE) {
        assert(passport_transport_parse(packet, packet_length, &parsed));
        assert(parsed.transfer_id == transport.transfer_id);
        memcpy(rebuilt + rebuilt_length, parsed.payload, parsed.payload_length);
        rebuilt_length += parsed.payload_length;
        assert(passport_transport_ack(&transport, parsed.transfer_id, parsed.chunk_index, true) ==
               (parsed.final_chunk ? PASSPORT_TRANSPORT_COMPLETE : PASSPORT_TRANSPORT_READY));
        if (!parsed.final_chunk) {
            assert(passport_transport_next(&transport, packet, sizeof(packet), &packet_length) ==
                   PASSPORT_TRANSPORT_WAITING_ACK);
        }
    }
    assert(rebuilt_length == sizeof(message));
    assert(memcmp(rebuilt, message, sizeof(message)) == 0);

    packet[PASSPORT_TRANSPORT_HEADER_SIZE] ^= 1;
    assert(!passport_transport_parse(packet, packet_length, &parsed));
    packet[PASSPORT_TRANSPORT_HEADER_SIZE] ^= 1;
    packet[4] ^= 1;
    assert(!passport_transport_parse(packet, packet_length, &parsed));

    passport_transport_t limited;
    assert(passport_transport_begin(&limited, message, 8, 7, 32, 2) == PASSPORT_TRANSPORT_READY);
    assert(passport_transport_next(&limited, packet, sizeof(packet), &packet_length) ==
           PASSPORT_TRANSPORT_WAITING_ACK);
    assert(passport_transport_timeout(&limited) == PASSPORT_TRANSPORT_READY);
    assert(passport_transport_next(&limited, packet, sizeof(packet), &packet_length) ==
           PASSPORT_TRANSPORT_WAITING_ACK);
    assert(passport_transport_timeout(&limited) == PASSPORT_TRANSPORT_EXHAUSTED);
    assert(passport_transport_disconnect(&limited) == PASSPORT_TRANSPORT_DISCONNECTED);
    assert(passport_transport_reconnect(&limited) == PASSPORT_TRANSPORT_READY);
}

int main(void)
{
    test_outbox();
    test_transport();
    return 0;
}
