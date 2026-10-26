#include "passport_receiver.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static uint8_t source[PASSPORT_RECEIVER_MESSAGE_MAX + 1];
static uint8_t packet[PASSPORT_TRANSPORT_PACKET_MAX];
static uint8_t saved[PASSPORT_TRANSPORT_PACKET_MAX];
static uint8_t output[PASSPORT_RECEIVER_MESSAGE_MAX];
static passport_transport_t tx;
static passport_receiver_t rx;

static size_t next(void)
{
    size_t length = 0;
    assert(passport_transport_next(&tx, packet, sizeof(packet), &length) == PASSPORT_TRANSPORT_WAITING_ACK);
    return length;
}
static void ack(void)
{
    passport_transport_ack(&tx, tx.transfer_id, tx.chunk_index, true);
}
static void begin(size_t length, size_t packet_size)
{
    passport_receiver_close(&rx);
    assert(passport_receiver_open(&rx, 100, packet_size, 1000, 5000) == PASSPORT_RECEIVER_READY);
    assert(passport_transport_begin(&tx, source, length, 27, packet_size, 3) == PASSPORT_TRANSPORT_READY);
}
static void wiped(void)
{
    assert(rx.length == 0 && rx.session == 0);
    for (size_t i = 0; i < sizeof(rx.message); i++) assert(rx.message[i] == 0);
}
static void round_trip(size_t length, size_t packet_size)
{
    begin(length, packet_size);
    size_t total = 0;
    while (tx.state != PASSPORT_TRANSPORT_COMPLETE) {
        size_t n = next();
        bool final = tx.chunk_index + 1 == tx.chunk_count;
        assert(passport_receiver_receive(&rx, 100, packet, n, 1002) ==
            (final ? PASSPORT_RECEIVER_COMPLETE : PASSPORT_RECEIVER_PARTIAL));
        total += n - PASSPORT_TRANSPORT_HEADER_SIZE;
        // Lost ACK: replay the exact packet without appending or extending TTL.
        assert(passport_transport_timeout(&tx) == PASSPORT_TRANSPORT_READY);
        memcpy(saved, packet, n);
        assert(next() == n && memcmp(saved, packet, n) == 0);
        assert(passport_receiver_receive(&rx, 100, packet, n, 1002) == PASSPORT_RECEIVER_DUPLICATE);
        assert(rx.length == total);
        ack();
    }
    assert(!passport_receiver_take(&rx, 100, 1003, output, length - 1, &total, &(uint32_t){0}));
    uint32_t id;
    assert(passport_receiver_take(&rx, 100, 1004, output, sizeof(output), &total, &id));
    assert(total == length && id == 27 && memcmp(output, source, length) == 0);
    assert(rx.state == PASSPORT_RECEIVER_CONSUMED && rx.length == 0);
    for (size_t i = rx.last_length; i < sizeof(rx.message); i++) assert(rx.message[i] == 0);
    assert(!passport_receiver_take(&rx, 100, 1005, output, sizeof(output), &total, &id));
    assert(total == 0 && id == 0);
    // Application already consumed the message, but sender lost the final ACK.
    assert(passport_transport_begin(&tx, source, length, 27, packet_size, 3) == PASSPORT_TRANSPORT_READY);
    tx.chunk_index = tx.chunk_count - 1;
    size_t n = next();
    assert(passport_receiver_receive(&rx, 100, packet, n, 1006) == PASSPORT_RECEIVER_DUPLICATE);
    ack(); assert(tx.state == PASSPORT_TRANSPORT_COMPLETE);
    assert(rx.state == PASSPORT_RECEIVER_CONSUMED);
    assert(passport_receiver_open(&rx, 200, packet_size, 1007, 5000) == PASSPORT_RECEIVER_BAD_ARGUMENT);
    assert(passport_receiver_receive(&rx, 99, packet, n, 1008) == PASSPORT_RECEIVER_STALE_SESSION);
    assert(passport_receiver_receive(&rx, 100, packet, n, 5999) == PASSPORT_RECEIVER_DUPLICATE);
    assert(passport_receiver_tick(&rx, 100, 6000) == PASSPORT_RECEIVER_EXPIRED); wiped();
}
int main(void)
{
    for (size_t i = 0; i < sizeof(source); i++) source[i] = (uint8_t)i;
    // MTU-23 ATT value (20 bytes), large negotiated value, exact bound and
    // partial final chunks all round-trip with the existing real sender.
    round_trip(1, 20); round_trip(4096, 20); round_trip(4095, 512); round_trip(4096, 512);
    // Consumed tombstones reject changed payload (valid CRC), transfer ID,
    // chunk count, earlier fragments and damaged packets; none redeliver.
    for (unsigned fault = 0; fault < 5; fault++) {
        begin(40, 32);
        while (tx.state != PASSPORT_TRANSPORT_COMPLETE) {
            size_t n = next();
            passport_receiver_receive(&rx, 100, packet, n, 1001); ack();
        }
        size_t length; uint32_t id;
        assert(passport_receiver_take(&rx, 100, 1002, output, sizeof(output), &length, &id));
        passport_transport_begin(&tx, source, 40, 27, 32, 3);
        tx.chunk_index = tx.chunk_count - 1;
        if (fault == 0) source[39] ^= 1;
        if (fault == 1) tx.transfer_id++;
        if (fault == 2) tx.chunk_count++;
        if (fault == 3) tx.chunk_index = 0;
        size_t n = next();
        if (fault == 0) source[39] ^= 1;
        if (fault == 4) packet[n - 1] ^= 1;
        assert(passport_receiver_receive(&rx, 100, packet, n, 1003) == PASSPORT_RECEIVER_REJECTED); wiped();
        assert(!passport_receiver_take(&rx, 100, 1004, output, sizeof(output), &length, &id));
    }
    begin(1, 32); size_t close_n = next();
    passport_receiver_receive(&rx, 100, packet, close_n, 1001);
    size_t close_length; uint32_t close_id;
    assert(passport_receiver_take(&rx, 100, 1002, output, sizeof(output), &close_length, &close_id));
    assert(passport_receiver_tick(&rx, 100, 1001) == PASSPORT_RECEIVER_EXPIRED); wiped();
    begin(1, 32); close_n = next();
    passport_receiver_receive(&rx, 100, packet, close_n, 1001);
    assert(passport_receiver_take(&rx, 100, 1002, output, sizeof(output), &close_length, &close_id));
    passport_receiver_close(&rx); wiped();
    assert(passport_receiver_open(&rx, 200, 32, 1003, 5000) == PASSPORT_RECEIVER_READY);
    assert(passport_receiver_receive(&rx, 100, packet, close_n, 1004) == PASSPORT_RECEIVER_STALE_SESSION);
    assert(rx.state == PASSPORT_RECEIVER_READY);
    begin(40, 32);
    size_t n = next(); memcpy(saved, packet, n);
    assert(passport_receiver_receive(&rx, 99, packet, n, 1001) == PASSPORT_RECEIVER_STALE_SESSION);
    assert(rx.state == PASSPORT_RECEIVER_READY && rx.length == 0);
    assert(passport_receiver_receive(&rx, 100, packet, n, 1001) == PASSPORT_RECEIVER_PARTIAL);
    assert(passport_receiver_open(&rx, 200, 32, 1002, 5000) == PASSPORT_RECEIVER_BAD_ARGUMENT);
    assert(rx.session == 100);
    passport_receiver_close(&rx); wiped();
    assert(passport_receiver_open(&rx, 200, 32, 1002, 5000) == PASSPORT_RECEIVER_READY);
    assert(passport_receiver_receive(&rx, 100, packet, n, 1003) == PASSPORT_RECEIVER_STALE_SESSION);
    ack(); n = next();
    assert(passport_receiver_receive(&rx, 200, packet, n, 1004) == PASSPORT_RECEIVER_REJECTED); wiped();
    // Same session, new transfer or inconsistent chunk count cannot replace data.
    begin(40, 32); n = next();
    assert(passport_receiver_receive(&rx, 100, packet, n, 1001) == PASSPORT_RECEIVER_PARTIAL);
    tx.transfer_id++;
    passport_transport_timeout(&tx); n = next();
    assert(passport_receiver_receive(&rx, 100, packet, n, 1002) == PASSPORT_RECEIVER_REJECTED); wiped();
    begin(40, 32); n = next(); passport_receiver_receive(&rx, 100, packet, n, 1001);
    tx.chunk_count++; passport_transport_timeout(&tx); n = next();
    assert(passport_receiver_receive(&rx, 100, packet, n, 1002) == PASSPORT_RECEIVER_REJECTED); wiped();
    // Duplicate with a valid CRC but changed bytes is a conflict, not an ACK.
    begin(40, 32); n = next(); passport_receiver_receive(&rx, 100, packet, n, 1001);
    source[0] ^= 1; passport_transport_timeout(&tx); n = next(); source[0] ^= 1;
    assert(passport_receiver_receive(&rx, 100, packet, n, 1002) == PASSPORT_RECEIVER_REJECTED); wiped();
    // Corruption, truncation, oversized ATT values, empty payload, huge count,
    // non-final short chunk, and maximum+1 message are all rejected and wiped.
    for (unsigned fault = 0; fault < 7; fault++) {
        begin(40, 32);
        if (fault == 4) tx.chunk_count = UINT16_MAX;
        if (fault == 5) tx.chunk_payload--;
        n = next();
        if (fault == 0) packet[n - 1] ^= 1;
        if (fault == 1) n--;
        if (fault == 2) n = 33;
        if (fault == 3) {
            passport_transport_begin(&tx, source, 1, 27, 32, 3);
            tx.message_length = 0; n = next();
        }
        if (fault == 6) {
            passport_transport_begin(&tx, source, sizeof(source), 27, 512, 3);
            rx.packet_size = 512;
            // Accept preceding chunks; the oversized final byte must fail.
            while (tx.chunk_index + 1 < tx.chunk_count) {
                n = next(); assert(passport_receiver_receive(&rx, 100, packet, n, 1001) == PASSPORT_RECEIVER_PARTIAL); ack();
            }
            n = next();
        }
        assert(passport_receiver_receive(&rx, 100, packet, n, 1002) == PASSPORT_RECEIVER_REJECTED); wiped();
    }
    // Absolute deadline is not refreshed by bytes or duplicate traffic.
    begin(40, 32); n = next(); passport_receiver_receive(&rx, 100, packet, n, 1001);
    assert(passport_receiver_receive(&rx, 100, packet, n, 5999) == PASSPORT_RECEIVER_DUPLICATE);
    assert(passport_receiver_tick(&rx, 100, 6000) == PASSPORT_RECEIVER_EXPIRED); wiped();
    begin(1, 32); n = next(); passport_receiver_receive(&rx, 100, packet, n, 1001);
    size_t length; uint32_t id;
    assert(!passport_receiver_take(&rx, 100, 6000, output, sizeof(output), &length, &id)); wiped();
    begin(40, 32); n = next(); passport_receiver_receive(&rx, 100, packet, n, 1002);
    assert(passport_receiver_tick(&rx, 100, 1001) == PASSPORT_RECEIVER_EXPIRED); wiped();
    // Arithmetic near uint64 max avoids deadline addition overflow.
    assert(passport_receiver_open(&rx, 300, 32, UINT64_MAX - 10, 20) == PASSPORT_RECEIVER_READY);
    assert(passport_receiver_tick(&rx, 300, UINT64_MAX) == PASSPORT_RECEIVER_READY);
    assert(passport_receiver_tick(&rx, 300, 0) == PASSPORT_RECEIVER_EXPIRED); wiped();
    assert(passport_receiver_open(&rx, 0, 32, 0, 20) == PASSPORT_RECEIVER_BAD_ARGUMENT);
    assert(passport_receiver_open(&rx, 1, 18, 0, 20) == PASSPORT_RECEIVER_BAD_ARGUMENT);
    assert(passport_receiver_open(&rx, 1, 513, 0, 20) == PASSPORT_RECEIVER_BAD_ARGUMENT);
    assert(passport_receiver_open(&rx, 1, 32, 0, 0) == PASSPORT_RECEIVER_BAD_ARGUMENT);
    assert(passport_receiver_open(&rx, 1, 32, 0, 30001) == PASSPORT_RECEIVER_BAD_ARGUMENT);
    assert(passport_receiver_tick(NULL, 1, 0) == PASSPORT_RECEIVER_BAD_ARGUMENT);
    puts("Passport bounded receiver: PASS");
}
