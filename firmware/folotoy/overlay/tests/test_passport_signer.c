// Host-only software key. Generated in RAM each run; never a production backend.
#include "passport_signer.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>

typedef struct {
    uint8_t data[2][PASSPORT_OUTBOX_RECORD_MAX];
    size_t length[2];
    size_t writes, fail_write;
    bool fail_read, corrupt_readback;
} memory_t;
static passport_store_result_t read_slot(void *context, size_t slot,
    uint8_t *output, size_t capacity, size_t *length)
{
    memory_t *m = context;
    if (m->fail_read || slot > 1 || m->length[slot] > capacity) return PASSPORT_STORE_ERROR;
    if (!m->length[slot]) return PASSPORT_STORE_NOT_FOUND;
    *length = m->length[slot];
    memcpy(output, m->data[slot], *length);
    if (m->corrupt_readback) output[0] ^= 1;
    return PASSPORT_STORE_OK;
}
static bool write_slot(void *context, size_t slot, const uint8_t *data, size_t length)
{
    memory_t *m = context;
    if (++m->writes == m->fail_write) return false;
    assert(slot < 2 && length <= sizeof(m->data[slot]));
    memcpy(m->data[slot], data, length);
    m->length[slot] = length;
    return true;
}
static passport_outbox_store_t store_for(memory_t *m)
{
    return (passport_outbox_store_t){ m, read_slot, write_slot };
}
typedef struct {
    EVP_PKEY *key;
    size_t calls;
    bool fail, corrupt;
    passport_counter_t *counter;
    passport_signer_t *signer;
} provider_t;
static bool sign_frame(void *context, const uint8_t *frame, size_t length, uint8_t output[64])
{
    provider_t *p = context;
    p->calls++;
    assert(p->counter->ready && p->counter->last_reserved > 0);
    // Reentrant submissions are blocked before reserving or calling provider.
    assert(passport_signer_retry_save(p->signer) == PASSPORT_SIGN_INVALID);
    if (p->fail) return false;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    assert(ctx);
    assert(EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, p->key) == 1);
    unsigned char der[80];
    size_t written = sizeof(der);
    assert(EVP_DigestSign(ctx, der, &written, frame, length) == 1);
    const unsigned char *cursor = der;
    ECDSA_SIG *pair = d2i_ECDSA_SIG(NULL, &cursor, (long)written);
    assert(pair);
    const BIGNUM *r, *s;
    ECDSA_SIG_get0(pair, &r, &s);
    assert(BN_bn2binpad(r, output, 32) == 32);
    assert(BN_bn2binpad(s, output + 32, 32) == 32);
    if (p->corrupt) output[0] ^= 1;
    ECDSA_SIG_free(pair);
    EVP_MD_CTX_free(ctx);
    return true;
}
static passport_confirmation_frame_t confirmation(void)
{
    return (passport_confirmation_frame_t){
        .community_id = "synthetic-community", .decision = "decline",
        .device_id = "synthetic-device", .expires_at = 1999999999999ULL,
        .member_id = "synthetic-member", .nonce = "01234567890123456789012345678901",
        .request_digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        .request_id = "synthetic-request", .request_version = 2,
    };
}
int main(void)
{
    provider_t p = {0};
    p.key = EVP_EC_gen("prime256v1");
    assert(p.key);
    uint8_t point[65], key_hash[32];
    size_t point_length = sizeof(point);
    assert(EVP_PKEY_get_octet_string_param(p.key, OSSL_PKEY_PARAM_PUB_KEY,
        point, sizeof(point), &point_length) == 1 && point_length == sizeof(point));
    assert(passport_sha256(point, sizeof(point), key_hash));
    passport_sign_provider_t provider = { .context = &p, .sign = sign_frame };
    memcpy(provider.public_x, point + 1, 32);
    memcpy(provider.public_y, point + 33, 32);
    memory_t counters = {0}, outbox = {0};
    passport_outbox_store_t cs = store_for(&counters), os = store_for(&outbox);
    passport_counter_t counter, reopened;
    assert(!passport_counter_open(&counter, &cs, key_hash, 0));
    assert(passport_counter_enroll(&counter, &cs, key_hash, 5));
    assert(passport_counter_open(&reopened, &cs, key_hash, 5));
    assert(!passport_counter_enroll(&reopened, &cs, key_hash, 0));
    assert(!passport_counter_open(&reopened, &cs, key_hash, 6));
    uint8_t wrong_hash[32] = {0};
    assert(!passport_counter_open(&reopened, &cs, wrong_hash, 0));
    passport_delivery_t delivery;
    assert(passport_delivery_open(&delivery, &os, 100, 3) == PASSPORT_DELIVERY_EMPTY);
    passport_signer_t signer;
    assert(passport_signer_open(&signer, &counter, &delivery, &provider));
    p.counter = &counter; p.signer = &signer;
    passport_confirmation_frame_t frame = confirmation();
    frame.counter = 1;
    assert(passport_signer_submit(&signer, &frame, 7) == PASSPORT_SIGN_INVALID);
    frame.counter = 0;
    frame.request_digest = "bad";
    assert(passport_signer_submit(&signer, &frame, 7) == PASSPORT_SIGN_INVALID);
    assert(counter.last_reserved == 5 && p.calls == 0);
    frame = confirmation();
    p.fail = true;
    assert(passport_signer_submit(&signer, &frame, 7) == PASSPORT_SIGN_PROVIDER_FAILED);
    assert(counter.last_reserved == 6 && p.calls == 1 && outbox.writes == 0);
    p.fail = false; p.corrupt = true;
    assert(passport_signer_submit(&signer, &frame, 7) == PASSPORT_SIGN_PROVIDER_FAILED);
    assert(counter.last_reserved == 7 && p.calls == 2 && outbox.writes == 0);
    p.corrupt = false;
    outbox.fail_write = 1;
    assert(passport_signer_submit(&signer, &frame, 7) == PASSPORT_SIGN_NOT_DURABLE);
    assert(counter.last_reserved == 8 && p.calls == 3 && signer.staged);
    char saved_frame[sizeof(signer.frame)];
    uint8_t saved_signature[64];
    memcpy(saved_frame, signer.frame, sizeof(saved_frame));
    memcpy(saved_signature, signer.signature, 64);
    assert(passport_signer_submit(&signer, &frame, 8) == PASSPORT_SIGN_BUSY);
    outbox.fail_write = 0;
    assert(passport_signer_retry_save(&signer) == PASSPORT_SIGN_OK);
    assert(p.calls == 3 && counter.last_reserved == 8 && !signer.staged);
    assert(delivery.pending.transfer_id == 7);
    assert(strcmp(delivery.pending.frame, saved_frame) == 0);
    assert(memcmp(delivery.pending.signature, saved_signature, 64) == 0);
    assert(strstr(delivery.pending.frame, "\"counter\":8") &&
           strstr(delivery.pending.frame, "\"decision\":\"decline\""));
    assert(passport_signer_submit(&signer, &frame, 8) == PASSPORT_SIGN_BUSY);
    assert(passport_counter_open(&reopened, &cs, key_hash, 8));
    passport_delivery_t reboot;
    assert(passport_delivery_open(&reboot, &os, 100, 3) == PASSPORT_DELIVERY_OK);
    assert(strcmp(reboot.pending.frame, saved_frame) == 0 &&
           memcmp(reboot.pending.signature, saved_signature, 64) == 0);
    assert(passport_p256_verify_p1363(provider.public_x, provider.public_y,
        (uint8_t *)reboot.pending.frame, reboot.pending.frame_length, reboot.pending.signature));
    passport_sign_provider_t wrong_provider = provider;
    wrong_provider.public_x[0] ^= 1;
    passport_signer_t wrong_signer;
    assert(!passport_signer_open(&wrong_signer, &counter, &delivery, &wrong_provider));
    // A mirror-save error may have persisted a valid copy: reopen and retry the
    // same staged bytes, without asking provider to sign them again.
    memory_t uncertain_outbox = { .fail_write = 2 };
    passport_outbox_store_t us = store_for(&uncertain_outbox);
    passport_delivery_t uncertain_delivery;
    assert(passport_delivery_open(&uncertain_delivery, &us, 100, 3) == PASSPORT_DELIVERY_EMPTY);
    assert(passport_signer_open(&signer, &counter, &uncertain_delivery, &provider));
    assert(passport_signer_submit(&signer, &frame, 9) == PASSPORT_SIGN_NOT_DURABLE);
    assert(signer.staged && counter.last_reserved == 9 && p.calls == 4);
    memcpy(saved_signature, signer.signature, 64);
    uncertain_outbox.fail_write = 0;
    assert(passport_signer_retry_save(&signer) == PASSPORT_SIGN_OK);
    assert(p.calls == 4 && memcmp(uncertain_delivery.pending.signature, saved_signature, 64) == 0);
    // Reserve is fail-closed on a torn mirror, including across reboot.
    counters.fail_write = counters.writes + 2;
    uint64_t reserved = 999;
    assert(!passport_counter_reserve(&counter, &reserved));
    assert(reserved == 999 && !counter.ready);
    assert(!passport_counter_open(&reopened, &cs, key_hash, 0));
    assert(!passport_counter_enroll(&reopened, &cs, key_hash, 0));
    // Complete old-image rollback requires an external high-water mark to detect.
    counters = (memory_t){0};
    assert(passport_counter_enroll(&counter, &cs, key_hash, 2));
    memory_t old_image = counters;
    assert(passport_counter_reserve(&counter, &reserved) && reserved == 3);
    counters = old_image;
    assert(!passport_counter_reserve(&counter, &reserved)); // RAM floor detects rollback.
    assert(!passport_counter_open(&reopened, &cs, key_hash, 3));
    assert(passport_counter_open(&reopened, &cs, key_hash, 0)); // Honest limitation.
    counters.data[0][5] ^= 1;
    assert(!passport_counter_open(&reopened, &cs, key_hash, 0));
    // Two independently opened handles cannot silently reuse a counter when
    // serialized: the stale handle detects the durable high-water mark changed.
    counters = (memory_t){0};
    assert(passport_counter_enroll(&counter, &cs, key_hash, 0));
    assert(passport_counter_open(&reopened, &cs, key_hash, 0));
    assert(passport_counter_reserve(&counter, &reserved) && reserved == 1);
    assert(!passport_counter_reserve(&reopened, &reserved) && !reopened.ready);
    counters.fail_write = counters.writes + 1;
    assert(!passport_counter_reserve(&counter, &reserved) && !counter.ready);
    // A failed first write left both old copies valid. Reopen skips no
    // signed counter because signing was never called for the failed reserve.
    assert(passport_counter_open(&counter, &cs, key_hash, 1));
    // Exhaustion never wraps into JS-unsafe values.
    counters = (memory_t){0};
    assert(passport_counter_enroll(&counter, &cs, key_hash, PASSPORT_JS_SAFE_INTEGER_MAX));
    assert(!passport_counter_reserve(&counter, &reserved));
    // Storage read failure and readback corruption never provision a usable key.
    counters = (memory_t){ .fail_read = true };
    assert(!passport_counter_enroll(&counter, &cs, key_hash, 0));
    counters = (memory_t){ .corrupt_readback = true };
    assert(!passport_counter_enroll(&counter, &cs, key_hash, 0) && !counter.ready);
    EVP_PKEY_free(p.key);
    puts("Device signer/counter: real ephemeral P-256, exact retry, failure and rollback tests PASS");
    return 0;
}
