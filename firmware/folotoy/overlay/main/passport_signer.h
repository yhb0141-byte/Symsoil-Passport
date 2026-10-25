#pragma once

#include "passport_delivery.h"

#define PASSPORT_COUNTER_RECORD_SIZE 52

typedef struct {
    passport_outbox_store_t store; // Dedicated namespace; never share outbox/trust slots.
    uint8_t key_hash[32];
    uint64_t last_reserved;
    bool ready;
} passport_counter_t;

// Explicit local enrollment only. Both slots must be absent; never repairs or
// resets an existing identity. floor comes from trusted enrollment, not BLE.
bool passport_counter_enroll(passport_counter_t *counter,
    const passport_outbox_store_t *store, const uint8_t key_hash[32], uint64_t floor);
// Both copies must be valid and identical. A floor below an independently
// known high-water mark must not be used. Ordinary NVS cannot detect full rollback.
bool passport_counter_open(passport_counter_t *counter,
    const passport_outbox_store_t *store, const uint8_t key_hash[32], uint64_t floor);
bool passport_counter_reserve(passport_counter_t *counter, uint64_t *reserved);

typedef bool (*passport_sign_frame_fn)(void *context, const uint8_t *frame,
    size_t length, uint8_t signature[64]);

typedef struct {
    void *context;
    passport_sign_frame_fn sign; // SHA-256/P-256, returns fixed-width P1363.
    uint8_t public_x[32];
    uint8_t public_y[32];
} passport_sign_provider_t;

typedef enum {
    PASSPORT_SIGN_OK = 0,
    PASSPORT_SIGN_BUSY,
    PASSPORT_SIGN_INVALID,
    PASSPORT_SIGN_COUNTER_LOCKED,
    PASSPORT_SIGN_PROVIDER_FAILED,
    PASSPORT_SIGN_NOT_DURABLE,
} passport_sign_result_t;

typedef struct {
    passport_counter_t *counter;
    passport_delivery_t *delivery;
    passport_sign_provider_t provider;
    char frame[PASSPORT_CONFIRMATION_FRAME_MAX + 1];
    size_t frame_length;
    uint8_t signature[64];
    uint32_t transfer_id;
    bool staged;
    bool active;
} passport_signer_t;

bool passport_signer_open(passport_signer_t *signer, passport_counter_t *counter,
    passport_delivery_t *delivery, const passport_sign_provider_t *provider);
// Trusted local coordinator only, after final physical confirmation of this
// exact immutable frame. This function does NOT establish user consent, request
// freshness, device enrollment, or trusted time. Never call directly from BLE.
// counter must be zero: this module exclusively assigns the reserved counter.
passport_sign_result_t passport_signer_submit(passport_signer_t *signer,
    const passport_confirmation_frame_t *confirmed_frame, uint32_t transfer_id);
// Storage retry only. Never invokes provider or increments counter again.
passport_sign_result_t passport_signer_retry_save(passport_signer_t *signer);
