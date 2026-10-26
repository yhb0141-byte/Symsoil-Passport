#pragma once
#include "passport_core.h"
#include "passport_signer.h"

#define PASSPORT_REVIEW_REQUEST_MAX 4096
#define PASSPORT_REVIEW_SAMPLE_GAP_MS 250
#define PASSPORT_REVIEW_HOLD_MS 2000

typedef enum {
    PASSPORT_REVIEW_CLOSED, PASSPORT_REVIEW_READING,
    PASSPORT_REVIEW_CHOOSING, PASSPORT_REVIEW_FINAL, PASSPORT_REVIEW_CONSUMED,
} passport_review_state_t;

typedef struct {
    passport_review_state_t state;
    passport_kind_t kind;
    passport_confirmation_frame_t frame;
    char fields[PASSPORT_CONFIRMATION_FRAME_MAX + 1];
    uint8_t request[PASSPORT_REVIEW_REQUEST_MAX];
    size_t request_length, page_count, pages_read;
    uint64_t deadline_ms, last_event_ms, last_key_ms, hold_start_ms;
    bool sampled, released, holding, chosen, key_sampled;
} passport_review_t;

// Trusted, serialized local UI only. Not a BLE endpoint or proof of hardware
// consent. Request is the exact canonical request JSON hashed by the service;
// trusted renderer must show ALL its meaningful fields and confirmation identity.
// page_count is computed by that renderer, never copied from remote metadata.
// deadline is a trusted monotonic mapping of expires_at; no remote extension.
bool passport_review_open(passport_review_t *review, passport_kind_t kind,
    const passport_confirmation_frame_t *frame, const uint8_t *request,
    size_t request_length, size_t page_count, uint64_t deadline_ms, uint64_t now_ms);
void passport_review_cancel(passport_review_t *review);
// Call only after local user advances past the fully rendered current page.
bool passport_review_read_page(passport_review_t *review, size_t page, uint64_t now_ms);
bool passport_review_choose(passport_review_t *review, size_t choice, uint64_t now_ms);
// Requires an explicit successful choose; reading never selects a reply.
// After rendering final identity/decision/expiry summary, enter final page.
bool passport_review_final(passport_review_t *review, uint64_t now_ms);
// Poll physical debounced key state <=250ms, including while idle; 0=none,
// 1=OK only, all other masks cancel the hold. Missing samples, release, stale
// time, cancellation and expiry cannot produce a signature. No LONG event API.
// Returns INVALID while waiting; signing result only after a new 2-second hold.
passport_sign_result_t passport_review_sample(passport_review_t *review,
    unsigned keys, uint64_t now_ms, passport_signer_t *signer, uint32_t transfer_id);
