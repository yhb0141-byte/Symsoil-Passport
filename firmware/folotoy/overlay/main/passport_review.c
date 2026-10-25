#include "passport_review.h"
#include <string.h>

void passport_review_cancel(passport_review_t *r)
{
    if (r) memset(r, 0, sizeof(*r));
}
static bool fresh(passport_review_t *r, uint64_t now)
{
    if (!r || r->state == PASSPORT_REVIEW_CLOSED ||
        r->state == PASSPORT_REVIEW_CONSUMED) return false;
    if (now >= r->deadline_ms || (r->sampled && now < r->last_event_ms)) {
        passport_review_cancel(r);
        return false;
    }
    r->last_event_ms = now;
    r->sampled = true;
    return true;
}
static bool copy_field(passport_review_t *r, const char *source,
                       const char **target, size_t *used)
{
    if (!source) return false;
    size_t length = 0;
    while (length < sizeof(r->fields) && source[length]) ++length;
    if (length + 1 > sizeof(r->fields) - *used) return false;
    memcpy(r->fields + *used, source, length + 1);
    *target = r->fields + *used;
    *used += length + 1;
    return true;
}
bool passport_review_open(passport_review_t *r, passport_kind_t kind,
    const passport_confirmation_frame_t *f, const uint8_t *request,
    size_t length, size_t pages, uint64_t deadline, uint64_t now)
{
    if (!r) return false;
    passport_review_cancel(r); // Replacement always invalidates prior consent.
    if (!f || !request || !length || length > sizeof(r->request) ||
        !pages || pages > PASSPORT_REVIEW_REQUEST_MAX || now >= deadline ||
        !passport_decision_count(kind) || f->counter != 0) return false;
    r->frame = *f;
    size_t used = 0;
#define COPY(name) if (!copy_field(r, f->name, &r->frame.name, &used)) goto invalid
    COPY(community_id); COPY(device_id); COPY(member_id); COPY(nonce);
    COPY(request_digest); COPY(request_id);
#undef COPY
    r->frame.decision = passport_decision(kind, 0);
    char encoded[PASSPORT_CONFIRMATION_FRAME_MAX + 1];
    size_t encoded_length;
    // Protocol requires a reserved counter, while review always owns counter 0.
    passport_confirmation_frame_t check = r->frame;
    check.counter = 1;
    if (passport_confirmation_frame_json(&check, encoded, sizeof(encoded),
                                         &encoded_length) != PASSPORT_PROTOCOL_OK) goto invalid;
    uint8_t digest[32];
    if (!passport_sha256(request, length, digest)) goto invalid;
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < sizeof(digest); ++i) {
        if (r->frame.request_digest[2*i] != hex[digest[i] >> 4] ||
            r->frame.request_digest[2*i+1] != hex[digest[i] & 15]) goto invalid;
    }
    memcpy(r->request, request, length);
    r->request_length = length;
    r->kind = kind;
    r->page_count = pages;
    r->deadline_ms = deadline;
    r->last_event_ms = now;
    r->sampled = true;
    r->state = PASSPORT_REVIEW_READING;
    return true;
invalid:
    passport_review_cancel(r);
    return false;
}
bool passport_review_read_page(passport_review_t *r, size_t page, uint64_t now)
{
    if (!fresh(r, now) || r->state != PASSPORT_REVIEW_READING ||
        page != r->pages_read || page >= r->page_count) return false;
    if (++r->pages_read == r->page_count) r->state = PASSPORT_REVIEW_CHOOSING;
    return true;
}
bool passport_review_choose(passport_review_t *r, size_t choice, uint64_t now)
{
    if (!fresh(r, now) || (r->state != PASSPORT_REVIEW_CHOOSING &&
                          r->state != PASSPORT_REVIEW_FINAL)) return false;
    const char *decision = passport_decision(r->kind, choice);
    if (!decision) return false;
    r->frame.decision = decision;
    r->chosen = true;
    r->state = PASSPORT_REVIEW_CHOOSING;
    r->holding = r->released = r->key_sampled = false;
    return true;
}
bool passport_review_final(passport_review_t *r, uint64_t now)
{
    if (!fresh(r, now) || r->state != PASSPORT_REVIEW_CHOOSING || !r->chosen) return false;
    r->state = PASSPORT_REVIEW_FINAL;
    r->holding = r->released = r->key_sampled = false;
    return true;
}
passport_sign_result_t passport_review_sample(passport_review_t *r,
    unsigned keys, uint64_t now, passport_signer_t *signer, uint32_t transfer)
{
    if (!r) return PASSPORT_SIGN_INVALID;
    uint64_t previous = r->last_key_ms;
    if (!fresh(r, now) || r->state != PASSPORT_REVIEW_FINAL) return PASSPORT_SIGN_INVALID;
    if (!r->key_sampled || now - previous > PASSPORT_REVIEW_SAMPLE_GAP_MS) {
        r->holding = r->released = false;
    }
    r->last_key_ms = now;
    r->key_sampled = true;
    if (!keys) {
        r->released = true;
        r->holding = false;
    } else if (keys != 1) {
        r->released = r->holding = false;
    } else if (r->released) {
        if (!r->holding) { r->holding = true; r->hold_start_ms = now; }
        if (now - r->hold_start_ms >= PASSPORT_REVIEW_HOLD_MS) {
            // Consume even on provider/storage failure. Storage retry goes only
            // through signer_retry_save; never synthesize a second confirmation.
            r->state = PASSPORT_REVIEW_CONSUMED;
            r->holding = r->released = false;
            return passport_signer_submit(signer, &r->frame, transfer);
        }
    }
    return PASSPORT_SIGN_INVALID;
}
