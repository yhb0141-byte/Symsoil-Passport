#include "passport_provision.h"

#include <string.h>

static bool reviewing(const passport_provision_t *provision)
{
    return provision && (provision->view.state == PASSPORT_PROVISION_FINGERPRINT ||
        provision->view.state == PASSPORT_PROVISION_REVIEW ||
        provision->view.state == PASSPORT_PROVISION_HOLDING);
}

static passport_provision_result_t close_ceremony(
    passport_provision_t *provision, passport_provision_state_t state,
    passport_provision_result_t result)
{
    provision->view.state = state;
    provision->fingerprint_key_down = false;
    provision->hold_started_ms = 0;
    return result;
}

void passport_provision_init(passport_provision_t *provision)
{
    if (provision) memset(provision, 0, sizeof(*provision));
}

static bool root_unchanged(const passport_provision_t *provision)
{
    return provision->trust && provision->trust->initialized &&
        memcmp(&provision->trust->root, &provision->pinned_root,
               sizeof(provision->pinned_root)) == 0;
}

static passport_provision_result_t check_time(
    passport_provision_t *provision, uint64_t now_ms)
{
    if (!provision) return PASSPORT_PROVISION_BAD_ARGUMENT;
    if (!reviewing(provision)) return PASSPORT_PROVISION_NO_CHANGE;
    if (!root_unchanged(provision)) {
        return close_ceremony(provision, PASSPORT_PROVISION_STALE,
                              PASSPORT_PROVISION_WAS_STALE);
    }
    /* Subtractions avoid deadline addition overflowing near UINT64_MAX.
     * Monotonic rollback/wrap aborts rather than extending approval time. */
    if (now_ms < provision->last_ms || now_ms < provision->started_ms ||
        now_ms - provision->started_ms >= provision->timeout_ms) {
        return close_ceremony(provision, PASSPORT_PROVISION_EXPIRED,
                              PASSPORT_PROVISION_TIMED_OUT);
    }
    provision->last_ms = now_ms;
    return PASSPORT_PROVISION_OK;
}

static passport_provision_result_t commit_once(passport_provision_t *provision)
{
    /* Consume the ceremony BEFORE invoking storage. Failure never leaves a
     * reusable approval, and a duplicate timer/event cannot commit again. */
    close_ceremony(provision, PASSPORT_PROVISION_FAILED,
                   PASSPORT_PROVISION_TRUST_ERROR);
    passport_trust_result_t result;
    if (provision->view.mode == PASSPORT_PROVISION_RECOVER) {
        result = passport_trust_recover(provision->trust, &provision->candidate,
            provision->root_signature, true,
            provision->view.authoritative_minimum_epoch);
    } else {
        result = passport_trust_apply(provision->trust, &provision->candidate,
                                     provision->root_signature, true);
    }
    provision->view.trust_result = result;
    if (result != PASSPORT_TRUST_OK) return PASSPORT_PROVISION_TRUST_ERROR;
    provision->view.state = PASSPORT_PROVISION_COMPLETE;
    return PASSPORT_PROVISION_APPLIED;
}

passport_provision_result_t passport_provision_begin_local(
    passport_provision_t *provision,
    passport_trust_t *trust,
    const passport_trust_manifest_t *candidate,
    const uint8_t root_signature[PASSPORT_P256_P1363_SIZE],
    passport_provision_mode_t mode,
    const uint32_t *independently_verified_floor,
    uint64_t now_ms, uint64_t timeout_ms)
{
    if (!provision) return PASSPORT_PROVISION_BAD_ARGUMENT;
    /* Copy first: callers may restart with the currently displayed candidate. */
    passport_trust_manifest_t proposal = { 0 };
    uint8_t signature[PASSPORT_P256_P1363_SIZE] = { 0 };
    uint32_t floor = independently_verified_floor ? *independently_verified_floor : 0;
    if (candidate) proposal = *candidate;
    if (root_signature) memcpy(signature, root_signature, sizeof(signature));
    passport_provision_init(provision);
    provision->view.state = PASSPORT_PROVISION_FAILED;
    if (!trust || !trust->initialized || !candidate || !root_signature ||
        (mode != PASSPORT_PROVISION_APPLY && mode != PASSPORT_PROVISION_RECOVER) ||
        timeout_ms <= PASSPORT_PROVISION_HOLD_MS ||
        (mode == PASSPORT_PROVISION_RECOVER && !independently_verified_floor)) {
        return PASSPORT_PROVISION_BAD_ARGUMENT;
    }
    if ((mode == PASSPORT_PROVISION_RECOVER && trust->state != PASSPORT_TRUST_LOCKED) ||
        (mode == PASSPORT_PROVISION_APPLY && trust->state == PASSPORT_TRUST_LOCKED)) {
        provision->view.trust_result = mode == PASSPORT_PROVISION_RECOVER ?
            PASSPORT_TRUST_BAD_ARGUMENT : PASSPORT_TRUST_IS_LOCKED;
        return PASSPORT_PROVISION_TRUST_ERROR;
    }
    provision->trust = trust;
    provision->pinned_root = trust->root;
    provision->candidate = proposal;
    memcpy(provision->root_signature, signature, sizeof(signature));
    if (passport_trust_encode(&proposal, provision->frame,
            sizeof(provision->frame), &provision->frame_length) != PASSPORT_TRUST_OK) {
        return PASSPORT_PROVISION_BAD_MANIFEST;
    }
    if (strcmp(proposal.community_id, provision->pinned_root.community_id) != 0 ||
        (proposal.state == PASSPORT_TRUST_ACTIVE &&
         memcmp(proposal.service_public_x, provision->pinned_root.public_x, 32) == 0 &&
         memcmp(proposal.service_public_y, provision->pinned_root.public_y, 32) == 0) ||
        !passport_p256_verify_p1363(provision->pinned_root.public_x,
            provision->pinned_root.public_y, provision->frame,
            provision->frame_length, signature)) {
        return PASSPORT_PROVISION_UNTRUSTED;
    }
    if (proposal.epoch <= trust->observed_epoch ||
        (mode == PASSPORT_PROVISION_RECOVER && proposal.epoch <= floor)) {
        provision->view.trust_result = PASSPORT_TRUST_REPLAY;
        return PASSPORT_PROVISION_TRUST_ERROR;
    }
    uint8_t sec1[65] = { 4 }, digest[PASSPORT_SHA256_SIZE];
    memcpy(sec1 + 1, provision->pinned_root.public_x, 32);
    memcpy(sec1 + 33, provision->pinned_root.public_y, 32);
    if (!passport_sha256(sec1, sizeof(sec1), digest)) return PASSPORT_PROVISION_UNTRUSTED;
    static const char HEX[] = "0123456789abcdef";
    for (size_t index = 0; index < sizeof(digest); index++) {
        provision->view.root_fingerprint[index * 2] = HEX[digest[index] >> 4];
        provision->view.root_fingerprint[index * 2 + 1] = HEX[digest[index] & 15];
    }
    provision->view.root_fingerprint[PASSPORT_PROVISION_FINGERPRINT_HEX] = '\0';
    memcpy(provision->view.community_id, proposal.community_id, sizeof(proposal.community_id));
    provision->view.epoch = proposal.epoch;
    provision->view.requested_state = proposal.state;
    provision->view.mode = mode;
    provision->view.authoritative_minimum_epoch = floor;
    provision->view.state = PASSPORT_PROVISION_FINGERPRINT;
    provision->started_ms = now_ms;
    provision->last_ms = now_ms;
    provision->timeout_ms = timeout_ms;
    return PASSPORT_PROVISION_OK;
}

passport_provision_result_t passport_provision_tick(
    passport_provision_t *provision, uint64_t now_ms)
{
    const passport_provision_result_t checked = check_time(provision, now_ms);
    if (checked != PASSPORT_PROVISION_OK) return checked;
    return PASSPORT_PROVISION_NO_CHANGE;
}

static passport_provision_result_t process_input(
    passport_provision_t *provision,
    passport_provision_local_event_t event, uint64_t now_ms)
{
    const passport_provision_result_t checked = check_time(provision, now_ms);
    if (checked != PASSPORT_PROVISION_OK) return checked;
    if (event == PASSPORT_PROVISION_CANCEL || event == PASSPORT_PROVISION_OTHER_DOWN) {
        return close_ceremony(provision, PASSPORT_PROVISION_CANCELLED,
                              PASSPORT_PROVISION_WAS_CANCELLED);
    }
    if (event != PASSPORT_PROVISION_OK_DOWN && event != PASSPORT_PROVISION_OK_UP) {
        return close_ceremony(provision, PASSPORT_PROVISION_CANCELLED,
                              PASSPORT_PROVISION_BAD_ARGUMENT);
    }
    if (provision->view.state == PASSPORT_PROVISION_FINGERPRINT) {
        if (event == PASSPORT_PROVISION_OK_DOWN) provision->fingerprint_key_down = true;
        else if (provision->fingerprint_key_down) {
            provision->fingerprint_key_down = false;
            provision->view.state = PASSPORT_PROVISION_REVIEW;
            return PASSPORT_PROVISION_OK;
        }
        return PASSPORT_PROVISION_NO_CHANGE;
    }
    if (provision->view.state == PASSPORT_PROVISION_REVIEW) {
        if (event == PASSPORT_PROVISION_OK_DOWN) {
            provision->hold_started_ms = now_ms;
            provision->view.state = PASSPORT_PROVISION_HOLDING;
            return PASSPORT_PROVISION_OK;
        }
        return PASSPORT_PROVISION_NO_CHANGE;
    }
    if (event == PASSPORT_PROVISION_OK_UP) {
        provision->view.state = PASSPORT_PROVISION_REVIEW;
        provision->hold_started_ms = 0;
        return PASSPORT_PROVISION_OK;
    }
    return PASSPORT_PROVISION_NO_CHANGE;
}

/* Legacy edges are not evidence of continuous contact. Fail closed so an
 * old BSP integration cannot silently retain the former timer approval path. */
passport_provision_result_t passport_provision_local_input(
    passport_provision_t *p, passport_provision_local_event_t event, uint64_t now)
{
    if (event == PASSPORT_PROVISION_CANCEL || event == PASSPORT_PROVISION_OTHER_DOWN)
        return process_input(p, event, now);
    const passport_provision_result_t checked = check_time(p, now);
    if (checked != PASSPORT_PROVISION_OK) return checked;
    return close_ceremony(p, PASSPORT_PROVISION_CANCELLED, PASSPORT_PROVISION_BAD_ARGUMENT);
}

passport_provision_result_t passport_provision_sample(
    passport_provision_t *p, unsigned keys, uint64_t now)
{
    const passport_provision_result_t checked = check_time(p, now);
    if (checked != PASSPORT_PROVISION_OK) return checked;
    if (!p->key_sampled || now - p->last_key_ms > PASSPORT_PROVISION_SAMPLE_GAP_MS) {
        p->released = false;
        p->fingerprint_key_down = false;
        p->hold_started_ms = 0;
        if (p->view.state == PASSPORT_PROVISION_HOLDING)
            p->view.state = PASSPORT_PROVISION_REVIEW;
    }
    p->key_sampled = true;
    p->last_key_ms = now;
    if (keys > 1) return process_input(p, PASSPORT_PROVISION_OTHER_DOWN, now);
    if (!keys) {
        p->released = true;
        return process_input(p, PASSPORT_PROVISION_OK_UP, now);
    }
    if (!p->released) return PASSPORT_PROVISION_NO_CHANGE;
    const passport_provision_result_t result = process_input(p, PASSPORT_PROVISION_OK_DOWN, now);
    if (p->view.state == PASSPORT_PROVISION_HOLDING &&
        now - p->hold_started_ms >= PASSPORT_PROVISION_HOLD_MS)
        return commit_once(p);
    return result;
}

passport_provision_result_t passport_provision_sync_candidate(
    passport_provision_t *provision,
    const passport_trust_manifest_t *candidate,
    const uint8_t root_signature[PASSPORT_P256_P1363_SIZE], uint64_t now_ms)
{
    const passport_provision_result_t checked = check_time(provision, now_ms);
    if (checked != PASSPORT_PROVISION_OK) return checked;
    uint8_t frame[PASSPORT_TRUST_FRAME_MAX];
    size_t length = 0;
    if (!candidate || !root_signature ||
        passport_trust_encode(candidate, frame, sizeof(frame), &length) != PASSPORT_TRUST_OK ||
        length != provision->frame_length || memcmp(frame, provision->frame, length) != 0 ||
        memcmp(root_signature, provision->root_signature, PASSPORT_P256_P1363_SIZE) != 0) {
        return close_ceremony(provision, PASSPORT_PROVISION_STALE,
                              PASSPORT_PROVISION_WAS_STALE);
    }
    return PASSPORT_PROVISION_NO_CHANGE;
}

void passport_provision_get_view(
    const passport_provision_t *provision, passport_provision_view_t *view)
{
    if (!view) return;
    if (!provision) memset(view, 0, sizeof(*view));
    else *view = provision->view;
}
