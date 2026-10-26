#pragma once

#include "passport_trust.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PASSPORT_PROVISION_SAMPLE_GAP_MS UINT64_C(250)
#define PASSPORT_PROVISION_HOLD_MS UINT64_C(2000)
#define PASSPORT_PROVISION_FINGERPRINT_HEX 64

typedef enum {
    PASSPORT_PROVISION_IDLE = 0,
    PASSPORT_PROVISION_FINGERPRINT,
    PASSPORT_PROVISION_REVIEW,
    PASSPORT_PROVISION_HOLDING,
    PASSPORT_PROVISION_COMPLETE,
    PASSPORT_PROVISION_CANCELLED,
    PASSPORT_PROVISION_EXPIRED,
    PASSPORT_PROVISION_STALE,
    PASSPORT_PROVISION_FAILED,
} passport_provision_state_t;

typedef enum {
    PASSPORT_PROVISION_APPLY = 0,
    PASSPORT_PROVISION_RECOVER,
} passport_provision_mode_t;

typedef enum {
    PASSPORT_PROVISION_OK_DOWN = 0,
    PASSPORT_PROVISION_OK_UP,
    PASSPORT_PROVISION_OTHER_DOWN,
    PASSPORT_PROVISION_CANCEL,
} passport_provision_local_event_t;

typedef enum {
    PASSPORT_PROVISION_OK = 0,
    PASSPORT_PROVISION_NO_CHANGE,
    PASSPORT_PROVISION_APPLIED,
    PASSPORT_PROVISION_WAS_CANCELLED,
    PASSPORT_PROVISION_TIMED_OUT,
    PASSPORT_PROVISION_WAS_STALE,
    PASSPORT_PROVISION_BAD_ARGUMENT,
    PASSPORT_PROVISION_BAD_MANIFEST,
    PASSPORT_PROVISION_UNTRUSTED,
    PASSPORT_PROVISION_TRUST_ERROR,
} passport_provision_result_t;

typedef struct {
    passport_provision_state_t state;
    passport_provision_mode_t mode;
    char root_fingerprint[PASSPORT_PROVISION_FINGERPRINT_HEX + 1];
    char community_id[PASSPORT_TRUST_COMMUNITY_MAX + 1];
    uint32_t epoch;
    passport_trust_state_t requested_state;
    uint32_t authoritative_minimum_epoch;
    passport_trust_result_t trust_result;
} passport_provision_view_t;

typedef struct {
    passport_provision_view_t view;
    passport_trust_t *trust;
    passport_trust_root_t pinned_root;
    passport_trust_manifest_t candidate;
    uint8_t root_signature[PASSPORT_P256_P1363_SIZE];
    uint8_t frame[PASSPORT_TRUST_FRAME_MAX];
    size_t frame_length;
    uint64_t started_ms;
    uint64_t last_ms;
    uint64_t timeout_ms;
    uint64_t hold_started_ms;
    bool fingerprint_key_down;
    bool key_sampled;
    bool released;
    uint64_t last_key_ms;
} passport_provision_t;

void passport_provision_init(passport_provision_t *provision);

/* Entry must come from a trusted local settings/maintenance action, never a
 * received NFC/BLE field. Pins are taken from the already-open trust manager.
 * A new begin always discards any old hold and requires fresh review. RECOVER
 * requires an explicitly supplied, independently verified floor pointer; it
 * must not be inferred as zero because local storage is unreadable.
 * The root fingerprint is SHA256(0x04 || X32 || Y32), in full lower-case hex.
 * This controller cannot authenticate a hardware event's origin; that remains
 * the firmware integration contract. It is not a hostile-caller API boundary.
 */
passport_provision_result_t passport_provision_begin_local(
    passport_provision_t *provision,
    passport_trust_t *trust,
    const passport_trust_manifest_t *candidate,
    const uint8_t root_signature[PASSPORT_P256_P1363_SIZE],
    passport_provision_mode_t mode,
    const uint32_t *independently_verified_floor,
    uint64_t now_ms,
    uint64_t timeout_ms);

/* Check the full fingerprint independently. Feed debounced physical key
 * LEVELS (0=none, 1=OK only, other=cancel) at intervals <=250ms. Begin and a
 * sampling gap require a fresh release before a press can count. Fingerprint
 * press/release advances to review; a second continuous 2s press applies.
 * Release never commits. tick and sync never prove physical contact.
 * One serialized worker owns all calls; a successful sample performs crypto
 * and NVS writes. Queue overflow/uncertain source must cancel; never feed
 * network fields, replay queued edges, or cached key levels into sample.
 */
passport_provision_result_t passport_provision_sample(
    passport_provision_t *provision, unsigned keys, uint64_t now_ms);
/* Cancellation only. Legacy OK_DOWN/OK_UP events fail closed with BAD_ARGUMENT
 * and cancel: callers must migrate to actual periodic level sampling. */
passport_provision_result_t passport_provision_local_input(
    passport_provision_t *provision,
    passport_provision_local_event_t event,
    uint64_t now_ms);
passport_provision_result_t passport_provision_tick(
    passport_provision_t *provision, uint64_t now_ms);

/* A refresh that changes candidate bytes or signature invalidates this local
 * ceremony; it never silently replaces the reviewed candidate or writes it.
 */
passport_provision_result_t passport_provision_sync_candidate(
    passport_provision_t *provision,
    const passport_trust_manifest_t *candidate,
    const uint8_t root_signature[PASSPORT_P256_P1363_SIZE],
    uint64_t now_ms);

void passport_provision_get_view(
    const passport_provision_t *provision, passport_provision_view_t *view);
