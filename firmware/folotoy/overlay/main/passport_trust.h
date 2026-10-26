#pragma once

#include "passport_crypto.h"
#include "passport_outbox.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PASSPORT_TRUST_COMMUNITY_MAX 64
#define PASSPORT_TRUST_FRAME_MAX 152
#define PASSPORT_TRUST_RECORD_MAX 220

typedef enum {
    PASSPORT_TRUST_UNPROVISIONED = 0,
    PASSPORT_TRUST_ACTIVE = 1,
    PASSPORT_TRUST_SUSPENDED = 2,
    PASSPORT_TRUST_LOCKED = 3,
} passport_trust_state_t;

typedef enum {
    PASSPORT_TRUST_OK = 0,
    PASSPORT_TRUST_EMPTY,
    PASSPORT_TRUST_IS_SUSPENDED,
    PASSPORT_TRUST_IS_LOCKED,
    PASSPORT_TRUST_BAD_ARGUMENT,
    PASSPORT_TRUST_BAD_DATA,
    PASSPORT_TRUST_UNTRUSTED,
    PASSPORT_TRUST_REPLAY,
    PASSPORT_TRUST_LOCAL_CONFIRMATION_REQUIRED,
    PASSPORT_TRUST_IO_ERROR,
} passport_trust_result_t;

typedef struct {
    char community_id[PASSPORT_TRUST_COMMUNITY_MAX + 1];
    uint8_t public_x[PASSPORT_P256_COORD_SIZE];
    uint8_t public_y[PASSPORT_P256_COORD_SIZE];
} passport_trust_root_t;

typedef struct {
    char community_id[PASSPORT_TRUST_COMMUNITY_MAX + 1];
    uint32_t epoch;
    passport_trust_state_t state; /* ACTIVE or SUSPENDED only */
    uint8_t service_public_x[PASSPORT_P256_COORD_SIZE];
    uint8_t service_public_y[PASSPORT_P256_COORD_SIZE];
} passport_trust_manifest_t;

typedef struct {
    passport_outbox_store_t store; /* Dedicated namespace; never the outbox. */
    passport_trust_root_t root; /* Build/local ceremony pin; no update API. */
    passport_trust_manifest_t manifest;
    passport_trust_state_t state;
    uint32_t observed_epoch;
    bool initialized;
} passport_trust_t;

/* Signed bytes: domain `symsoil-trust/1` plus NUL (16), state (1), ASCII
 * community length (1), zero reserved (2), epoch u32 LE (4), community bytes,
 * service X (32), service Y (32). SUSPENDED encodes zero service coordinates.
 * No wall clock is needed. CRC detects storage damage, never authenticity or
 * rollback. Only root signatures authorize a new service key. */
passport_trust_result_t passport_trust_encode(
    const passport_trust_manifest_t *manifest,
    uint8_t *output, size_t capacity, size_t *length);

/* All operations require one serialized lifecycle owner; storage callbacks do
 * not provide cross-task locking or compare-and-swap.
 * Every stored manifest is reverified under the supplied locally pinned root.
 * Both slots must be present, valid and byte-identical to permit service use.
 * A missing, corrupt, divergent or unreadable copy locks the trust manager. */
passport_trust_result_t passport_trust_open(
    passport_trust_t *trust, const passport_outbox_store_t *store,
    const passport_trust_root_t *root);

/* First provisioning additionally needs explicit local confirmation. A caller
 * must derive this flag from a physical/local ceremony, never an NFC/BLE field.
 * Normal ACTIVE/SUSPENDED updates require a strictly greater signed epoch. */
passport_trust_result_t passport_trust_apply(
    passport_trust_t *trust, const passport_trust_manifest_t *manifest,
    const uint8_t root_signature[PASSPORT_P256_P1363_SIZE],
    bool locally_confirmed);

/* LOCKED recovery requires physical confirmation and a separately established
 * authoritative epoch floor, plus a root-signed epoch greater than both that
 * floor and every valid record observed. If both copies are corrupt the device
 * cannot establish the true previous floor itself. No API rotates the root. */
passport_trust_result_t passport_trust_recover(
    passport_trust_t *trust, const passport_trust_manifest_t *manifest,
    const uint8_t root_signature[PASSPORT_P256_P1363_SIZE],
    bool locally_confirmed, uint32_t authoritative_minimum_epoch);

/* Rechecks mirrored storage before returning the current key. No arbitrary
 * link-supplied key may replace this selection. Failure leaves outputs zero. */
passport_trust_result_t passport_trust_get_service(
    passport_trust_t *trust, const char *community_id,
    uint8_t public_x[PASSPORT_P256_COORD_SIZE],
    uint8_t public_y[PASSPORT_P256_COORD_SIZE], uint32_t *epoch);
