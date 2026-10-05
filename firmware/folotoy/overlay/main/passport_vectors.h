#pragma once

#include "passport_protocol.h"

#include <stddef.h>

typedef struct {
    const char *name;
    passport_confirmation_frame_t frame;
    const char *canonical_content;
    const char *canonical_frame;
    const char *public_x;
    const char *public_y;
    const char *signature;
} passport_protocol_vector_t;

typedef struct {
    passport_delivery_result_frame_t frame;
    const char *canonical_frame;
    const char *public_x;
    const char *public_y;
    const char *signature;
} passport_delivery_result_vector_t;

const passport_protocol_vector_t *passport_protocol_vectors(size_t *count);
const passport_delivery_result_vector_t *passport_delivery_result_vector(void);

// Returns zero after all public synthetic vectors pass. A negative result
// identifies the vector and stage; no private material is involved.
int passport_protocol_vectors_selftest(void);
