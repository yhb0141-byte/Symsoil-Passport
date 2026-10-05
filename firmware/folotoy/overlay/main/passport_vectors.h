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

const passport_protocol_vector_t *passport_protocol_vectors(size_t *count);

// Returns zero after all public synthetic vectors pass. A negative result
// identifies the vector and stage; no private material is involved.
int passport_protocol_vectors_selftest(void);
