#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PASSPORT_SHA256_SIZE 32
#define PASSPORT_P256_COORD_SIZE 32
#define PASSPORT_P256_P1363_SIZE 64

bool passport_sha256(const uint8_t *message, size_t length,
                     uint8_t output[PASSPORT_SHA256_SIZE]);
bool passport_p256_verify_p1363(
    const uint8_t public_x[PASSPORT_P256_COORD_SIZE],
    const uint8_t public_y[PASSPORT_P256_COORD_SIZE],
    const uint8_t *message,
    size_t message_length,
    const uint8_t signature[PASSPORT_P256_P1363_SIZE]);
