#pragma once

#include "passport_outbox.h"

#include "nvs.h"

typedef struct {
    nvs_handle_t handle;
    bool open;
} passport_outbox_nvs_t;

// nvs_flash_init() remains the application's responsibility. This adapter
// stores only the signed public reply envelope, never a private key.
bool passport_outbox_nvs_open(passport_outbox_nvs_t *storage, const char *name_space);
void passport_outbox_nvs_close(passport_outbox_nvs_t *storage);
passport_outbox_store_t passport_outbox_nvs_store(passport_outbox_nvs_t *storage);
