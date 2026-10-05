#include "passport_outbox_nvs.h"

#include <string.h>

static const char *const KEYS[PASSPORT_OUTBOX_SLOT_COUNT] = { "outbox0", "outbox1" };

static passport_store_result_t nvs_read_slot(
    void *context, size_t slot, uint8_t *output, size_t capacity, size_t *length)
{
    passport_outbox_nvs_t *storage = context;
    if (!storage || !storage->open || slot >= PASSPORT_OUTBOX_SLOT_COUNT || !output || !length) {
        return PASSPORT_STORE_ERROR;
    }
    size_t stored = 0;
    esp_err_t error = nvs_get_blob(storage->handle, KEYS[slot], NULL, &stored);
    if (error == ESP_ERR_NVS_NOT_FOUND) return PASSPORT_STORE_NOT_FOUND;
    if (error != ESP_OK || stored > capacity) return PASSPORT_STORE_ERROR;
    error = nvs_get_blob(storage->handle, KEYS[slot], output, &stored);
    if (error != ESP_OK) return PASSPORT_STORE_ERROR;
    *length = stored;
    return PASSPORT_STORE_OK;
}

static bool nvs_write_slot(void *context, size_t slot, const uint8_t *data, size_t length)
{
    passport_outbox_nvs_t *storage = context;
    if (!storage || !storage->open || slot >= PASSPORT_OUTBOX_SLOT_COUNT || !data || !length) return false;
    return nvs_set_blob(storage->handle, KEYS[slot], data, length) == ESP_OK &&
           nvs_commit(storage->handle) == ESP_OK;
}

bool passport_outbox_nvs_open(passport_outbox_nvs_t *storage, const char *name_space)
{
    if (!storage || !name_space) return false;
    memset(storage, 0, sizeof(*storage));
    storage->open = nvs_open(name_space, NVS_READWRITE, &storage->handle) == ESP_OK;
    return storage->open;
}

void passport_outbox_nvs_close(passport_outbox_nvs_t *storage)
{
    if (!storage || !storage->open) return;
    nvs_close(storage->handle);
    storage->open = false;
}

passport_outbox_store_t passport_outbox_nvs_store(passport_outbox_nvs_t *storage)
{
    return (passport_outbox_store_t) {
        .context = storage,
        .read = nvs_read_slot,
        .write = nvs_write_slot,
    };
}
