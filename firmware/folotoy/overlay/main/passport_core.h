#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    PASSPORT_KIND_CONTRIBUTION,
    PASSPORT_KIND_ORDER,
    PASSPORT_KIND_REFUND,
    PASSPORT_KIND_BORROW,
    PASSPORT_KIND_EXPRESSION,
    PASSPORT_KIND_GRANT,
} passport_kind_t;

typedef enum {
    PASSPORT_PAGE_INBOX,
    PASSPORT_PAGE_REVIEW,
    PASSPORT_PAGE_CHOOSE,
    PASSPORT_PAGE_CONFIRM,
    PASSPORT_PAGE_RESULT,
} passport_page_t;

typedef enum {
    PASSPORT_KEY_UP,
    PASSPORT_KEY_DOWN,
    PASSPORT_KEY_OK,
} passport_key_t;

typedef enum {
    PASSPORT_PRESS_CLICK,
    PASSPORT_PRESS_LONG,
} passport_press_t;

typedef enum {
    PASSPORT_ACTION_NONE,
    PASSPORT_ACTION_RENDER,
    PASSPORT_ACTION_SIGNATURE_READY,
    PASSPORT_ACTION_EXPIRED,
    PASSPORT_ACTION_SUPERSEDED,
} passport_action_t;

typedef struct {
    passport_kind_t kind;
    uint32_t version;
    uint8_t digest[32];
    uint64_t expires_at_ms;
} passport_request_t;

typedef struct {
    passport_page_t page;
    passport_request_t request;
    size_t choice;
    bool request_loaded;
} passport_model_t;

void passport_model_init(passport_model_t *model);
passport_action_t passport_model_load(passport_model_t *model,
                                      const passport_request_t *request,
                                      uint64_t now_ms);
passport_action_t passport_model_sync(passport_model_t *model,
                                      const passport_request_t *request,
                                      uint64_t now_ms);
passport_action_t passport_model_tick(passport_model_t *model, uint64_t now_ms);
passport_action_t passport_model_input(passport_model_t *model,
                                       passport_key_t key,
                                       passport_press_t press,
                                       uint64_t now_ms);
size_t passport_decision_count(passport_kind_t kind);
const char *passport_decision(passport_kind_t kind, size_t index);
