#include "passport_core.h"

#include <string.h>

static const char *const CONTRIBUTION[] = { "receive", "needs_change", "decline" };
static const char *const ORDER[] = { "spend", "decline" };
static const char *const REFUND[] = { "receive_refund", "decline" };
static const char *const BORROW[] = { "accept_task", "needs_change", "decline" };
static const char *const EXPRESSION[] = { "accurate", "needs_change", "original_only", "no_retelling" };
static const char *const GRANT[] = { "approve", "needs_change", "decline" };

static const char *const *decision_table(passport_kind_t kind, size_t *count)
{
    switch (kind) {
    case PASSPORT_KIND_CONTRIBUTION: *count = 3; return CONTRIBUTION;
    case PASSPORT_KIND_ORDER: *count = 2; return ORDER;
    case PASSPORT_KIND_REFUND: *count = 2; return REFUND;
    case PASSPORT_KIND_BORROW: *count = 3; return BORROW;
    case PASSPORT_KIND_EXPRESSION: *count = 4; return EXPRESSION;
    case PASSPORT_KIND_GRANT: *count = 3; return GRANT;
    }
    *count = 0;
    return NULL;
}

size_t passport_decision_count(passport_kind_t kind)
{
    size_t count;
    (void)decision_table(kind, &count);
    return count;
}

const char *passport_decision(passport_kind_t kind, size_t index)
{
    size_t count;
    const char *const *table = decision_table(kind, &count);
    return table && index < count ? table[index] : NULL;
}

void passport_model_init(passport_model_t *model)
{
    memset(model, 0, sizeof(*model));
    model->page = PASSPORT_PAGE_INBOX;
}

static passport_action_t expire(passport_model_t *model, uint64_t now_ms)
{
    if (!model->request_loaded || now_ms < model->request.expires_at_ms) {
        return PASSPORT_ACTION_NONE;
    }
    model->request_loaded = false;
    model->page = PASSPORT_PAGE_RESULT;
    return PASSPORT_ACTION_EXPIRED;
}

passport_action_t passport_model_load(passport_model_t *model,
                                      const passport_request_t *request,
                                      uint64_t now_ms)
{
    if (!request || now_ms >= request->expires_at_ms) {
        model->request_loaded = false;
        model->page = PASSPORT_PAGE_RESULT;
        return PASSPORT_ACTION_EXPIRED;
    }
    model->request = *request;
    model->choice = 0;
    model->request_loaded = true;
    model->page = PASSPORT_PAGE_REVIEW;
    return PASSPORT_ACTION_RENDER;
}

passport_action_t passport_model_sync(passport_model_t *model,
                                      const passport_request_t *request,
                                      uint64_t now_ms)
{
    passport_action_t expired = expire(model, now_ms);
    if (expired != PASSPORT_ACTION_NONE) return expired;
    if (!request || request->version != model->request.version ||
        request->kind != model->request.kind ||
        memcmp(request->digest, model->request.digest, sizeof(request->digest)) != 0) {
        model->request_loaded = false;
        model->page = PASSPORT_PAGE_RESULT;
        return PASSPORT_ACTION_SUPERSEDED;
    }
    model->request.expires_at_ms = request->expires_at_ms;
    return PASSPORT_ACTION_NONE;
}

passport_action_t passport_model_tick(passport_model_t *model, uint64_t now_ms)
{
    return expire(model, now_ms);
}

passport_action_t passport_model_input(passport_model_t *model,
                                       passport_key_t key,
                                       passport_press_t press,
                                       uint64_t now_ms)
{
    passport_action_t expired = expire(model, now_ms);
    if (expired != PASSPORT_ACTION_NONE) return expired;
    if (!model->request_loaded) return PASSPORT_ACTION_NONE;

    if (model->page == PASSPORT_PAGE_REVIEW) {
        if (press == PASSPORT_PRESS_CLICK && key == PASSPORT_KEY_OK) {
            model->page = PASSPORT_PAGE_CHOOSE;
            return PASSPORT_ACTION_RENDER;
        }
        if (press == PASSPORT_PRESS_CLICK && key == PASSPORT_KEY_UP) {
            model->page = PASSPORT_PAGE_INBOX;
            return PASSPORT_ACTION_RENDER;
        }
    } else if (model->page == PASSPORT_PAGE_CHOOSE) {
        const size_t count = passport_decision_count(model->request.kind);
        if (press == PASSPORT_PRESS_CLICK && key == PASSPORT_KEY_UP) {
            model->choice = (model->choice + count - 1) % count;
            return PASSPORT_ACTION_RENDER;
        }
        if (press == PASSPORT_PRESS_CLICK && key == PASSPORT_KEY_DOWN) {
            model->choice = (model->choice + 1) % count;
            return PASSPORT_ACTION_RENDER;
        }
        if (press == PASSPORT_PRESS_CLICK && key == PASSPORT_KEY_OK) {
            model->page = PASSPORT_PAGE_CONFIRM;
            return PASSPORT_ACTION_RENDER;
        }
    } else if (model->page == PASSPORT_PAGE_CONFIRM) {
        if (press == PASSPORT_PRESS_CLICK && key == PASSPORT_KEY_UP) {
            model->page = PASSPORT_PAGE_CHOOSE;
            return PASSPORT_ACTION_RENDER;
        }
        // Only the BSP's two-second continuous OK long event can request a
        // signature. A click, silence, another key, or a stale request cannot.
        if (press == PASSPORT_PRESS_LONG && key == PASSPORT_KEY_OK) {
            model->page = PASSPORT_PAGE_RESULT;
            return PASSPORT_ACTION_SIGNATURE_READY;
        }
    } else if (model->page == PASSPORT_PAGE_RESULT &&
               press == PASSPORT_PRESS_CLICK && key == PASSPORT_KEY_OK) {
        model->page = PASSPORT_PAGE_INBOX;
        return PASSPORT_ACTION_RENDER;
    }
    return PASSPORT_ACTION_NONE;
}
