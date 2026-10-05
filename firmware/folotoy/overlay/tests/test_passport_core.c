#include <assert.h>
#include <string.h>

#include "passport_core.h"

static passport_request_t request(passport_kind_t kind, uint32_t version, uint64_t expiry)
{
    passport_request_t value = { .kind = kind, .version = version, .expires_at_ms = expiry };
    memset(value.digest, (int)version, sizeof(value.digest));
    return value;
}

int main(void)
{
    assert(strcmp(passport_decision(PASSPORT_KIND_CONTRIBUTION, 0), "receive") == 0);
    assert(strcmp(passport_decision(PASSPORT_KIND_ORDER, 0), "spend") == 0);
    assert(strcmp(passport_decision(PASSPORT_KIND_REFUND, 0), "receive_refund") == 0);
    assert(strcmp(passport_decision(PASSPORT_KIND_BORROW, 0), "accept_task") == 0);
    assert(strcmp(passport_decision(PASSPORT_KIND_EXPRESSION, 2), "original_only") == 0);
    assert(strcmp(passport_decision(PASSPORT_KIND_EXPRESSION, 3), "no_retelling") == 0);
    assert(strcmp(passport_decision(PASSPORT_KIND_GRANT, 0), "approve") == 0);
    assert(passport_decision(PASSPORT_KIND_ORDER, 2) == NULL);

    passport_model_t model;
    passport_model_init(&model);
    passport_request_t v1 = request(PASSPORT_KIND_CONTRIBUTION, 1, 3000);
    assert(passport_model_load(&model, &v1, 1000) == PASSPORT_ACTION_RENDER);
    assert(model.page == PASSPORT_PAGE_REVIEW);
    assert(passport_model_input(&model, PASSPORT_KEY_OK, PASSPORT_PRESS_CLICK, 1100) == PASSPORT_ACTION_RENDER);
    assert(passport_model_input(&model, PASSPORT_KEY_DOWN, PASSPORT_PRESS_CLICK, 1200) == PASSPORT_ACTION_RENDER);
    assert(strcmp(passport_decision(v1.kind, model.choice), "needs_change") == 0);
    assert(passport_model_input(&model, PASSPORT_KEY_OK, PASSPORT_PRESS_CLICK, 1300) == PASSPORT_ACTION_RENDER);
    assert(model.page == PASSPORT_PAGE_CONFIRM);

    // Early release, silence and a different long-pressed key never approve.
    assert(passport_model_input(&model, PASSPORT_KEY_OK, PASSPORT_PRESS_CLICK, 1400) == PASSPORT_ACTION_NONE);
    assert(passport_model_tick(&model, 1800) == PASSPORT_ACTION_NONE);
    assert(passport_model_input(&model, PASSPORT_KEY_DOWN, PASSPORT_PRESS_LONG, 1900) == PASSPORT_ACTION_NONE);
    assert(passport_model_input(&model, PASSPORT_KEY_OK, PASSPORT_PRESS_LONG, 2000) == PASSPORT_ACTION_SIGNATURE_READY);

    passport_model_init(&model);
    assert(passport_model_load(&model, &v1, 1000) == PASSPORT_ACTION_RENDER);
    passport_request_t v2 = request(PASSPORT_KIND_CONTRIBUTION, 2, 4000);
    assert(passport_model_sync(&model, &v2, 1500) == PASSPORT_ACTION_SUPERSEDED);
    assert(!model.request_loaded);
    assert(passport_model_input(&model, PASSPORT_KEY_OK, PASSPORT_PRESS_LONG, 1600) == PASSPORT_ACTION_NONE);

    passport_model_init(&model);
    assert(passport_model_load(&model, &v1, 1000) == PASSPORT_ACTION_RENDER);
    assert(passport_model_tick(&model, 2999) == PASSPORT_ACTION_NONE);
    assert(passport_model_tick(&model, 3000) == PASSPORT_ACTION_EXPIRED);
    assert(!model.request_loaded);
    assert(passport_model_load(&model, &v1, 3000) == PASSPORT_ACTION_EXPIRED);
    return 0;
}
