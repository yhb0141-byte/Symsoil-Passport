#include "passport_core.h"

#include "bsp_battery.h"
#include "bsp_button.h"
#include "bsp_display.h"
#include "bsp_i2c.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "lvgl.h"

#include <stdio.h>
#include <string.h>

#define INPUT_QUEUE_DEPTH 8
#define COLOR_FOREST 0x163F32
#define COLOR_FOREST_2 0x245846
#define COLOR_CREAM 0xF3F0DF
#define COLOR_SUN 0xF2CB45
#define COLOR_MUTED 0xA8C5B7

typedef struct {
    bsp_btn_t button;
    bsp_btn_ev_t event;
} input_event_t;

static const char *TAG = "symsoil_passport";
static QueueHandle_t s_input_queue;
static TaskHandle_t s_input_task;
static volatile bool s_input_ready;
static passport_model_t s_model;
static passport_request_t s_fixture;
static lv_obj_t *s_screen;
static lv_obj_t *s_title;
static lv_obj_t *s_body;
static lv_obj_t *s_hint;
static lv_obj_t *s_battery;
static lv_timer_t *s_tick;
static const char *s_result = "No response submitted.";

static uint64_t now_ms(void)
{
    return (uint64_t)(esp_timer_get_time() / 1000);
}

static const char *decision_label(const char *decision)
{
    if (!decision) return "Unknown";
    if (strcmp(decision, "receive") == 0) return "Receive +30 points";
    if (strcmp(decision, "needs_change") == 0) return "Needs a change";
    if (strcmp(decision, "decline") == 0) return "Decline";
    return decision;
}

static void set_text(lv_obj_t *label, const char *text, uint32_t color,
                     const lv_font_t *font)
{
    lv_label_set_text(label, text);
    lv_obj_set_style_text_color(label, lv_color_hex(color), 0);
    lv_obj_set_style_text_font(label, font, 0);
    lv_obj_set_style_text_align(label, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_width(label, 204);
}

static void render(void)
{
    char body[256];
    const char *title = "SYMSOIL PASSPORT";
    const char *hint = "UP / DOWN   OK";

    switch (s_model.page) {
    case PASSPORT_PAGE_INBOX:
        title = "COMMUNITY INBOX";
        snprintf(body, sizeof(body),
                 "1 request\n\nGarden care\n+30 community points\n\nViewing is not consent.");
        hint = "OK: read request";
        break;
    case PASSPORT_PAGE_REVIEW:
        title = "READ THE REQUEST";
        snprintf(body, sizeof(body),
                 "Contribution  v%lu\n\nGarden care\n+30 community points\n\nRecord: synthetic test\nNo NFC balance is trusted.",
                 (unsigned long)s_model.request.version);
        hint = "UP: back   OK: choices";
        break;
    case PASSPORT_PAGE_CHOOSE:
        title = "CHOOSE A REPLY";
        snprintf(body, sizeof(body), "\n<  %s  >\n\nThis choice applies only\nto this exact version.",
                 decision_label(passport_decision(s_model.request.kind, s_model.choice)));
        hint = "UP / DOWN   OK: review";
        break;
    case PASSPORT_PAGE_CONFIRM:
        title = "FINAL REVIEW";
        snprintf(body, sizeof(body), "%s\n\nGarden care  +30\nv%lu\n\nShort press does nothing.",
                 decision_label(passport_decision(s_model.request.kind, s_model.choice)),
                 (unsigned long)s_model.request.version);
        hint = "Hold OK for 2 seconds";
        break;
    case PASSPORT_PAGE_RESULT:
        title = "TEST RESULT";
        snprintf(body, sizeof(body), "%s\n\nThis acceptance build\ndoes not sign or change\nthe community ledger.", s_result);
        hint = "OK: return to inbox";
        break;
    }

    set_text(s_title, title, COLOR_SUN, &lv_font_montserrat_20);
    set_text(s_body, body, COLOR_CREAM, &lv_font_montserrat_14);
    set_text(s_hint, hint, COLOR_MUTED, &lv_font_montserrat_14);
    int soc = bsp_battery_soc();
    if (soc >= 0) lv_label_set_text_fmt(s_battery, "%d%%", soc);
    else lv_label_set_text(s_battery, "--");
}

static void show_action(passport_action_t action)
{
    if (action == PASSPORT_ACTION_SIGNATURE_READY) {
        s_result = "Explicit 2-second hold observed.";
        ESP_LOGI(TAG, "SYNTHETIC acceptance event: decision=%s version=%lu (no signature, no ledger write)",
                 passport_decision(s_model.request.kind, s_model.choice),
                 (unsigned long)s_model.request.version);
    } else if (action == PASSPORT_ACTION_EXPIRED) {
        s_result = "Request expired. Re-open required.";
    } else if (action == PASSPORT_ACTION_SUPERSEDED) {
        s_result = "Content changed. Re-read required.";
    }
    if (action != PASSPORT_ACTION_NONE) render();
}

static void tick(lv_timer_t *timer)
{
    (void)timer;
    show_action(passport_model_tick(&s_model, now_ms()));
}

static void build_ui(void)
{
    s_screen = lv_obj_create(NULL);
    lv_obj_remove_style_all(s_screen);
    lv_obj_set_style_bg_color(s_screen, lv_color_hex(COLOR_FOREST), 0);
    lv_obj_set_style_bg_opa(s_screen, LV_OPA_COVER, 0);

    lv_obj_t *sun = lv_obj_create(s_screen);
    lv_obj_remove_style_all(sun);
    lv_obj_set_size(sun, 11, 11);
    lv_obj_set_style_radius(sun, LV_RADIUS_CIRCLE, 0);
    lv_obj_set_style_bg_color(sun, lv_color_hex(COLOR_SUN), 0);
    lv_obj_set_style_bg_opa(sun, LV_OPA_COVER, 0);
    lv_obj_align(sun, LV_ALIGN_TOP_LEFT, 17, 16);

    s_battery = lv_label_create(s_screen);
    lv_obj_set_style_text_font(s_battery, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(s_battery, lv_color_hex(COLOR_MUTED), 0);
    lv_obj_align(s_battery, LV_ALIGN_TOP_RIGHT, -16, 14);

    lv_obj_t *card = lv_obj_create(s_screen);
    lv_obj_set_size(card, 216, 244);
    lv_obj_align(card, LV_ALIGN_TOP_MID, 0, 38);
    lv_obj_set_style_bg_color(card, lv_color_hex(COLOR_FOREST_2), 0);
    lv_obj_set_style_bg_opa(card, LV_OPA_COVER, 0);
    lv_obj_set_style_border_color(card, lv_color_hex(0x5C8775), 0);
    lv_obj_set_style_border_width(card, 1, 0);
    lv_obj_set_style_radius(card, 18, 0);
    lv_obj_set_style_pad_all(card, 6, 0);
    lv_obj_clear_flag(card, LV_OBJ_FLAG_SCROLLABLE);

    s_title = lv_label_create(card);
    lv_obj_align(s_title, LV_ALIGN_TOP_MID, 0, 12);
    s_body = lv_label_create(card);
    lv_obj_align(s_body, LV_ALIGN_TOP_MID, 0, 58);
    lv_label_set_long_mode(s_body, LV_LABEL_LONG_WRAP);
    s_hint = lv_label_create(card);
    lv_obj_align(s_hint, LV_ALIGN_BOTTOM_MID, 0, -12);

    lv_obj_t *foot = lv_label_create(s_screen);
    lv_label_set_text(foot, "HARDWARE ACCEPTANCE  /  NO LEDGER WRITE");
    lv_obj_set_style_text_font(foot, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(foot, lv_color_hex(COLOR_MUTED), 0);
    lv_obj_align(foot, LV_ALIGN_BOTTOM_MID, 0, -13);

    lv_screen_load(s_screen);
    s_tick = lv_timer_create(tick, 250, NULL);
    render();
}

static bool translate(const input_event_t *input, passport_key_t *key,
                      passport_press_t *press)
{
    if (input->button == BSP_BTN_UP) *key = PASSPORT_KEY_UP;
    else if (input->button == BSP_BTN_DOWN) *key = PASSPORT_KEY_DOWN;
    else if (input->button == BSP_BTN_OK) *key = PASSPORT_KEY_OK;
    else return false;

    if (input->event == BSP_BTN_CLICK) *press = PASSPORT_PRESS_CLICK;
    else if (input->event == BSP_BTN_LONG) *press = PASSPORT_PRESS_LONG;
    else return false;
    return true;
}

static void process_input(const input_event_t *input)
{
    passport_key_t key;
    passport_press_t press;
    if (!translate(input, &key, &press)) return;

    if (s_model.page == PASSPORT_PAGE_INBOX && key == PASSPORT_KEY_OK &&
        press == PASSPORT_PRESS_CLICK) {
        show_action(passport_model_load(&s_model, &s_fixture, now_ms()));
        return;
    }
    show_action(passport_model_input(&s_model, key, press, now_ms()));
}

static void input_task(void *arg)
{
    (void)arg;
    input_event_t input;
    for (;;) {
        if (xQueueReceive(s_input_queue, &input, portMAX_DELAY) != pdTRUE) continue;
        if (!bsp_lvgl_lock(500)) continue;
        process_input(&input);
        bsp_lvgl_unlock();
    }
}

static void on_key(bsp_btn_t button, bsp_btn_ev_t event, void *user)
{
    (void)user;
    if (!s_input_ready || !s_input_queue) return;
    const input_event_t input = { .button = button, .event = event };
    (void)xQueueSend(s_input_queue, &input, 0);
}

void app_main(void)
{
    ESP_LOGI(TAG, "starting Symsoil hardware acceptance build");
    passport_model_init(&s_model);
    s_fixture = (passport_request_t) {
        .kind = PASSPORT_KIND_CONTRIBUTION,
        .version = 1,
        .expires_at_ms = now_ms() + 10 * 60 * 1000,
    };
    memset(s_fixture.digest, 0xA5, sizeof(s_fixture.digest));

    (void)bsp_i2c_init();
    if (bsp_display_init() != ESP_OK || !bsp_lvgl_init()) {
        ESP_LOGE(TAG, "display/LVGL initialization failed");
        return;
    }
    bsp_display_backlight(80);
    (void)bsp_battery_init();

    s_input_queue = xQueueCreate(INPUT_QUEUE_DEPTH, sizeof(input_event_t));
    if (!s_input_queue || xTaskCreate(input_task, "passport_input", 4096, NULL, 5,
                                      &s_input_task) != pdPASS) {
        ESP_LOGE(TAG, "input worker allocation failed");
        return;
    }
    if (bsp_button_init(on_key, NULL) != ESP_OK) {
        ESP_LOGE(TAG, "button initialization failed");
        return;
    }
    if (bsp_lvgl_lock(1000)) {
        build_ui();
        bsp_lvgl_unlock();
        s_input_ready = true;
    }
}
