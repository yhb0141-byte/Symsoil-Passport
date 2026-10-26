#include "passport_text.h"
#include <string.h>

static bool decode(const uint8_t *in, size_t left, uint32_t *cp, size_t *bytes)
{
    if (!left) return false;
    uint8_t first = in[0];
    size_t count;
    uint32_t value, minimum;
    if (first < 0x80) { count = 1; value = first; minimum = 0; }
    else if (first >= 0xc2 && first <= 0xdf) { count = 2; value = first & 0x1f; minimum = 0x80; }
    else if (first >= 0xe0 && first <= 0xef) { count = 3; value = first & 0x0f; minimum = 0x800; }
    else if (first >= 0xf0 && first <= 0xf4) { count = 4; value = first & 7; minimum = 0x10000; }
    else return false;
    if (left < count) return false;
    for (size_t i = 1; i < count; ++i) {
        if ((in[i] & 0xc0) != 0x80) return false;
        value = (value << 6) | (in[i] & 0x3f);
    }
    if (value < minimum || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff)) return false;
    *cp = value; *bytes = count;
    return true;
}
static size_t cells(uint32_t cp)
{
    if (cp >= 0x20 && cp <= 0x7e) return 1;
    if ((cp >= 0x3000 && cp <= 0x303f && !(cp >= 0x302a && cp <= 0x302f)) ||
        (cp >= 0x3400 && cp <= 0x4dbf) || (cp >= 0x4e00 && cp <= 0x9fff) ||
        (cp >= 0xff01 && cp <= 0xff60)) return 2;
    return 0;
}
static passport_text_result_t fail(passport_text_t *t, passport_text_result_t result, uint32_t cp)
{
    memset(t, 0, sizeof(*t));
    t->result = result; t->blocked_codepoint = cp;
    return result;
}
static bool next_line(passport_text_t *t, size_t *row, size_t rows)
{
    if (++*row == rows) {
        if (t->page_count == PASSPORT_TEXT_PAGES_MAX || t->used + 1 >= sizeof(t->text)) return false;
        t->text[t->used++] = '\0';
        t->offsets[t->page_count++] = t->used;
        *row = 0;
    } else {
        if (t->used + 1 >= sizeof(t->text)) return false;
        t->text[t->used++] = '\n';
    }
    return true;
}
passport_text_result_t passport_text_open(passport_text_t *t,
    const uint8_t *input, size_t length, size_t columns, size_t rows,
    passport_text_glyph_fn has_glyph, void *context)
{
    if (!t) return PASSPORT_TEXT_INVALID;
    memset(t, 0, sizeof(*t));
    if (!input || !length || !has_glyph || columns < 2 || columns > 80 || !rows || rows > 40)
        return fail(t, PASSPORT_TEXT_INVALID, 0);
    if (length > PASSPORT_TEXT_INPUT_MAX) return fail(t, PASSPORT_TEXT_TOO_LARGE, 0);
    t->page_count = 1;
    size_t row = 0, column = 0;
    for (size_t offset = 0; offset < length;) {
        uint32_t cp; size_t bytes;
        if (!decode(input + offset, length - offset, &cp, &bytes)) return fail(t, PASSPORT_TEXT_INVALID, 0);
        if (cp == '\n') {
            if (!next_line(t, &row, rows)) return fail(t, PASSPORT_TEXT_TOO_LARGE, 0);
            column = 0;
        } else {
            size_t width = cells(cp);
            if (!width) return fail(t, PASSPORT_TEXT_UNSUPPORTED, cp);
            if (!has_glyph(context, cp)) return fail(t, PASSPORT_TEXT_MISSING_GLYPH, cp);
            if (column + width > columns) {
                if (!next_line(t, &row, rows)) return fail(t, PASSPORT_TEXT_TOO_LARGE, 0);
                column = 0;
            }
            if (bytes >= sizeof(t->text) - t->used) return fail(t, PASSPORT_TEXT_TOO_LARGE, 0);
            memcpy(t->text + t->used, input + offset, bytes);
            t->used += bytes;
            column += width;
        }
        offset += bytes;
    }
    t->text[t->used++] = '\0';
    t->result = PASSPORT_TEXT_OK;
    return PASSPORT_TEXT_OK;
}
bool passport_text_page(const passport_text_t *t, size_t page, char *output, size_t capacity)
{
    if (!output || !capacity) return false;
    output[0] = '\0';
    if (!t || t->result != PASSPORT_TEXT_OK || page >= t->page_count) return false;
    size_t start = t->offsets[page];
    size_t end = page + 1 < t->page_count ? t->offsets[page + 1] : t->used;
    if (end <= start || end - start > capacity) return false;
    memcpy(output, t->text + start, end - start);
    return true;
}
