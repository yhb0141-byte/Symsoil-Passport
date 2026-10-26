#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PASSPORT_TEXT_INPUT_MAX 4096
#define PASSPORT_TEXT_PAGES_MAX 128
#define PASSPORT_TEXT_BUFFER_MAX (2 * PASSPORT_TEXT_INPUT_MAX + PASSPORT_TEXT_PAGES_MAX + 1)

typedef enum {
    PASSPORT_TEXT_OK, PASSPORT_TEXT_INVALID, PASSPORT_TEXT_UNSUPPORTED,
    PASSPORT_TEXT_MISSING_GLYPH, PASSPORT_TEXT_TOO_LARGE,
} passport_text_result_t;
/* Must consult the ACTUAL selected font, without substitution. Layout assumes
 * a fixed cell font: printable ASCII=1 cell, supported CJK/fullwidth=2 cells.
 * Proportional fonts need a different pixel layout. Not a remote capability. */
typedef bool (*passport_text_glyph_fn)(void *context, uint32_t codepoint);
typedef struct {
    char text[PASSPORT_TEXT_BUFFER_MAX];
    size_t offsets[PASSPORT_TEXT_PAGES_MAX];
    size_t used, page_count;
    uint32_t blocked_codepoint;
    passport_text_result_t result;
} passport_text_t;
/* Serialized local renderer helper, NOT a request parser/consent proof.
 * Input must be stable and independent of output during this call. Copies all
 * pages; failure clears ALL prior pages. No truncation/replacement on missing
 * glyphs. Place the ~9KiB object off a small task stack. Page text is plain,
 * never LVGL recolor/markup; disable markup and auto-wrap, use matching cells.
 * ASCII + LF, CJK punctuation (excluding combining marks), Ext A/unified
 * ideographs, fullwidth ASCII are supported. Other scripts/emoji fail closed.
 */
passport_text_result_t passport_text_open(passport_text_t *text,
    const uint8_t *input, size_t length, size_t columns, size_t rows,
    passport_text_glyph_fn has_glyph, void *context);
/* Copies a complete NUL-terminated page or returns false with output empty.
 * An empty trailing page after explicit newline is meaningful and preserved. */
bool passport_text_page(const passport_text_t *text, size_t page,
    char *output, size_t capacity);
