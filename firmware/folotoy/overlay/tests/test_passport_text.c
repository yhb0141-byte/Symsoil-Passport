#include "passport_text.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

/* Synthetic fixed-cell font coverage only, not a claim about the BSP font. */
static bool glyph(void *context, uint32_t cp)
{
    return !context || cp != *(uint32_t *)context;
}
static passport_text_result_t open_text(passport_text_t *t, const char *in, size_t columns, size_t rows)
{
    return passport_text_open(t, (const uint8_t *)in, strlen(in), columns, rows, glyph, NULL);
}
static void page_is(passport_text_t *t, size_t page, const char *expected)
{
    char result[PASSPORT_TEXT_BUFFER_MAX];
    assert(passport_text_page(t, page, result, sizeof(result)));
    assert(strcmp(result, expected) == 0);
}
static void test_chinese_pages(void)
{
    passport_text_t t;
    char source[] = "扣除20积分\n兑换种子。";
    assert(open_text(&t, source, 6, 2) == PASSPORT_TEXT_OK);
    assert(t.page_count == 2);
    page_is(&t, 0, "扣除20\n积分");
    page_is(&t, 1, "兑换种\n子。");
    memset(source, 'X', sizeof(source) - 1);
    page_is(&t, 0, "扣除20\n积分");
    /* Explicit newline after row 2 starts a new page, not a hidden blank row. */
    assert(open_text(&t, "一二三\n四五六\n", 6, 2) == PASSPORT_TEXT_OK);
    assert(t.page_count == 2);
    page_is(&t, 0, "一二三\n四五六");
    page_is(&t, 1, "");
    assert(open_text(&t, "A中B文C", 3, 1) == PASSPORT_TEXT_OK);
    assert(t.page_count == 3);
    page_is(&t, 0, "A中"); page_is(&t, 1, "B文"); page_is(&t, 2, "C");
    page_is(&t, 0, "A中");
    char small[4] = "old";
    assert(!passport_text_page(&t, 0, small, sizeof(small)) && !small[0]);
    assert(!passport_text_page(&t, 3, small, sizeof(small)) && !small[0]);
    assert(open_text(&t, "#ff0000 扣除20积分#", 40, 2) == PASSPORT_TEXT_OK);
    page_is(&t, 0, "#ff0000 扣除20积分#"); /* plain text, never markup */
}
static void test_blocked_text_clears_pages(void)
{
    passport_text_t t;
    const char *invalid[] = {"\xc0\xaf", "\x80", "\xe4\xb8", "\xed\xa0\x80", "\xf4\x90\x80\x80", "\xe0\x80\x80"};
    for (size_t i = 0; i < sizeof(invalid)/sizeof(invalid[0]); ++i) {
        assert(open_text(&t, "已有内容", 20, 2) == PASSPORT_TEXT_OK);
        assert(open_text(&t, invalid[i], 20, 2) == PASSPORT_TEXT_INVALID);
        assert(!t.page_count && !t.used && !t.text[0]);
    }
    const char *blocked[] = {"\t", "\r", "\x7f", "\xc2\xa0", "\xe2\x80\xae", "\xe2\x80\x8b", "\xcc\x81", "\xf0\x9f\x98\x80", "\xe3\x80\xaa"};
    for (size_t i = 0; i < sizeof(blocked)/sizeof(blocked[0]); ++i) {
        assert(open_text(&t, blocked[i], 20, 2) == PASSPORT_TEXT_UNSUPPORTED);
        assert(!t.page_count && !t.used && !t.text[0] && t.blocked_codepoint);
    }
    const uint8_t nul[] = {'A',0,'B'};
    assert(passport_text_open(&t, nul, sizeof(nul), 20, 2, glyph, NULL) == PASSPORT_TEXT_UNSUPPORTED);
    uint32_t absent = 0x79ef; /* 积: detect even AFTER earlier pages were built */
    const char *in = "先读完这些字再领取积分";
    assert(passport_text_open(&t, (const uint8_t *)in, strlen(in), 2, 1, glyph, &absent) == PASSPORT_TEXT_MISSING_GLYPH);
    assert(t.blocked_codepoint == absent && !t.page_count && !t.text[0]);
    assert(open_text(&t, "恢复", 4, 1) == PASSPORT_TEXT_OK && !t.blocked_codepoint);
    page_is(&t, 0, "恢复");
}
static void test_bounds_and_exact_bytes(void)
{
    passport_text_t t;
    char input[PASSPORT_TEXT_INPUT_MAX + 2];
    memset(input, 'A', sizeof(input));
    assert(passport_text_open(&t, (uint8_t *)input, PASSPORT_TEXT_INPUT_MAX, 80, 40, glyph, NULL) == PASSPORT_TEXT_OK);
    size_t count = 0;
    for (size_t p = 0; p < t.page_count; ++p) {
        char page[PASSPORT_TEXT_BUFFER_MAX];
        assert(passport_text_page(&t, p, page, sizeof(page)));
        for (size_t i = 0; page[i]; ++i) {
            assert(page[i] == 'A' || page[i] == '\n');
            if (page[i] == 'A') ++count;
        }
    }
    assert(count == PASSPORT_TEXT_INPUT_MAX);
    assert(passport_text_open(&t, (uint8_t *)input, PASSPORT_TEXT_INPUT_MAX + 1, 80, 40, glyph, NULL) == PASSPORT_TEXT_TOO_LARGE);
    memset(input, '\n', sizeof(input));
    assert(passport_text_open(&t, (uint8_t *)input, 127, 2, 1, glyph, NULL) == PASSPORT_TEXT_OK && t.page_count == 128);
    assert(passport_text_open(&t, (uint8_t *)input, 128, 2, 1, glyph, NULL) == PASSPORT_TEXT_TOO_LARGE && !t.page_count);
    assert(open_text(&t, "", 20, 2) == PASSPORT_TEXT_INVALID);
    assert(open_text(&t, "A", 1, 2) == PASSPORT_TEXT_INVALID);
    assert(open_text(&t, "A", 81, 2) == PASSPORT_TEXT_INVALID);
    assert(open_text(&t, "A", 20, 0) == PASSPORT_TEXT_INVALID);
    assert(open_text(&t, "A", 20, 41) == PASSPORT_TEXT_INVALID);
    assert(passport_text_open(&t, (uint8_t *)"A", 1, 20, 2, NULL, NULL) == PASSPORT_TEXT_INVALID);
    /* Deterministic byte mutations exercise decoder boundaries under ASan. */
    uint32_t random = 1;
    for (size_t run = 0; run < 10000; ++run) {
        uint8_t bytes[32];
        for (size_t i = 0; i < sizeof(bytes); ++i) {
            random = random * 1664525u + 1013904223u;
            bytes[i] = (uint8_t)(random >> 24);
        }
        passport_text_result_t result = passport_text_open(&t, bytes, run % 32 + 1, 10, 3, glyph, NULL);
        if (result == PASSPORT_TEXT_OK) assert(t.page_count && t.used <= sizeof(t.text));
        else assert(!t.page_count && !t.used && !t.text[0]);
    }
}
int main(void)
{
    test_chinese_pages(); test_blocked_text_clears_pages(); test_bounds_and_exact_bytes();
    puts("Passport UTF-8 pagination and fail-closed glyph checks: PASS");
}
