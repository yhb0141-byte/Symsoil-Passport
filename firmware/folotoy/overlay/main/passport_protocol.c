#include "passport_protocol.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    char *output;
    size_t capacity;
    size_t length;
    passport_protocol_result_t result;
} writer_t;

static void put_byte(writer_t *writer, char byte)
{
    if (writer->result != PASSPORT_PROTOCOL_OK) return;
    if (writer->length + 1 >= writer->capacity) {
        writer->result = PASSPORT_PROTOCOL_BUFFER_TOO_SMALL;
        return;
    }
    writer->output[writer->length++] = byte;
    writer->output[writer->length] = '\0';
}

static void put_ascii(writer_t *writer, const char *text)
{
    while (*text && writer->result == PASSPORT_PROTOCOL_OK) {
        put_byte(writer, *text++);
    }
}

static size_t utf8_sequence_length(const unsigned char *text)
{
    const unsigned char lead = text[0];
    if (lead <= 0x7f) return 1;
    if (lead >= 0xc2 && lead <= 0xdf && text[1] >= 0x80 && text[1] <= 0xbf) return 2;
    if (lead == 0xe0 && text[1] >= 0xa0 && text[1] <= 0xbf &&
        text[2] >= 0x80 && text[2] <= 0xbf) return 3;
    if (((lead >= 0xe1 && lead <= 0xec) || (lead >= 0xee && lead <= 0xef)) &&
        text[1] >= 0x80 && text[1] <= 0xbf && text[2] >= 0x80 && text[2] <= 0xbf) return 3;
    if (lead == 0xed && text[1] >= 0x80 && text[1] <= 0x9f &&
        text[2] >= 0x80 && text[2] <= 0xbf) return 3;
    if (lead == 0xf0 && text[1] >= 0x90 && text[1] <= 0xbf &&
        text[2] >= 0x80 && text[2] <= 0xbf && text[3] >= 0x80 && text[3] <= 0xbf) return 4;
    if (lead >= 0xf1 && lead <= 0xf3 && text[1] >= 0x80 && text[1] <= 0xbf &&
        text[2] >= 0x80 && text[2] <= 0xbf && text[3] >= 0x80 && text[3] <= 0xbf) return 4;
    if (lead == 0xf4 && text[1] >= 0x80 && text[1] <= 0x8f &&
        text[2] >= 0x80 && text[2] <= 0xbf && text[3] >= 0x80 && text[3] <= 0xbf) return 4;
    return 0;
}

static void put_json_string(writer_t *writer, const char *text)
{
    static const char HEX[] = "0123456789abcdef";
    const unsigned char *cursor = (const unsigned char *)text;
    put_byte(writer, '"');
    while (*cursor && writer->result == PASSPORT_PROTOCOL_OK) {
        const unsigned char byte = *cursor;
        if (byte == '"' || byte == '\\') {
            put_byte(writer, '\\');
            put_byte(writer, (char)byte);
            cursor++;
        } else if (byte == '\b' || byte == '\f' || byte == '\n' || byte == '\r' || byte == '\t') {
            const char escaped = byte == '\b' ? 'b' : byte == '\f' ? 'f' :
                                 byte == '\n' ? 'n' : byte == '\r' ? 'r' : 't';
            put_byte(writer, '\\');
            put_byte(writer, escaped);
            cursor++;
        } else if (byte < 0x20) {
            put_ascii(writer, "\\u00");
            put_byte(writer, HEX[byte >> 4]);
            put_byte(writer, HEX[byte & 0x0f]);
            cursor++;
        } else if (byte < 0x80) {
            put_byte(writer, (char)byte);
            cursor++;
        } else {
            const size_t count = utf8_sequence_length(cursor);
            if (!count) {
                writer->result = PASSPORT_PROTOCOL_INVALID_UTF8;
                return;
            }
            for (size_t index = 0; index < count; index++) put_byte(writer, (char)cursor[index]);
            cursor += count;
        }
    }
    put_byte(writer, '"');
}

static bool fixed_chars(const char *text, size_t count, const char *allowed)
{
    if (!text || strlen(text) != count) return false;
    for (size_t index = 0; index < count; index++) {
        if (!strchr(allowed, text[index])) return false;
    }
    return true;
}

static void put_uint(writer_t *writer, uint64_t value)
{
    char number[24];
    const int length = snprintf(number, sizeof(number), "%" PRIu64, value);
    if (length <= 0 || (size_t)length >= sizeof(number)) {
        writer->result = PASSPORT_PROTOCOL_INVALID_FIELD;
        return;
    }
    put_ascii(writer, number);
}

static void field_string(writer_t *writer, const char *name, const char *value, bool first)
{
    if (!first) put_byte(writer, ',');
    put_json_string(writer, name);
    put_byte(writer, ':');
    put_json_string(writer, value);
}

static void field_uint(writer_t *writer, const char *name, uint64_t value)
{
    put_byte(writer, ',');
    put_json_string(writer, name);
    put_byte(writer, ':');
    put_uint(writer, value);
}

passport_protocol_result_t passport_confirmation_frame_json(
    const passport_confirmation_frame_t *frame,
    char *output,
    size_t capacity,
    size_t *length)
{
    static const char BASE64URL[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
    static const char LOWER_HEX[] = "0123456789abcdef";
    if (length) *length = 0;
    if (!frame || !output || !capacity || !length || !frame->community_id ||
        !frame->decision || !frame->device_id || !frame->member_id || !frame->request_id) {
        return PASSPORT_PROTOCOL_INVALID_ARGUMENT;
    }
    output[0] = '\0';
    if (frame->counter > PASSPORT_JS_SAFE_INTEGER_MAX ||
        frame->expires_at > PASSPORT_JS_SAFE_INTEGER_MAX ||
        frame->request_version > PASSPORT_JS_SAFE_INTEGER_MAX ||
        !fixed_chars(frame->nonce, 32, BASE64URL) ||
        !fixed_chars(frame->request_digest, 64, LOWER_HEX)) {
        return PASSPORT_PROTOCOL_INVALID_FIELD;
    }

    writer_t writer = { .output = output, .capacity = capacity, .result = PASSPORT_PROTOCOL_OK };
    put_byte(&writer, '{');
    field_string(&writer, "communityId", frame->community_id, true);
    field_uint(&writer, "counter", frame->counter);
    field_string(&writer, "decision", frame->decision, false);
    field_string(&writer, "deviceId", frame->device_id, false);
    field_uint(&writer, "expiresAt", frame->expires_at);
    field_string(&writer, "memberId", frame->member_id, false);
    field_string(&writer, "nonce", frame->nonce, false);
    field_string(&writer, "protocol", "symsoil-passport/1", false);
    field_string(&writer, "requestDigest", frame->request_digest, false);
    field_string(&writer, "requestId", frame->request_id, false);
    field_uint(&writer, "requestVersion", frame->request_version);
    put_byte(&writer, '}');
    if (writer.result == PASSPORT_PROTOCOL_OK) *length = writer.length;
    return writer.result;
}

passport_protocol_result_t passport_delivery_result_frame_json(
    const passport_delivery_result_frame_t *frame,
    char *output,
    size_t capacity,
    size_t *length)
{
    uint8_t decoded_signature[64];
    size_t decoded_signature_length = 0;
    if (length) *length = 0;
    if (!frame || !output || !capacity || !length || !frame->community_id ||
        !frame->outcome || !frame->reply_signature || !frame->request_id ||
        !frame->result_id) {
        return PASSPORT_PROTOCOL_INVALID_ARGUMENT;
    }
    output[0] = '\0';
    if ((strcmp(frame->outcome, "accepted") != 0 && strcmp(frame->outcome, "rejected") != 0) ||
        !frame->community_id[0] || !frame->request_id[0] || !frame->result_id[0] ||
        !frame->transfer_id ||
        passport_base64url_decode(frame->reply_signature, decoded_signature,
            sizeof(decoded_signature), &decoded_signature_length) != PASSPORT_PROTOCOL_OK ||
        decoded_signature_length != sizeof(decoded_signature)) {
        return PASSPORT_PROTOCOL_INVALID_FIELD;
    }

    writer_t writer = { .output = output, .capacity = capacity, .result = PASSPORT_PROTOCOL_OK };
    put_byte(&writer, '{');
    field_string(&writer, "communityId", frame->community_id, true);
    field_string(&writer, "outcome", frame->outcome, false);
    field_string(&writer, "protocol", "symsoil-delivery-result/1", false);
    field_string(&writer, "replySignature", frame->reply_signature, false);
    field_string(&writer, "requestId", frame->request_id, false);
    field_string(&writer, "resultId", frame->result_id, false);
    field_uint(&writer, "transferId", frame->transfer_id);
    put_byte(&writer, '}');
    if (writer.result == PASSPORT_PROTOCOL_OK) *length = writer.length;
    return writer.result;
}

static int base64url_value(char byte)
{
    if (byte >= 'A' && byte <= 'Z') return byte - 'A';
    if (byte >= 'a' && byte <= 'z') return byte - 'a' + 26;
    if (byte >= '0' && byte <= '9') return byte - '0' + 52;
    if (byte == '-') return 62;
    if (byte == '_') return 63;
    return -1;
}

passport_protocol_result_t passport_base64url_decode(
    const char *text,
    uint8_t *output,
    size_t capacity,
    size_t *length)
{
    if (length) *length = 0;
    if (!text || !output || !length) return PASSPORT_PROTOCOL_INVALID_ARGUMENT;
    const size_t input_length = strlen(text);
    if (input_length % 4 == 1) return PASSPORT_PROTOCOL_INVALID_FIELD;

    uint32_t accumulator = 0;
    unsigned bits = 0;
    size_t written = 0;
    for (size_t index = 0; index < input_length; index++) {
        const int value = base64url_value(text[index]);
        if (value < 0) return PASSPORT_PROTOCOL_INVALID_FIELD;
        accumulator = (accumulator << 6) | (uint32_t)value;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (written >= capacity) return PASSPORT_PROTOCOL_BUFFER_TOO_SMALL;
            output[written++] = (uint8_t)((accumulator >> bits) & 0xff);
            accumulator &= bits ? ((UINT32_C(1) << bits) - 1) : 0;
        }
    }
    if (accumulator != 0) return PASSPORT_PROTOCOL_INVALID_FIELD;
    *length = written;
    return PASSPORT_PROTOCOL_OK;
}
