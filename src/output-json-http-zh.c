
/*
 * WARN, add on 20250326
 * For EveHttpLogJSON() in output-json-http.c
 * not compile this file, to use this file by include in output-json-http.c
 */

 #include <stdint.h>
 #include <string.h>
 #include "rust-bindings.h"
 #include "app-layer-htp.h"


// WARN, copy from util-print.c PrintStringsToBuffer
// Also print zh, chinese words.
static void PrintStringsToBufferZh(uint8_t *dst_buf, uint32_t *dst_buf_offset_ptr, uint32_t dst_buf_size,
    const uint8_t *src_buf, const uint32_t src_buf_len)
{
    uint32_t ch = 0;
    for (ch = 0; ch < src_buf_len && *dst_buf_offset_ptr < dst_buf_size;
        ch++, (*dst_buf_offset_ptr)++) {
        // if (isprint((uint8_t)src_buf[ch]) || src_buf[ch] == '\n' || src_buf[ch] == '\r') {
            dst_buf[*dst_buf_offset_ptr] = src_buf[ch];
        // } else {
        //     dst_buf[*dst_buf_offset_ptr] = '.';
        // }
    }
    dst_buf[dst_buf_size - 1] = 0;

    return;
}

static void BodyPrintableBufferZh(JsonBuilder *js, HtpBody *body, const char *key)
{
    if (body->sb != NULL && body->sb->region.buf != NULL) {
        uint32_t offset = 0;
        const uint8_t *body_data;
        uint32_t body_data_len;
        uint64_t body_offset;

        if (StreamingBufferGetData(body->sb, &body_data,
                                   &body_data_len, &body_offset) == 0) {
            return;
        }

        uint8_t printable_buf[body_data_len + 1];
        PrintStringsToBufferZh(printable_buf, &offset,
                             sizeof(printable_buf),
                             body_data, body_data_len);
        if (offset > 0) {
            jb_set_string(js, key, (char *)printable_buf);
        }
    }
}
