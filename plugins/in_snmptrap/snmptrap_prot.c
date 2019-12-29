/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <string.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_time.h>

#include "syslog.h"
#include "syslog_conn.h"

static inline void consume_bytes(char *buf, int bytes, int length)
{
    memmove(buf, buf + bytes, length - bytes);
}

static inline int pack_line(struct flb_snmptrap *ctx,
                            struct flb_time *time, char *data, size_t data_size)
{
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;

    /* Initialize local msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_pack_array(&mp_pck, 2);
    flb_time_append_to_msgpack(time, &mp_pck, 0);
    msgpack_sbuffer_write(&mp_sbuf, data, data_size);

    flb_input_chunk_append_raw(ctx->i_ins, NULL, 0, mp_sbuf.data, mp_sbuf.size);
    msgpack_sbuffer_destroy(&mp_sbuf);

    return 0;
}

int snmptrap_prot_process(struct snmptrap_conn *conn)
{
    int len;
    int ret;
    char *p;
    char *eof;
    char *end;
    void *out_buf;
    size_t out_size;
    struct flb_time out_time;
    struct flb_snmptrap *ctx = conn->ctx;
    
    eof = conn->buf_data;
    end = conn->buf_data + conn->buf_len;

    /* Always parse while some remaining bytes exists */
    while (eof < end) {
        /* Lookup the ending byte */ 
        eof = p = conn->buf_data + conn->buf_parsed;
        while (*eof != '\n' && *eof != '\0' && eof < end) {
            eof++;
        }

        /* Incomplete message */
        if (eof == end || (*eof != '\n' && *eof != '\0')) {
            break;
        }

        /* No data ? */
        len = (eof - p);
        if (len == 0) {
            consume_bytes(conn->buf_data, 1, conn->buf_len);
            conn->buf_len--;
            conn->buf_parsed = 0;
            conn->buf_data[conn->buf_len] = '\0';
            end = conn->buf_data + conn->buf_len;

            if (conn->buf_len == 0) {
                break;
            }

            continue;
        }

        /* here parse SNMPTRAP PDU using flb_parser_do)

        /* Process the string */
        ret = flb_parser_do(ctx->parser, p, len,
                            &out_buf, &out_size, &out_time);
        if (ret >= 0) {
            pack_line(ctx, &out_time, out_buf, out_size);
            flb_free(out_buf);
        }
        else {
            flb_warn("[in_syslog] error parsing log message");
        }

        conn->buf_parsed += len + 1;
        end = conn->buf_data + conn->buf_len;
        eof = conn->buf_data + conn->buf_parsed;
    }

    if (conn->buf_parsed > 0) {
        consume_bytes(conn->buf_data, conn->buf_parsed, conn->buf_len);
        conn->buf_len -= conn->buf_parsed;
        conn->buf_parsed = 0;
        conn->buf_data[conn->buf_len] = '\0';
    }

    return 0;
}

int snmptrap_prot_process_udp(char *buf, size_t size, struct flb_snmptrap *ctx)
{
    int ret;
    void *out_buf;
    size_t out_size;
    struct flb_time out_time = {0};

    ret = flb_parser_do(ctx->parser, buf, size,
                        &out_buf, &out_size, &out_time);
    if (ret >= 0) {
        if (flb_time_to_double(&out_time) == 0) {
            flb_time_get(&out_time);
        }
        pack_line(ctx, &out_time, out_buf, out_size);
        flb_free(out_buf);
    }
    else {
        flb_warn("[in_snmptrap] error parsing log message");
        return -1;
    }

    return 0;
}

