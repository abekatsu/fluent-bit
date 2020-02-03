/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <string.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_time.h>

#include <mbedtls/asn1.h>

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

static inline void print_mbedtls_asn1_bitstring(mbedtls_asn1_bitstring *bs)
{
    size_t i;
    for (i = 0; i < bs->len; i++) {
        print("%c", (char)*bs->p[i]);
    }
    printf("\n");
    return 0;
}

/*
 * SNMPTrap PDU
 *
 */

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

int snmptrap_prot_process_udp(unsinged char *buf, size_t size, struct flb_snmptrap *ctx)
{
    int ret;
    void *out_buf;
    int ret, version;
    size_t len;
    struct flb_time out_time = {0};
    // mbedtls_asn1_buf *buf;
    unsinged char **p;
    unsinged char *end;
    char *community = NULL;
    mbedtls_asn1_bitstring community = {0, 0, NULL};

    p = &buf;
    end = buf + size;
    /* Get main sequence tag */
    ret = mbedtls_asn1_get_tag(p, end, &len,
                               MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE );
    if (ret != 0) {
        flb_warn("[in_snmptrap] error - unexpcected trap/inform message");
        return -1;
    }
    printf("size: %lu, len: %l\n");
    if (*p + len != end) {
        flb_warn("[in_snmptrap] error - length mismatch");
        return -1;
    }

    /* Get SNMP version */
    ret = mbedtls_asn1_get_int(p, end, &version);

    if (version == SNMP_VERSION_1) {
    }
    else if (version == SNMP_VERSION_2c) {
        /* Get SNMP community */
        ret = mbedtls_asn1_get_tag(p, end, &len, MBEDTLS_ASN1_OCTET_STRING);
        if (ret != 0) {
            flb_warn("[in_snmptrap] error - unexpcected snnmp trap pdu format");
            return -1;
        }
        if (*p + len != end) {
            flb_warn("[in_snmptrap] error - length mismatch");
            return -1;
        }
        ret = mbedtls_asn1_get_bistring(p, end, &community);






    }
    else if (version == SNMP_VERSION_3) {
        /* TODO: implemented */
    }


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

