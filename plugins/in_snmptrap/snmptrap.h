/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef FLB_IN_SYSLOG_H
#define FLB_IN_SYSLOG_H

/* SNMPTrap modes. But TCP is not implemented yet. */
#define FLB_SNMPTRAP_UDP 0x1
#define FLB_SNMPTRAP_TCP 0x2

/* 32KB chunk size */
#define FLB_SYSLOG_CHUNK   32768

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>

struct flb_snmptrap {
    /* Listening mode: normap udp or normal tcp */
    int mode;

    /* Network mode */
    char *listen;
    char *port;

    /* UDP buffer, data length and buffer size */
    char *buffer_data;
    size_t buffer_len;
    size_t buffer_size;

    /* Buffers setup */
    size_t buffer_max_size;
    size_t buffer_chunk_size;

    /* Configuration */
    struct flb_parser *parser;

    /* List for connections and event loop */
    struct mk_list connections;
    struct mk_event_loop *evl;
    struct flb_input_instance *i_ins;
};

#endif
