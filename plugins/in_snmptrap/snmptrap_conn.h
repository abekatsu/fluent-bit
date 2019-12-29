/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef FLB_IN_SNMPTRAP_CONN_H
#define FLB_IN_SNMPTRAP_CONN_H

#include <fluent-bit/flb_config.h>

#include "snmptrap.h"

/* Respresents a connection */
struct snmptrap_conn {
    struct mk_event event;           /* Built-in event data for mk_events */
    int fd;                          /* Socket file descriptor            */
    int status;                      /* Connection status                 */

    /* Buffer */
    char *buf_data;                  /* Buffer data                       */
    size_t buf_size;                 /* Buffer size                       */
    size_t buf_len;                  /* Buffer length                     */
    size_t buf_parsed;               /* Parsed buffer (offset)            */
    struct flb_input_instance *in;   /* Parent plugin instance            */
    struct flb_snmptrap *ctx;        /* Plugin configuration context      */

    struct mk_list _head;
};

int snmptrap_conn_event(void *data);
struct snmptarp_conn *snmptrap_conn_add(int fd, struct flb_snmptrap *ctx);
int snmptrap_conn_del(struct snmptrap_conn *conn);
int snmptrap_conn_exit(struct snmptrap_syslog *ctx);

#endif
