/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <msgpack.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_utils.h>

#include "snmptrap.h"
#include "snmptrap_conf.h"
#include "snmptrap_server.h"
#include "snmptrap_conn.h"
#include "snmptrap_prot.h"

/* cb_collect callback */
static int in_snmptrap_collect_tcp(struct flb_input_instance *i_ins,
                                   struct flb_config *config, void *in_context)
{
    int fd;
    struct flb_snmptrap *ctx = in_context;
    struct snmptrap_conn *conn;
    (void) i_ins;

    /* Accept the new connection */
    fd = flb_net_accept(ctx->server_fd);
    if (fd == -1) {
        flb_error("[in_snmptrap] could not accept new connection");
        return -1;
    }

    flb_trace("[in_snmptrap] new Unix connection arrived FD=%i", fd);
    conn = snmptrap_conn_add(fd, ctx);
    if (!conn) {
        return -1;
    }

    return 0;
}


/*
 * Collect a datagram
 */
static int in_snmptrap_collect_udp(struct flb_input_instance *i_ins,
                                   struct flb_config *config,
                                   void *in_context)
{
    int fd;
    struct flb_snmptrap *ctx = in_context;
    (void) i_ins;

    bytes = recvfrom(ctx->server_fd,
                     ctx->buffer_data, ctx->buffer_size - 1, 0,
                     NULL, NULL);
    if (bytes > 0) {
        ctx->buffer_len = bytes;
        snmptrap_prot_process_udp(&ctx->buffer_data, ctx->buffer_len, ctx);
    }
    else {
        flb_errno();
    }
    ctx->buffer_len = 0;

    return 0;
}


/* Initialize plugin */
static int in_snmtrap_init(struct flb_input_instance *in,
                           struct flb_config *config,
                           void *data)
{
    int ret;
    struct flb_snmptrap *ctx;

    /* Allocate space for the configuration */
    ctx = snmptrap_conf_create(in, config);
    if (!ctx) {
        flb_error("[in_snmptrap] could not initialize plugin");
        return -1;
    }

    /* Create Unix Socket */
    ret = syslog_server_create(ctx);
    if (ret == -1) {
        syslog_conf_destroy(ctx);
        return -1;
    }

    /* Set context */
    flb_input_set_context(in, ctx);

    /* Collect events for every opened connection to our socket */
    if (ctx->mode == FLB_SNMPTRAP_TCP) {
        ret = flb_input_set_collector_socket(in,
                                             in_snmptrap_collect_tcp,
                                             ctx->server_fd,
                                             config);
    }
    else {
        ret = flb_input_set_collector_socket(in,
                                             in_snmptrap_collect_udp,
                                             ctx->server_fd,
                                             config);
    }

    if (ret == -1) {
        flb_error("[in_snmptrap] Could not set collector");
        snmptrap_conf_destroy(ctx);
        return -1;
    }

    return 0;
}

/* Destory plugin */
static int in_snmptrap_exit(void *data, struct flb_config *config)
{
    struct flb_snmptrap *ctx = data;
    (void) config;

    snmptrap_conn_exit(ctx);
    snmptrap_conf_destroy(ctx);

    return 0;
}


struct flb_input_plugin in_snmptrap_plugin = {
    .name         = "smptrap",
    .description  = "SNMP Trap Input Plugin",
    .cb_init      = in_snmptrap_init,
    .cb_pre_run   = NULL,
    .cb_collect   = NULL,
    .cb_flush_buf = NULL,
    .cb_exit      = in_snmptrap_exit,
    .flags        = FLB_INPUT_NET
};

