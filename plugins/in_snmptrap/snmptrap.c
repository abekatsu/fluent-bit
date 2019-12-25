/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_input.h>

#include "snmptrap.h"
#include "snmptrap_conf.h"

/* cb_collect callback */


/*
 * Collect a datagram
 */
static int in_snmptrap_collect_udp(struct flb_input_instance *i_ins,
                                   struct flb_config *config,
                                   void *in_context)
{
    int fd;
    struct flb_syslog *ctx = in_context;
    struct syslog_conn *conn;
    (void) i_ins;

    /* Accept the new connection */
    fd = flb_net_accept(ctx->server_fd);
    if (fd == -1) {
        flb_error("[in_syslog] could not accept new connection");
        return -1;
    }

    flb_trace("[in_snmptrap] new Unix connection arrived FD=%i", fd);
    conn = syslog_conn_add(fd, ctx);
    if (!conn) {
        return -1;
    }

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

    ret = snmptrap_server_create(ctx);
    if (ret == -1) {
        snmptrap_conf_destroy(ctx);
        return -1;
    }

    /* Set context */
    flb_input_set_context(in, ctx);

    /* Collect events for every opened connection to our socket */
    if (ctx->mode == FLB_SNMPTRAP_TCP) {
        flb_error("[in_snmptrap] binding tcp port is not supported yet");
        snmptrap_conf_destroy(ctx);
        return -1;
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

