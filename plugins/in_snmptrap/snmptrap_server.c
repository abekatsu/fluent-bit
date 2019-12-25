/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_network.h>
np
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "snmptrap.h"

static int snmptrap_server_net_create(struct flb_snmptrap *ctx)
{
    if (ctx->mode == FLB_SNMPTRAPG_TCP) {
        ctx->server_fd = flb_net_server(ctx->port, ctx->listen);
    }
    else {
        ctx->server_fd = flb_net_server_udp(ctx->port, ctx->listen);
    }

    if (ctx->server_fd > 0) {
        flb_info("[in_snmptrap] %s server binding %s:%s",
                 ((ctx->mode == FLB_SNMPTRAP_TCP) ? "TCP" : "UDP"),
                 ctx->listen, ctx->port);
    }
    else {
        flb_error("[in_snmptrap] could not bind address %s:%s. Aborting",
                  ctx->listen, ctx->port);
        return -1;
    }

    flb_net_socket_nonblocking(ctx->server_fd);
    return 0;
}

int snmptrap_server_create(struct flb_snmptrap *ctx)
{
    int ret;

    if (ctx->mode == FLB_SNMPTRAP_UDP) {
        /* create UDP buffer */
        ctx->buffer_data = flb_calloc(1, ctx->buffer_chunk_size);
        if (!ctx->buffer_data) {
            flb_errno();
            return -1;
        }
        ctx->buffer_size = ctx->buffer_chunk_size;
        flb_info("[in_snmptrap] UDP buffer size set to %lu bytes",
                 ctx->buffer_size);

    }

    ret = snmptrap_server_net_create(ctx);
    if (ret != 0) {
        return -1;
    }

    return 0;
}

int snmptrap_server_destroy(struct flb_snmptrap *ctx)
{
    if (ctx->mode == FLB_SNMPTRAP_UDP || ctx->mode == FLB_SNMPTRAP_TCP) {
        flb_free(ctx->listen);
        flb_free(ctx->port);
    }
    else {
    }

    close(ctx->server_fd);

    return 0;
}
