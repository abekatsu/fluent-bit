/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "snmptrap.h"
#include "snmptrap_server.h"
#include "snmptrap_conf.h"

struct flb_snmptrap *snmptrap_conf_create(struct flb_input_instance *i_ins,
                                          struct flb_config *config)
{
    const char *tmp;
    char port[16];
    struct flb_snmptrap *ctx;

    ctx = flb_calloc(1, sizeof(struct flb_syslog));
    if (!ctx) {
        flb_errno();
        return NULL;
    }

    ctx->evl = config->evl;
    ctx->i_ins = i_ins;
    ctx->buffer_data = NULL;
    mk_list_init(&ctx->connections);

    tmp = flb_input_get_property("mode", i_ins);
    if (tmp) {
        if (strcasecmp(tmp, "udp") == 0) {
            ctx->mode = FLB_SNMPTRAP_UDP;
        }
        else {
            flb_error("[in_syslog] Unknown snmptrap mode %s", tmp);
            flb_free(ctx);
            return NULL;
        }
    }
    else {
        /* default is UDP port */
        ctx->mode = FLB_SNMPTRAP_UDP;
    }

    /* Listen interface */
    if (!i_ins->host.listen) {
        tmp = flb_input_get_property("listen", i_ins);
        if (tmp) {
            ctx->listen = flb_strdup(tmp);
        }
        else {
            ctx->listen = flb_strdup("0.0.0.0");
        }
    }
    else {
        ctx->listen = flb_strdup(i_ins->host.listen);
    }

    /* port */
    if (i_ins->host.port == 0) {
        ctx->port = flb_strdup("162");
    }
    else {
        snprintf(port, sizeof(port) - 1, "%d", i_ins->host.port);
        ctx->port = flb_strdup(port);
    }

    /* TODO: parser */

    return ctx;
}

int snmptrap_conf_destroy(struct flb_syslog *ctx)
{
    if (ctx->buffer_data) {
        flb_free(ctx->buffer_data);
        ctx->buffer_data = NULL;
    }
    snmptrap_server_destroy(ctx);
    flb_free(ctx);

    return 0;
}

