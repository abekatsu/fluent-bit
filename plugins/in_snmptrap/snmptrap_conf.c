/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_utils.h>

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
        else if (strcasecmp(tmp, "tcp") == 0) {
            ctx->mode = FLB_SNMPTRAP_TCP;
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

    /* Buffer Chunk Size */
    tmp = flb_input_get_property("buffer_chunk_size", i_ins);
    if (!tmp) {
        ctx->buffer_chunk_size = FLB_SYSLOG_CHUNK; /* 32KB */
    }
    else {
        ctx->buffer_chunk_size = flb_utils_size_to_bytes(tmp);
    }

    /* Buffer Max Size */
    tmp = flb_input_get_property("buffer_max_size", i_ins);
    if (!tmp) {
        ctx->buffer_max_size = ctx->buffer_chunk_size;
    }
    else {
        ctx->buffer_max_size  = flb_utils_size_to_bytes(tmp);
    }


    /* TODO: parser */
    tmp = flb_input_get_property("parser", i_ins);
    if (tmp) {
        ctx->parser = flb_parser_get(tmp, config);
    }
    else {
        ctx->parser = flb_parser_get("syslog-rfc3164-local", config); // TODO; what's syslog-rfc3164-local
    }

    if (!ctx->parser) {
        flb_error("[in_syslog] parser not set");
        syslog_conf_destroy(ctx);
        return NULL;
    }

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

