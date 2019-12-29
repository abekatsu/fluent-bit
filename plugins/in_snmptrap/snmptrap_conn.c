/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_network.h>

#include "snmptrap.h"
#include "snmptrap_conf.h"
#include "snmptrap_conn.h"
#include "snmptrap_prot.h"

int snmptrap_conn_event(void *data)
{
    int ret;
    int bytes;
    int available;
    int size;
    char *tmp;
    struct mk_event *event;
    struct snmptrap_conn *conn = data;
    struct flb_snmptrap *ctx = conn->ctx;

    event = &conn->event;

    if (event->mask & MK_EVENT_READ) {
        available = (conn->buf_size - conn->buf_len) - 1;
        if (available < 1) {
            if (conn->buf_size + ctx->buffer_chunk_size > ctx->buffer_max_size) {
                flb_debug("[in_snnmptrap] fd=%i incoming data exceed limit (%i bytes)",
                          event->fd, (ctx->buffer_max_size));
                snmptrap_conn_del(conn);
                return -1;
            }

            size = conn->buf_size + ctx->buffer_chunk_size;
            tmp = flb_realloc(conn->buf_data, size);
            if (!tmp) {
                flb_errno();
                return -1;
            }
            flb_trace("[in_snmptrap] fd=%i buffer realloc %i -> %i",
                      event->fd, conn->buf_size, size);

            conn->buf_data = tmp;
            conn->buf_size = size;
            available = (conn->buf_size - conn->buf_len) - 1;
        }

        bytes = read(conn->fd,
                     conn->buf_data + conn->buf_len, available);
        if (bytes > 0) {
            flb_trace("[in_snmptrap] read()=%i pre_len=%i now_len=%i",
                      bytes, conn->buf_len, conn->buf_len + bytes);
            conn->buf_len += bytes;
            conn->buf_data[conn->buf_len] = '\0';
            ret = snmptrap_prot_process(conn);
            if (ret == -1) {
                return -1;
            }
            return bytes;
        }
        else {
            flb_trace("[in_snmptrap] fd=%i closed connection", event->fd);
            snmptrap_conn_del(conn);
            return -1;
        }
    }

    if (event->mask & MK_EVENT_CLOSE) {
        flb_trace("[in_snmptrap] fd=%i hangup", event->fd);
        snmptrap_conn_del(conn);
        return -1;
    }
    return 0;
}

struct snmptarp_conn *snmptrap_conn_add(int fd, struct flb_snmptrap *ctx)
{
    int ret;
    struct snmptrap_conn *conn;
    struct mk_event *event;

    conn = flb_malloc(sizeof(struct snmptrap_conn));
    if (!conn) {
        return NULL;
    }

    /* Set data for the event-loop */
    event = &conn->event;
    MK_EVENT_NEW(event);
    event->fd           = fd;
    event->type         = FLB_ENGINE_EV_CUSTOM;
    event->handler      = syslog_conn_event;

    /* Connection info */
    conn->fd      = fd;
    conn->ctx     = ctx;
    conn->buf_len = 0;
    conn->buf_parsed = 0;
    conn->in      = ctx->i_ins;

    /* Allocate read buffer */
    conn->buf_data = flb_malloc(ctx->buffer_chunk_size);
    if (!conn->buf_data) {
        flb_errno();
        close(fd);
        flb_free(conn);
        return NULL;
    }
    conn->buf_size = ctx->buffer_chunk_size;

    /* Register instance into the event loop */
    ret = mk_event_add(ctx->evl, fd, FLB_ENGINE_EV_CUSTOM, MK_EVENT_READ, conn);
    if (ret == -1) {
        flb_error("[in_fw] could not register new connection");
        close(fd);
        flb_free(conn->buf_data);
        flb_free(conn);
        return NULL;
    }

    mk_list_add(&conn->_head, &ctx->connections);

    return conn;
}

int snmptrap_conn_del(struct snmptrap_conn *conn)
{
    /* Unregister the file descriptior from the event-loop */
    mk_event_del(conn->ctx->evl, &conn->event);

    /* Release resources */
    mk_list_del(&conn->_head);
    close(conn->fd);
    flb_free(conn->buf_data);
    flb_free(conn);

    return 0;
}

int snmptrap_conn_exit(struct snmptrap_syslog *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct snmptrap_conn *conn;

    mk_list_foreach_safe(head, tmp, &ctx->connections) {
        conn = mk_list_entry(head, struct snmptrap_conn, _head);
        snmptrap_conn_del(conn);
    }

    return 0;
}

