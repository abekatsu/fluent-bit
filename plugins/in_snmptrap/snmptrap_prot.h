/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef FLB_IN_SNMPTRAP_PROT_H
#define FLB_IN_SNMPTRAP_PROT_H

#include <fluent-bit/flb_info.h>

#include "snmptrap.h"

int snmptrap_prot_process(struct snmptrap_conn *conn);
int snmptrap_prot_process_udp(char *buf, size_t size, struct flb_snmptrap *ctx);

#endif

