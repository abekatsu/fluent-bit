/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef FLB_IN_SNMPTRAP_SERVER_H
#define FLB_IN_SNMPTRAP_SERVER_H

#include "snmptrap.h"

int snmptrap_server_create(struct flb_snmptrap *ctx);
int snmptrap_server_destroy(struct flb_snmptrap *ctx);

#endif
