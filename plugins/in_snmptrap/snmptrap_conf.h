/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef FLB_IN_SNMPTRAP_CONF_H
#define FLB_IN_SNMPTRAP_CONF_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>

#include "snmptrap.h"

struct flb_snmptrap *snmptrap_conf_create(struct flb_input_instance *i_ins,
                                          struct flb_config *config);
int snmptrap_conf_destroy(struct flb_snmptrap *ctx);

#endif
