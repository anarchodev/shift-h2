#pragma once

#include "shift_h2_internal.h"

sh2_result_t sh2_nghttp2_client_init_callbacks(sh2_context_t *ctx);
sh2_result_t sh2_nghttp2_client_session_create(sh2_context_t *ctx,
                                                shift_entity_t conn_entity);
