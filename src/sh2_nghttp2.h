#pragma once

#include "shift_h2_internal.h"

sh2_result_t sh2_nghttp2_init_callbacks(sh2_context_t *ctx);
sh2_result_t sh2_nghttp2_session_create(sh2_context_t *ctx, uint32_t conn_idx);
void         sh2_nghttp2_session_destroy(sh2_context_t *ctx, uint32_t conn_idx);
sh2_result_t sh2_drive_send(sh2_context_t *ctx, uint32_t conn_idx);
void         sh2_conn_close(sh2_context_t *ctx, uint32_t conn_idx);

nghttp2_ssize on_data_source_read(
    nghttp2_session *session, int32_t stream_id,
    uint8_t *buf, size_t length, uint32_t *data_flags,
    nghttp2_data_source *source, void *user_data);
