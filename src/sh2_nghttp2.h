#pragma once

#include "shift_h2_internal.h"

/* --------------------------------------------------------------------------
 * Shared stream helpers (used by both server and client nghttp2 paths)
 * -------------------------------------------------------------------------- */

sh2_stream_t       *sh2_stream_alloc(shift_entity_t user_conn_entity);
void                sh2_stream_free(sh2_stream_t *s);
bool                sh2_stream_hdr_append(sh2_stream_t *s,
                                          const uint8_t *name,  size_t namelen,
                                          const uint8_t *value, size_t valuelen);
sh2_header_field_t *sh2_stream_hdr_finalize(sh2_stream_t *s, uint32_t *out_count);
bool                sh2_stream_body_append(sh2_stream_t *s,
                                           const uint8_t *data, size_t len);

/* --------------------------------------------------------------------------
 * Server session management
 * -------------------------------------------------------------------------- */

sh2_result_t sh2_nghttp2_init_callbacks(sh2_context_t *ctx);
sh2_result_t sh2_nghttp2_session_create(sh2_context_t *ctx,
                                         shift_entity_t user_conn_entity);
void         sh2_nghttp2_session_destroy(sh2_context_t *ctx,
                                          shift_entity_t user_conn_entity);
sh2_result_t sh2_drive_send(sh2_context_t *ctx,
                             shift_entity_t user_conn_entity);
void         sh2_conn_close(sh2_context_t *ctx,
                             shift_entity_t user_conn_entity);

nghttp2_ssize on_data_source_read(
    nghttp2_session *session, int32_t stream_id,
    uint8_t *buf, size_t length, uint32_t *data_flags,
    nghttp2_data_source *source, void *user_data);

int sh2_on_data_chunk_recv(nghttp2_session *session, uint8_t flags,
                           int32_t stream_id, const uint8_t *data,
                           size_t len, void *user_data);

void sh2_stream_finish(sh2_context_t *ctx, sh2_stream_t *stream,
                       uint32_t error_code, shift_collection_id_t dest);
