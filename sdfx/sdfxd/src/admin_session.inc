/* Read-only session inventory and explicit administrative termination. */

static int admin_session_list(daemon_context_t *ctx, BYTE *output,
                              uint32_t *output_len)
{
    if (ctx == NULL || output == NULL || output_len == NULL || *output_len < 3) {
        return SDR_INARGERR;
    }
    size_t capacity = *output_len;
    size_t used = 0;
    uint32_t count = 0;
    output[used++] = '[';

    pthread_mutex_lock(&ctx->sessions_mutex);
    for (session_info_t *session = ctx->sessions;
         session != NULL; session = session->next) {
        int n = snprintf((char *)output + used, capacity - used,
            "%s{\"session_id\":%u,\"device_id\":%u,"
            "\"created_at\":%lld,\"last_access\":%lld,\"active\":%s}",
            count == 0 ? "" : ",",
            session->session_id,
            session->device_handle,
            (long long)session->create_time,
            (long long)session->last_access,
            session->active ? "true" : "false");
        if (n < 0 || (size_t)n >= capacity - used) {
            pthread_mutex_unlock(&ctx->sessions_mutex);
            return SDR_NOBUFFER;
        }
        used += (size_t)n;
        ++count;
    }
    pthread_mutex_unlock(&ctx->sessions_mutex);

    if (used + 2 > capacity) {
        return SDR_NOBUFFER;
    }
    output[used++] = ']';
    output[used] = '\0';
    *output_len = (uint32_t)used;
    return SDR_OK;
}
