/*
 * Copyright (C) 2025 SDFX Project
 * SDFX is licensed under Mulan PSL v2.
 */

/**
 * @file audit_db.h
 * @brief Write external SDF call records into the web management audit DB.
 */

#ifndef SDFX_AUDIT_DB_H
#define SDFX_AUDIT_DB_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Write one INFO-level "sdf" audit row for an external SDF call.
 *
 * Rows are inserted into SDFX_DATA_DIR/web/manager.db so the web audit page
 * and TXT export include calls made directly by external SDK clients over
 * TCP port 18081.  The row username is set to the calling client IP.
 *
 * @param command     Protocol command code (used to skip read-only admin calls)
 * @param client_info Transport client identity (e.g. "tcp_client_1.2.3.4:1234_fd_5")
 * @param action      SDF function name (e.g. "SDF_OpenDevice")
 * @param ok          1 on success, 0 on failure
 * @param details     Optional concise detail string (may be NULL)
 * @return 0 on success, nonzero when the audit database is unavailable
 */
int audit_db_log_sdf_call(uint32_t command, const char *client_info,
                          const char *action, int ok, const char *details);

#ifdef __cplusplus
}
#endif

#endif /* SDFX_AUDIT_DB_H */
