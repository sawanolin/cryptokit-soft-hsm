/*
 * Copyright (C) 2025 SDFX Project
 * SDFX is licensed under Mulan PSL v2.
 */

/**
 * @file audit_db.c
 * @brief SQLite-backed audit logging for external SDF calls.
 *
 * The daemon shares the web management database
 * (SDFX_DATA_DIR/web/manager.db) with the Python web backend.  Every SDF
 * call received from any client is written as an INFO-level "sdf" audit row,
 * so the audit administrator can see external SDK activity in both the web
 * page and the exported TXT file.
 */

#include <pthread.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "audit_db.h"
#include "protocol.h"

static pthread_mutex_t g_audit_mutex = PTHREAD_MUTEX_INITIALIZER;
static char g_audit_db_path[1024] = {0};

static const char *audit_db_path(void)
{
    if (g_audit_db_path[0] != '\0') {
        return g_audit_db_path;
    }
    const char *root = getenv("SDFX_DATA_DIR");
    const char *base = (root != NULL && root[0] != '\0') ? root : "/var/lib/sdfx";
    snprintf(g_audit_db_path, sizeof(g_audit_db_path), "%s/web/manager.db", base);
    return g_audit_db_path;
}

/* Read-only admin queries are not SDF operations; do not flood the audit log. */
static int audit_db_skip_command(uint32_t command)
{
    switch (command) {
        case SDFX_CMD_ADMIN_STATUS:
        case SDFX_CMD_ADMIN_KEY_LIST:
        case SDFX_CMD_ADMIN_RSA_KEY_LIST:
        case SDFX_CMD_ADMIN_KEK_LIST:
        case SDFX_CMD_ADMIN_BACKUP_LIST:
        case SDFX_CMD_ADMIN_SESSION_LIST:
            return 1;
        default:
            return 0;
    }
}

/* "tcp_client_1.2.3.4:5678_fd_5" -> "1.2.3.4" */
static void audit_remote_addr(const char *client_info, char *out, size_t out_size)
{
    out[0] = '\0';
    if (client_info == NULL || out_size == 0) {
        return;
    }
    const char *prefix = "tcp_client_";
    const char *p = strstr(client_info, prefix);
    if (p != NULL) {
        p += strlen(prefix);
        const char *end = strchr(p, ':');
        size_t n = end != NULL ? (size_t)(end - p) : strlen(p);
        if (n >= out_size) {
            n = out_size - 1;
        }
        memcpy(out, p, n);
        out[n] = '\0';
        return;
    }
    snprintf(out, out_size, "%s", client_info);
}

int audit_db_log_sdf_call(uint32_t command, const char *client_info,
                          const char *action, int ok, const char *details)
{
    if (action == NULL || audit_db_skip_command(command)) {
        return 0;
    }

    pthread_mutex_lock(&g_audit_mutex);

    sqlite3 *db = NULL;
    int rc = sqlite3_open_v2(
        audit_db_path(), &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
    if (rc != SQLITE_OK) {
        if (db != NULL) {
            sqlite3_close(db);
        }
        pthread_mutex_unlock(&g_audit_mutex);
        return -1;
    }
    sqlite3_busy_timeout(db, 5000);

    /* Keep the schema in sync with web/backend/app/main.py. */
    const char *create_table =
        "CREATE TABLE IF NOT EXISTS audit ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " occurred_at INTEGER NOT NULL,"
        " username TEXT NOT NULL,"
        " action TEXT NOT NULL,"
        " target TEXT NOT NULL,"
        " result TEXT NOT NULL,"
        " remote_addr TEXT NOT NULL,"
        " level TEXT NOT NULL DEFAULT 'INFO',"
        " category TEXT NOT NULL DEFAULT 'management',"
        " request_id TEXT NOT NULL DEFAULT '',"
        " method TEXT NOT NULL DEFAULT '',"
        " path TEXT NOT NULL DEFAULT '',"
        " details TEXT NOT NULL DEFAULT '',"
        " user_agent TEXT NOT NULL DEFAULT ''"
        ")";
    sqlite3_exec(db, create_table, NULL, NULL, NULL);

    const char *insert_sql =
        "INSERT INTO audit("
        " occurred_at, username, action, target, result, remote_addr,"
        " level, category, request_id, method, path, details, user_agent"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, insert_sql, -1, &stmt, NULL) == SQLITE_OK) {
        char remote[128];
        audit_remote_addr(client_info, remote, sizeof(remote));
        sqlite3_bind_int64(stmt, 1, (sqlite3_int64)time(NULL));
        /* 没有 web 登录用户，用调用来源 IP 作为用户名，便于追溯。 */
        sqlite3_bind_text(stmt, 2, remote, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, action, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 4, "sdf", -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 5, ok ? "success" : "failure", -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 6, remote, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 7, "INFO", -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 8, "sdf", -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 9, "", -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 10, "TCP", -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 11, "18081", -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 12, details != NULL ? details : "", -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 13, "", -1, SQLITE_STATIC);
        sqlite3_step(stmt);
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    pthread_mutex_unlock(&g_audit_mutex);
    return 0;
}
