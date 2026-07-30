/* Structured SDFX logging with timestamp, source and execution context. */
#ifndef SDFX_LOG_H
#define SDFX_LOG_H

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#include <unistd.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define LOG_LEVEL_ERROR 1
#define LOG_LEVEL_WARN  2
#define LOG_LEVEL_INFO  3
#define LOG_LEVEL_DEBUG 4
#ifndef SDFX_LOG_LEVEL
#ifdef DEBUG
#define SDFX_LOG_LEVEL LOG_LEVEL_DEBUG
#else
#define SDFX_LOG_LEVEL LOG_LEVEL_INFO
#endif
#endif

static inline const char *sdfx_log_basename(const char *path)
{
    const char *base = path;
    if (path == NULL) return "unknown";
    for (const char *p = path; *p != '\0'; ++p)
        if (*p == '/' || *p == '\\') base = p + 1;
    return base;
}

static inline void sdfx_log_write(const char *level, const char *module,
                                  const char *function, const char *file,
                                  int line, const char *format, ...)
{
    time_t now = time(NULL); struct tm local_time;
#ifdef _WIN32
    localtime_s(&local_time, &now);
    unsigned long process_id = GetCurrentProcessId();
    unsigned long long thread_id = GetCurrentThreadId();
#else
    localtime_r(&now, &local_time);
    unsigned long process_id = (unsigned long)getpid();
    unsigned long long thread_id = (unsigned long long)(uintptr_t)pthread_self();
#endif
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &local_time);
#ifndef _WIN32
    flockfile(stdout);
#endif
    fprintf(stdout, "%s %-5s [%s] [pid=%lu tid=%llu] [%s] [%s:%d] ",
            timestamp, level, module ? module : "default", process_id,
            thread_id, function ? function : "unknown",
            sdfx_log_basename(file), line);
    va_list arguments; va_start(arguments, format); vfprintf(stdout, format, arguments); va_end(arguments);
    fputc('\n', stdout); fflush(stdout);
#ifndef _WIN32
    funlockfile(stdout);
#endif
}

#if SDFX_LOG_LEVEL >= LOG_LEVEL_ERROR
#define LOG_ERROR(fmt, ...) sdfx_log_write("ERROR", "default", __func__, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_MODULE_ERROR(module, fmt, ...) sdfx_log_write("ERROR", module, __func__, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#else
#define LOG_ERROR(fmt, ...)
#define LOG_MODULE_ERROR(module, fmt, ...)
#endif
#if SDFX_LOG_LEVEL >= LOG_LEVEL_WARN
#define LOG_WARN(fmt, ...) sdfx_log_write("WARN", "default", __func__, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_MODULE_WARN(module, fmt, ...) sdfx_log_write("WARN", module, __func__, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#else
#define LOG_WARN(fmt, ...)
#define LOG_MODULE_WARN(module, fmt, ...)
#endif
#if SDFX_LOG_LEVEL >= LOG_LEVEL_INFO
#define LOG_INFO(fmt, ...) sdfx_log_write("INFO", "default", __func__, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_MODULE_INFO(module, fmt, ...) sdfx_log_write("INFO", module, __func__, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#else
#define LOG_INFO(fmt, ...)
#define LOG_MODULE_INFO(module, fmt, ...)
#endif
#if SDFX_LOG_LEVEL >= LOG_LEVEL_DEBUG
#define LOG_DEBUG(fmt, ...) sdfx_log_write("DEBUG", "default", __func__, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_MODULE_DEBUG(module, fmt, ...) sdfx_log_write("DEBUG", module, __func__, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#else
#define LOG_DEBUG(fmt, ...)
#define LOG_MODULE_DEBUG(module, fmt, ...)
#endif

#ifdef __cplusplus
}
#endif
#endif


