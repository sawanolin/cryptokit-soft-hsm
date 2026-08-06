/*
 * Copyright (C) 2025 SDFX Project
 * SDFX is licensed under Mulan PSL v2.
 */

/**
 * @file session_manager.c
 * @brief SDFX session manager implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "daemon_internal.h"

int session_manager_init(daemon_context_t *ctx)
{
    if (ctx == NULL) {
        return SDR_INARGERR;
    }
    
    ctx->sessions = NULL;
    ctx->next_session_id = 1;
    ctx->next_device_id = 1;
    ctx->active_sessions_count = 0;
    
    if (pthread_mutex_init(&ctx->sessions_mutex, NULL) != 0) {
        return SDR_NOBUFFER;
    }
    
    LOG_INFO("Session manager initialized");
    return SDR_OK;
}

void session_manager_cleanup(daemon_context_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    
    pthread_mutex_lock(&ctx->sessions_mutex);
    
    session_info_t *current = ctx->sessions;
    while (current != NULL) {
        session_info_t *next = current->next;
        
        /* Mark as inactive and decrease reference count */
        pthread_mutex_lock(&current->ref_mutex);
        current->active = false;
        current->ref_count--; /* Remove initial reference */
        int final_ref_count = current->ref_count;
        pthread_mutex_unlock(&current->ref_mutex);
        
        /* Free if no other references, otherwise let other threads handle cleanup */
        if (final_ref_count <= 0) {
            session_objects_cleanup(current);
            pthread_mutex_destroy(&current->object_mutex);
            pthread_mutex_destroy(&current->ref_mutex);
            free(current);
        } else {
            LOG_WARN("Session %u has %d remaining references during cleanup", 
                    current->session_id, final_ref_count);
        }
        
        current = next;
    }
    ctx->sessions = NULL;
    ctx->active_sessions_count = 0;
    
    pthread_mutex_unlock(&ctx->sessions_mutex);
    pthread_mutex_destroy(&ctx->sessions_mutex);
    
    LOG_INFO("Session manager cleanup completed");
}

static session_info_t* find_session_locked(daemon_context_t *ctx, uint32_t session_id)
{
    session_info_t *current = ctx->sessions;
    while (current != NULL) {
        if (current->session_id == session_id) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

uint32_t session_manager_create_session(daemon_context_t *ctx, uint32_t device_handle)
{
    if (ctx == NULL) {
        return 0;
    }
    
    session_info_t *new_session = calloc(1, sizeof(session_info_t));
    if (new_session == NULL) {
        return 0;
    }
    
    /* Initialize reference counting */
    new_session->ref_count = 1;  /* Start with one reference */
    if (pthread_mutex_init(&new_session->ref_mutex, NULL) != 0) {
        free(new_session);
        return 0;
    }
    if (pthread_mutex_init(&new_session->object_mutex, NULL) != 0) {
        pthread_mutex_destroy(&new_session->ref_mutex);
        free(new_session);
        return 0;
    }
    
    pthread_mutex_lock(&ctx->sessions_mutex);
    
    new_session->session_id = ctx->next_session_id++;
    new_session->device_handle = device_handle;
    new_session->create_time = time(NULL);
    new_session->last_access = new_session->create_time;
    new_session->active = true;
    
    /* Add to the head of the list */
    new_session->next = ctx->sessions;
    ctx->sessions = new_session;
    ctx->active_sessions_count++;
    
    uint32_t session_id = new_session->session_id;
    
    pthread_mutex_unlock(&ctx->sessions_mutex);
    
    
    return session_id;
}

int session_manager_close_session(daemon_context_t *ctx, uint32_t session_id)
{
    if (ctx == NULL) {
        return SDR_INARGERR;
    }
    
    pthread_mutex_lock(&ctx->sessions_mutex);
    
    session_info_t *current = ctx->sessions;
    session_info_t *prev = NULL;
    
    while (current != NULL) {
        if (current->session_id == session_id) {
            /* Mark session as inactive instead of removing immediately */
            pthread_mutex_lock(&current->ref_mutex);
            current->active = false;
            current->ref_count--; /* Remove the initial reference */
            int final_ref_count = current->ref_count;
            pthread_mutex_unlock(&current->ref_mutex);
            
            /* Remove from active session list */
            if (prev != NULL) {
                prev->next = current->next;
            } else {
                ctx->sessions = current->next;
            }
            ctx->active_sessions_count--;
            
            /* Free immediately if no other references, otherwise defer */
            if (final_ref_count <= 0) {
                session_objects_cleanup(current);
                pthread_mutex_destroy(&current->object_mutex);
                pthread_mutex_destroy(&current->ref_mutex);
                free(current);
                
            } else {
                
            }
            
            pthread_mutex_unlock(&ctx->sessions_mutex);
            return SDR_OK;
        }
        
        prev = current;
        current = current->next;
    }
    
    pthread_mutex_unlock(&ctx->sessions_mutex);
    LOG_WARN("Attempt to close non-existent session %u", session_id);
    return SDR_INVALID_HANDLE;
}

int session_manager_validate_session(daemon_context_t *ctx, uint32_t session_id)
{
    if (ctx == NULL) {
        return SDR_INARGERR;
    }
    
    pthread_mutex_lock(&ctx->sessions_mutex);
    
    session_info_t *session = find_session_locked(ctx, session_id);
    if (session != NULL && session->active) {
        session->last_access = time(NULL);
        pthread_mutex_unlock(&ctx->sessions_mutex);
        return SDR_OK;
    }
    
    pthread_mutex_unlock(&ctx->sessions_mutex);
    return SDR_INVALID_HANDLE;
}

/* DEPRECATED: This function is unsafe due to race conditions.
 * Use session_manager_get_session() and session_manager_put_session() instead.
 */
session_info_t* session_manager_find_session_deprecated(daemon_context_t *ctx, uint32_t session_id)
{
    LOG_WARN("Using deprecated session_manager_find_session - race condition possible");
    
    if (ctx == NULL) {
        return NULL;
    }
    
    pthread_mutex_lock(&ctx->sessions_mutex);
    session_info_t *session = find_session_locked(ctx, session_id);
    if (session != NULL) {
        session->last_access = time(NULL);
    }
    pthread_mutex_unlock(&ctx->sessions_mutex);
    
    /* CRITICAL SECURITY ISSUE: Returning session pointer after unlocking mutex! 
     * This creates a race condition that can lead to use-after-free vulnerabilities.
     */
    return session;
}

/**
 * @brief Get a session with increased reference count (thread-safe)
 * @param ctx Daemon context
 * @param session_id Session ID to find
 * @return Session pointer with increased reference count, or NULL if not found
 * @note The caller must call session_manager_put_session() when done
 */
session_info_t* session_manager_get_session(daemon_context_t *ctx, uint32_t session_id)
{
    if (ctx == NULL) {
        return NULL;
    }
    
    pthread_mutex_lock(&ctx->sessions_mutex);
    
    session_info_t *session = find_session_locked(ctx, session_id);
    if (session != NULL && session->active) {
        /* Increase reference count */
        pthread_mutex_lock(&session->ref_mutex);
        session->ref_count++;
        session->last_access = time(NULL);
        pthread_mutex_unlock(&session->ref_mutex);
    } else {
        session = NULL;  /* Session not found or inactive */
    }
    
    pthread_mutex_unlock(&ctx->sessions_mutex);
    
    return session;
}

/**
 * @brief Release a session reference (thread-safe)
 * @param session Session to release
 * @note This decreases the reference count and may free the session
 */
void session_manager_put_session(session_info_t *session)
{
    if (session == NULL) {
        return;
    }
    
    pthread_mutex_lock(&session->ref_mutex);
    session->ref_count--;
    int final_ref_count = session->ref_count;
    pthread_mutex_unlock(&session->ref_mutex);
    /* Free session if reference count reaches zero and session is inactive */
    if (final_ref_count <= 0 && !session->active) {
        
        session_objects_cleanup(session);
        pthread_mutex_destroy(&session->object_mutex);
        pthread_mutex_destroy(&session->ref_mutex);
        free(session);
    }
}

uint32_t device_manager_create_device(daemon_context_t *ctx)
{
    if (ctx == NULL) {
        return 0;
    }
    
    uint32_t device_id = ctx->next_device_id++;
    
    return device_id;
}

int device_manager_validate_device(daemon_context_t *ctx, uint32_t device_handle)
{
    /* Simple implementation: all device IDs are considered valid */
    if (ctx == NULL || device_handle == 0) {
        return SDR_INARGERR;
    }
    
    return SDR_OK;
}