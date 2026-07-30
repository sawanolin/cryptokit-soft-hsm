/*
 * Copyright (C) 2025 SDFX Project
 * SDFX is licensed under Mulan PSL v2.
 */

/**
 * @file thread_pool.c
 * @brief Thread pool implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>

#include "daemon_internal.h"

/* Task queue node */
typedef struct task_node {
    void (*function)(void *arg);
    void *arg;
    struct task_node *next;
} task_node_t;

/* Task queue */
typedef struct task_queue {
    task_node_t *head;
    task_node_t *tail;
    int count;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
} task_queue_t;

/* Thread pool structure */
typedef struct thread_pool {
    pthread_t *threads;
    int thread_count;
    int shutdown;
    task_queue_t task_queue;
    pthread_mutex_t pool_mutex;
} thread_pool_t;

static thread_pool_t *g_thread_pool = NULL;

/* Worker thread function */
static void* worker_thread(void *arg)
{
    thread_pool_t *pool = (thread_pool_t *)arg;
    
    LOG_INFO("Worker thread %lu started", pthread_self());
    
    while (1) {
        pthread_mutex_lock(&pool->task_queue.mutex);
        
        /* Wait for a task or shutdown signal */
        while (pool->task_queue.count == 0 && !pool->shutdown) {
            pthread_cond_wait(&pool->task_queue.not_empty, &pool->task_queue.mutex);
        }
        
        /* Check shutdown flag */
        if (pool->shutdown) {
            pthread_mutex_unlock(&pool->task_queue.mutex);
            break;
        }
        
        /* Get task */
        task_node_t *task = pool->task_queue.head;
        if (task == NULL) {
            pthread_mutex_unlock(&pool->task_queue.mutex);
            continue;
        }
        
        pool->task_queue.head = task->next;
        if (pool->task_queue.head == NULL) {
            pool->task_queue.tail = NULL;
        }
        pool->task_queue.count--;
        
        pthread_mutex_unlock(&pool->task_queue.mutex);
        
        /* Execute task */
        if (task->function) {
            task->function(task->arg);
        }
        free(task);
    }
    
    LOG_DEBUG("Worker thread %lu exiting", pthread_self());
    return NULL;
}

/* Initialize task queue */
static int task_queue_init(task_queue_t *queue)
{
    queue->head = NULL;
    queue->tail = NULL;
    queue->count = 0;
    
    if (pthread_mutex_init(&queue->mutex, NULL) != 0) {
        return -1;
    }
    
    if (pthread_cond_init(&queue->not_empty, NULL) != 0) {
        pthread_mutex_destroy(&queue->mutex);
        return -1;
    }
    
    return 0;
}

/* Cleanup task queue */
static void task_queue_cleanup(task_queue_t *queue)
{
    pthread_mutex_lock(&queue->mutex);
    
    /* Cleanup remaining tasks */
    task_node_t *node = queue->head;
    while (node) {
        task_node_t *next = node->next;
        free(node);
        node = next;
    }
    
    queue->head = NULL;
    queue->tail = NULL;
    queue->count = 0;
    
    pthread_mutex_unlock(&queue->mutex);
    
    pthread_cond_destroy(&queue->not_empty);
    pthread_mutex_destroy(&queue->mutex);
}

/* Push a task to the task queue */
static int task_queue_push(task_queue_t *queue, void (*function)(void*), void *arg)
{
    task_node_t *task = malloc(sizeof(task_node_t));
    if (task == NULL) {
        LOG_ERROR("Failed to allocate task node: %s", strerror(errno));
        return -1;
    }
    
    task->function = function;
    task->arg = arg;
    task->next = NULL;
    
    pthread_mutex_lock(&queue->mutex);
    
    if (queue->tail == NULL) {
        queue->head = queue->tail = task;
    } else {
        queue->tail->next = task;
        queue->tail = task;
    }
    queue->count++;
    
    pthread_cond_signal(&queue->not_empty);
    pthread_mutex_unlock(&queue->mutex);
    
    return 0;
}

/* Create thread pool */
int thread_pool_create(int thread_count)
{
    if (g_thread_pool != NULL) {
        LOG_WARN("Thread pool already exists");
        return 0;
    }
    
    if (thread_count <= 0 || thread_count > 100) {
        LOG_ERROR("Invalid thread count: %d", thread_count);
        return -1;
    }
    
    thread_pool_t *pool = malloc(sizeof(thread_pool_t));
    if (pool == NULL) {
        LOG_ERROR("Failed to allocate thread pool: %s", strerror(errno));
        return -1;
    }
    
    memset(pool, 0, sizeof(thread_pool_t));
    pool->thread_count = thread_count;
    pool->shutdown = 0;
    
    /* Initialize mutex */
    if (pthread_mutex_init(&pool->pool_mutex, NULL) != 0) {
        LOG_ERROR("Failed to init pool mutex");
        free(pool);
        return -1;
    }
    
    /* Initialize task queue */
    if (task_queue_init(&pool->task_queue) != 0) {
        LOG_ERROR("Failed to init task queue");
        pthread_mutex_destroy(&pool->pool_mutex);
        free(pool);
        return -1;
    }
    
    /* Allocate thread array */
    pool->threads = malloc(sizeof(pthread_t) * thread_count);
    if (pool->threads == NULL) {
        LOG_ERROR("Failed to allocate threads array: %s", strerror(errno));
        task_queue_cleanup(&pool->task_queue);
        pthread_mutex_destroy(&pool->pool_mutex);
        free(pool);
        return -1;
    }
    
    /* Create worker threads */
    for (int i = 0; i < thread_count; i++) {
        if (pthread_create(&pool->threads[i], NULL, worker_thread, pool) != 0) {
            LOG_ERROR("Failed to create worker thread %d", i);
            pool->thread_count = i; /* Set the actual number of created threads */
            thread_pool_destroy();
            return -1;
        }
    }
    
    g_thread_pool = pool;
    LOG_INFO("Thread pool created with %d worker threads", thread_count);
    return 0;
}

/* Submit a task to the thread pool */
int thread_pool_submit(void (*function)(void*), void *arg)
{
    if (g_thread_pool == NULL) {
        LOG_ERROR("Thread pool not initialized");
        return -1;
    }
    
    if (function == NULL) {
        LOG_ERROR("Task function is NULL");
        return -1;
    }
    
    pthread_mutex_lock(&g_thread_pool->pool_mutex);
    
    if (g_thread_pool->shutdown) {
        pthread_mutex_unlock(&g_thread_pool->pool_mutex);
        LOG_WARN("Thread pool is shutting down");
        return -1;
    }
    
    int ret = task_queue_push(&g_thread_pool->task_queue, function, arg);
    
    pthread_mutex_unlock(&g_thread_pool->pool_mutex);
    
    if (ret != 0) {
        LOG_ERROR("Failed to submit task to thread pool");
        return -1;
    }
    
    LOG_DEBUG("Task submitted to thread pool");
    return 0;
}

/* Destroy thread pool */
void thread_pool_destroy(void)
{
    if (g_thread_pool == NULL) {
        return;
    }
    
    LOG_INFO("Destroying thread pool...");
    
    pthread_mutex_lock(&g_thread_pool->pool_mutex);
    g_thread_pool->shutdown = 1;
    pthread_mutex_unlock(&g_thread_pool->pool_mutex);
    
    /* Wake up all worker threads */
    pthread_cond_broadcast(&g_thread_pool->task_queue.not_empty);
    
    /* Wait for all threads to exit */
    for (int i = 0; i < g_thread_pool->thread_count; i++) {
        pthread_join(g_thread_pool->threads[i], NULL);
    }
    
    /* Cleanup resources */
    task_queue_cleanup(&g_thread_pool->task_queue);
    pthread_mutex_destroy(&g_thread_pool->pool_mutex);
    free(g_thread_pool->threads);
    free(g_thread_pool);
    g_thread_pool = NULL;
    
    LOG_INFO("Thread pool destroyed");
}

/* Get thread pool status */
int thread_pool_get_stats(int *thread_count, int *queue_size)
{
    if (g_thread_pool == NULL) {
        return -1;
    }
    
    pthread_mutex_lock(&g_thread_pool->pool_mutex);
    
    if (thread_count) {
        *thread_count = g_thread_pool->thread_count;
    }
    
    if (queue_size) {
        pthread_mutex_lock(&g_thread_pool->task_queue.mutex);
        *queue_size = g_thread_pool->task_queue.count;
        pthread_mutex_unlock(&g_thread_pool->task_queue.mutex);
    }
    
    pthread_mutex_unlock(&g_thread_pool->pool_mutex);
    return 0;
}