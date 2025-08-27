/*
 * mqtt_mempool.h -- mqtt memory pool.
 *
 * Copyright (c) zhoukk <izhoukk@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef _MQTT_MEMPOOL_H_
#define _MQTT_MEMPOOL_H_

#include <stddef.h>
#include <stdint.h>

typedef struct mqtt_mempool_s mqtt_mempool_t;

mqtt_mempool_t *mqtt_mempool_create(size_t block_size);

void mqtt_mempool_destroy(mqtt_mempool_t *pool);

void *mqtt_mempool_alloc(mqtt_mempool_t *pool, size_t size);

void mqtt_mempool_free(mqtt_mempool_t *pool, void *ptr);

void mqtt_mempool_stats(mqtt_mempool_t *pool, size_t *allocated_size, size_t *used_size, size_t *total_allocations,
                        size_t *total_frees, double *hit_rate);

#endif /* _MQTT_MEMPOOL_H_ */

#ifdef MQTT_MEMPOOL_IMPL

#include <stdlib.h>
#include <string.h>

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_THREADS__)
#define MQTT_MEMPOOL_C11_THREADS 1
#include <threads.h>
#else
#define MQTT_MEMPOOL_C11_THREADS 0
#ifdef _WIN32
#include <windows.h>
typedef CRITICAL_SECTION mqtt_mempool_mutex_t;
#else
#include <pthread.h>
typedef pthread_mutex_t mqtt_mempool_mutex_t;
#endif
#endif

#if MQTT_MEMPOOL_C11_THREADS
#define MQTT_MEMPOOL_LOCK_INIT(m) mtx_init(&(m), mtx_plain)
#define MQTT_MEMPOOL_LOCK_DESTROY(m) mtx_destroy(&(m))
#define MQTT_MEMPOOL_LOCK(m) mtx_lock(&(m))
#define MQTT_MEMPOOL_UNLOCK(m) mtx_unlock(&(m))
#else
#ifdef _WIN32
#define MQTT_MEMPOOL_LOCK_INIT(m) InitializeCriticalSection(&(m))
#define MQTT_MEMPOOL_LOCK_DESTROY(m) DeleteCriticalSection(&(m))
#define MQTT_MEMPOOL_LOCK(m) EnterCriticalSection(&(m))
#define MQTT_MEMPOOL_UNLOCK(m) LeaveCriticalSection(&(m))
#else
#define MQTT_MEMPOOL_LOCK_INIT(m) pthread_mutex_init(&(m), NULL)
#define MQTT_MEMPOOL_LOCK_DESTROY(m) pthread_mutex_destroy(&(m))
#define MQTT_MEMPOOL_LOCK(m) pthread_mutex_lock(&(m))
#define MQTT_MEMPOOL_UNLOCK(m) pthread_mutex_unlock(&(m))
#endif
#endif

#define MQTT_MEMPOOL_BLOCK_SIZE 4096
#define MQTT_MEMPOOL_SLAB_COUNT 8

#define MQTT_MEMPOOL_ALIGN_SIZE(size) (((size) + 7) & ~7)

static const size_t mqtt_mempool_slab_sizes[MQTT_MEMPOOL_SLAB_COUNT] = {32, 64, 128, 256, 512, 1024, 2048, 4096};

typedef struct mqtt_mempool_block_s {
    struct mqtt_mempool_block_s *next;
    size_t size;
    size_t used;
    int slab_index;
    char data[1];
} mqtt_mempool_block_t;

typedef struct mqtt_mempool_slab_s {
    mqtt_mempool_block_t *free_list;
    mqtt_mempool_block_t *used_list;
    size_t block_size;
    size_t allocated;
    size_t used;
    size_t allocations;
    size_t frees;
} mqtt_mempool_slab_t;

typedef struct mqtt_mempool_s {
    size_t block_size;
    size_t allocated_size;
    size_t used_size;
    size_t total_allocations;
    size_t total_frees;
    size_t slab_allocations;

    mqtt_mempool_slab_t slabs[MQTT_MEMPOOL_SLAB_COUNT];

    mqtt_mempool_block_t *large_blocks;

#if MQTT_MEMPOOL_C11_THREADS
    mtx_t mutex;
#else
    mqtt_mempool_mutex_t mutex;
#endif
} mqtt_mempool_t;

static int
_mqtt_mempool_get_slab_index(size_t size) {
    int i;

    for (i = 0; i < MQTT_MEMPOOL_SLAB_COUNT; i++) {
        if (size <= mqtt_mempool_slab_sizes[i]) {
            return i;
        }
    }

    return -1;
}

mqtt_mempool_t *
mqtt_mempool_create(size_t block_size) {
    mqtt_mempool_t *pool;
    int i;

    pool = (mqtt_mempool_t *)malloc(sizeof(mqtt_mempool_t));
    if (!pool) {
        return NULL;
    }

    if (block_size == 0) {
        block_size = MQTT_MEMPOOL_BLOCK_SIZE;
    }

    memset(pool, 0, sizeof(mqtt_mempool_t));
    pool->block_size = block_size;

    if (MQTT_MEMPOOL_LOCK_INIT(pool->mutex) != 0) {
        free(pool);
        return NULL;
    }

    for (i = 0; i < MQTT_MEMPOOL_SLAB_COUNT; i++) {
        pool->slabs[i].block_size = mqtt_mempool_slab_sizes[i];
        pool->slabs[i].free_list = NULL;
        pool->slabs[i].used_list = NULL;
        pool->slabs[i].allocated = 0;
        pool->slabs[i].used = 0;
        pool->slabs[i].allocations = 0;
        pool->slabs[i].frees = 0;
    }

    pool->large_blocks = NULL;

    return pool;
}

void
mqtt_mempool_destroy(mqtt_mempool_t *pool) {
    mqtt_mempool_block_t *block;
    mqtt_mempool_block_t *next;
    int i;

    if (!pool) {
        return;
    }

    MQTT_MEMPOOL_LOCK(pool->mutex);

    for (i = 0; i < MQTT_MEMPOOL_SLAB_COUNT; i++) {
        block = pool->slabs[i].free_list;
        while (block) {
            next = block->next;
            free(block);
            block = next;
        }

        block = pool->slabs[i].used_list;
        while (block) {
            next = block->next;
            free(block);
            block = next;
        }
    }

    block = pool->large_blocks;
    while (block) {
        next = block->next;
        free(block);
        block = next;
    }

    MQTT_MEMPOOL_UNLOCK(pool->mutex);
    MQTT_MEMPOOL_LOCK_DESTROY(pool->mutex);

    free(pool);
}

void *
mqtt_mempool_alloc(mqtt_mempool_t *pool, size_t size) {
    mqtt_mempool_block_t *block;
    size_t block_size;
    int slab_index;
    size_t aligned_size;
    void *result;

    if (!pool || size == 0) {
        return NULL;
    }

    MQTT_MEMPOOL_LOCK(pool->mutex);

    pool->total_allocations++;

    aligned_size = MQTT_MEMPOOL_ALIGN_SIZE(size);

    slab_index = _mqtt_mempool_get_slab_index(aligned_size);

    if (slab_index == -1) {
        block_size = sizeof(mqtt_mempool_block_t) + aligned_size;
        block = (mqtt_mempool_block_t *)malloc(block_size);
        if (!block) {
            MQTT_MEMPOOL_UNLOCK(pool->mutex);
            return NULL;
        }

        block->next = pool->large_blocks;
        block->size = aligned_size;
        block->used = aligned_size;
        block->slab_index = -1;

        pool->large_blocks = block;
        pool->allocated_size += block_size;
        pool->used_size += aligned_size;

        result = block->data;
        MQTT_MEMPOOL_UNLOCK(pool->mutex);
        return result;
    }

    pool->slab_allocations++;
    pool->slabs[slab_index].allocations++;

    if (pool->slabs[slab_index].free_list) {
        block = pool->slabs[slab_index].free_list;
        pool->slabs[slab_index].free_list = block->next;

        block->next = pool->slabs[slab_index].used_list;
        pool->slabs[slab_index].used_list = block;

        block->used = aligned_size;
        pool->slabs[slab_index].used += aligned_size;
        pool->used_size += aligned_size;

        result = block->data;
        MQTT_MEMPOOL_UNLOCK(pool->mutex);
        return result;
    }

    block_size = sizeof(mqtt_mempool_block_t) + pool->slabs[slab_index].block_size;
    block = (mqtt_mempool_block_t *)malloc(block_size);
    if (!block) {
        MQTT_MEMPOOL_UNLOCK(pool->mutex);
        return NULL;
    }

    block->next = pool->slabs[slab_index].used_list;
    block->size = pool->slabs[slab_index].block_size;
    block->used = aligned_size;
    block->slab_index = slab_index;

    pool->slabs[slab_index].used_list = block;
    pool->slabs[slab_index].allocated += block_size;
    pool->slabs[slab_index].used += aligned_size;
    pool->allocated_size += block_size;
    pool->used_size += aligned_size;

    result = block->data;
    MQTT_MEMPOOL_UNLOCK(pool->mutex);
    return result;
}

void
mqtt_mempool_free(mqtt_mempool_t *pool, void *ptr) {
    mqtt_mempool_block_t *block, *prev;
    int slab_index;

    if (!pool || !ptr) {
        return;
    }

    MQTT_MEMPOOL_LOCK(pool->mutex);

    pool->total_frees++;

    prev = NULL;
    block = pool->large_blocks;
    while (block) {
        if (ptr == (void *)block->data) {
            if (prev) {
                prev->next = block->next;
            } else {
                pool->large_blocks = block->next;
            }

            pool->allocated_size -= (sizeof(mqtt_mempool_block_t) + block->size);
            pool->used_size -= block->used;
            free(block);
            MQTT_MEMPOOL_UNLOCK(pool->mutex);
            return;
        }
        prev = block;
        block = block->next;
    }

    for (slab_index = 0; slab_index < MQTT_MEMPOOL_SLAB_COUNT; slab_index++) {
        prev = NULL;
        block = pool->slabs[slab_index].used_list;
        while (block) {
            if (ptr == (void *)block->data) {
                if (prev) {
                    prev->next = block->next;
                } else {
                    pool->slabs[slab_index].used_list = block->next;
                }

                block->next = pool->slabs[slab_index].free_list;
                pool->slabs[slab_index].free_list = block;

                pool->slabs[slab_index].used -= block->used;
                pool->slabs[slab_index].frees++;
                pool->used_size -= block->used;
                block->used = 0;

                MQTT_MEMPOOL_UNLOCK(pool->mutex);
                return;
            }
            prev = block;
            block = block->next;
        }
    }

    MQTT_MEMPOOL_UNLOCK(pool->mutex);
}

void
mqtt_mempool_stats(mqtt_mempool_t *pool, size_t *allocated_size, size_t *used_size, size_t *total_allocations,
                   size_t *total_frees, double *hit_rate) {
    if (!pool) {
        return;
    }

    MQTT_MEMPOOL_LOCK(pool->mutex);

    if (allocated_size) {
        *allocated_size = pool->allocated_size;
    }

    if (used_size) {
        *used_size = pool->used_size;
    }

    if (total_allocations) {
        *total_allocations = pool->total_allocations;
    }

    if (total_frees) {
        *total_frees = pool->total_frees;
    }

    if (hit_rate) {
        if (pool->total_allocations > 0) {
            *hit_rate = (double)pool->slab_allocations / (double)pool->total_allocations;
        } else {
            *hit_rate = 0.0;
        }
    }

    MQTT_MEMPOOL_UNLOCK(pool->mutex);
}

#endif /* MQTT_MEMPOOL_IMPL */