/*
 * snowflake.h -- snowflake implementation.
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

#ifndef _SNOWFLAKE_H_
#define _SNOWFLAKE_H_

#include <time.h>

#define SNOWFLAKE_EPOCH 1409583600000

#define SNOWFLAKE_TIME_BITS 41
#define SNOWFLAKE_REGIONID_BITS 4
#define SNOWFLAKE_WORKERID_BITS 10
#define SNOWFLAKE_SEQUENCE_BITS 8

#define SNOWFLAKE_ID_LEN 18

typedef struct {
    long worker_id;
    long region_id;
    long time;
    long seq;
    long seq_max;
    long time_shift_bits;
    long region_shift_bits;
    long worker_shift_bits;
} snowflake_t;

int snowflake_init(snowflake_t *snowflake, int region_id, int worker_id);

long snowflake_id(snowflake_t *snowflake);

#endif /* _SNOWFLAKE_H_ */

#ifdef SNOWFLAKE_IMPL

/**
 * Implement
 */

#include <sys/time.h>

int
snowflake_init(snowflake_t *snowflake, int region_id, int worker_id) {
    int max_region_id = (1 << SNOWFLAKE_REGIONID_BITS) - 1;
    int max_worker_id = (1 << SNOWFLAKE_WORKERID_BITS) - 1;

    if (region_id < 0 || region_id > max_region_id) {
        return -1;
    }
    if (worker_id < 0 || worker_id > max_worker_id) {
        return -1;
    }

    snowflake->time_shift_bits = SNOWFLAKE_REGIONID_BITS + SNOWFLAKE_WORKERID_BITS + SNOWFLAKE_SEQUENCE_BITS;
    snowflake->region_shift_bits = SNOWFLAKE_WORKERID_BITS + SNOWFLAKE_SEQUENCE_BITS;
    snowflake->worker_shift_bits = SNOWFLAKE_SEQUENCE_BITS;

    snowflake->worker_id = worker_id;
    snowflake->region_id = region_id;
    snowflake->seq_max = (1L << SNOWFLAKE_SEQUENCE_BITS) - 1;
    snowflake->seq = 0L;
    snowflake->time = 0L;
    return 0;
}

long
snowflake_id(snowflake_t *snowflake) {
    struct timeval tp;
    long id, millisecs;

    gettimeofday(&tp, 0);
    millisecs = tp.tv_sec * 1000 + tp.tv_usec / 1000 - SNOWFLAKE_EPOCH;

    if ((snowflake->seq > snowflake->seq_max) || snowflake->time > millisecs) {
        while (snowflake->time >= millisecs) {
            gettimeofday(&tp, 0);
            millisecs = tp.tv_sec * 1000 + tp.tv_usec / 1000 - SNOWFLAKE_EPOCH;
        }
    }

    if (snowflake->time < millisecs) {
        snowflake->time = millisecs;
        snowflake->seq = 0L;
    }

    id = (millisecs << snowflake->time_shift_bits) | (snowflake->region_id << snowflake->region_shift_bits) |
         (snowflake->worker_id << snowflake->worker_shift_bits) | (snowflake->seq++);
    return id;
}

#endif /* SNOWFLAKE_IMPL */
