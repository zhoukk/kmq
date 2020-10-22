/**
 * author: zhoukk
 * link: gist.github.com/zhoukk/f5366ce217e614b60ea4
 *
 * MinHeap or MaxHeap
 */

#ifndef _HEAP_H_
#define _HEAP_H_

typedef struct heap heap_t;

/** compare function for order heap */
typedef int (*heap_compare_pt)(void *va, void *vb);

/** Create a heap array with default cap n, and compare function f. */
heap_t *heap_new(int n, heap_compare_pt f);

/** Release the heap array. */
void heap_free(heap_t *heap);

/** Clear heap array, just make size == 0. */
void heap_clear(heap_t *heap);

/** Push an object v to heap array. */
int heap_push(heap_t *heap, void *v);

/** Pop object in top of array. */
void *heap_pop(heap_t *heap);

/** Return object in top of array. */
void *heap_top(heap_t *heap);

/** Update object v in heap array orderd. */
void heap_update(heap_t *heap, void *v);

/** Remove the object v in heap array. */
void *heap_remove(heap_t *heap, void *v);

/** Check exist of object v in heap array. */
int heap_exist(heap_t *heap, void *v);

#endif /* _HEAP_H_ */

#ifdef HEAP_IMPL

/**
 * Implement
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct heap {
    int cur;
    int cap;
    heap_compare_pt f;
    void **array;
};

heap_t *
heap_new(int n, heap_compare_pt f) {
    heap_t *heap;

    heap = (heap_t *)malloc(sizeof *heap);
    heap->array = (void **)calloc(n, sizeof(void *));
    heap->cur = 0;
    heap->cap = n;
    heap->f = f;
    return heap;
}

void
heap_free(heap_t *heap) {
    free(heap->array);
    free(heap);
}

void
heap_clear(heap_t *heap) {
    heap->cur = 0;
}

static void
heap_adjust_up(heap_t *heap, int i) {
    int p = (i + 1) / 2 - 1;
    void *v = heap->array[i];
    while (i > 0 && heap->f(v, heap->array[p])) {
        heap->array[i] = heap->array[p];
        i = p;
        p = (i + 1) / 2 - 1;
    }
    heap->array[i] = v;
}

static void
heap_adjust_down(heap_t *heap, int i) {
    void *v = heap->array[i];
    for (;;) {
        int l = (i + 1) * 2 - 1;
        int r = l + 1;
        if (l < heap->cur - 1) {
            int k = r;
            if (r == heap->cur - 1 || heap->f(heap->array[l], heap->array[r])) {
                k = l;
            }
            if (heap->f(v, heap->array[k])) {
                break;
            }
            heap->array[i] = heap->array[k];
            i = k;
        } else
            break;
    }
    heap->array[i] = v;
}

int
heap_push(heap_t *heap, void *v) {
    if (heap->cur >= heap->cap) {
        void **array = (void **)calloc(heap->cap * 2, sizeof(void *));
        memcpy(array, heap->array, heap->cap * sizeof(void *));
        free(heap->array);
        heap->array = array;
        heap->cap *= 2;
    }

    heap->array[heap->cur] = v;
    heap_adjust_up(heap, heap->cur);
    heap->cur++;
    return 0;
}

void *
heap_pop(heap_t *heap) {
    if (heap->cur <= 0)
        return 0;
    void *v = heap->array[0];
    heap->array[0] = heap->array[heap->cur - 1];
    heap_adjust_down(heap, 0);
    heap->cur--;
    return v;
}

void *
heap_top(heap_t *heap) {
    if (heap->cur <= 0)
        return 0;
    return heap->array[0];
}

void
heap_update(heap_t *heap, void *v) {
    int i;
    for (i = 0; i < heap->cur; i++) {
        if (heap->array[i] == v) {
            heap_adjust_up(heap, i);
            heap_adjust_down(heap, i);
            return;
        }
    }
}

void *
heap_remove(heap_t *heap, void *v) {
    int i;
    for (i = 0; i < heap->cur; i++) {
        if (heap->array[i] == v) {
            heap->array[i] = heap->array[heap->cur - 1];
            heap_adjust_down(heap, i);
            heap->cur--;
            return v;
        }
    }
    return 0;
}

int
heap_exist(heap_t *heap, void *v) {
    int i;
    for (i = 0; i < heap->cur; i++) {
        if (heap->array[i] == v) {
            return 1;
        }
    }
    return 0;
}

#endif /* HEAP_IMPL */
