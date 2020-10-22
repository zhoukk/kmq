/*
 * queue.h
 *
 * Copyright (c) zhoukk <izhoukk@gmail.com>
 */

#ifndef _QUEUE_H_
#define _QUEUE_H_

typedef struct queue_s queue_t;

struct queue_s {
    queue_t *prev;
    queue_t *next;
};

#define queue_init(q) \
    (q)->prev = q;    \
    (q)->next = q

#define queue_empty(h) (h == (h)->prev)

#define queue_insert_head(h, x) \
    (x)->next = (h)->next;      \
    (x)->next->prev = x;        \
    (x)->prev = h;              \
    (h)->next = x

#define queue_insert_tail(h, x) \
    (x)->prev = (h)->prev;      \
    (x)->prev->next = x;        \
    (x)->next = h;              \
    (h)->prev = x

#define queue_head(h) (h)->next

#define queue_last(h) (h)->prev

#define queue_next(q) (q)->next

#define queue_prev(q) (q)->prev

#define queue_remove(x)          \
    (x)->next->prev = (x)->prev; \
    (x)->prev->next = (x)->next

#define queue_foreach(q, h) for ((q) = queue_head(h); (q) != (h); (q) = queue_next(q))

#define queue_data(q, type, link) (type *)((u_char *)q - offsetof(type, link))

#endif /* _QUEUE_H_ */