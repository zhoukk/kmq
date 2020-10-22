/*
 * map.h
 *
 * Copyright (c) zhoukk <izhoukk@gmail.com>
 */

#ifndef _MAP_H_
#define _MAP_H_

#include "rbtree.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct rb_node map_node_t;

typedef void *(*map_key_pt)(map_node_t *);
typedef int (*map_cmp_pt)(void *a, void *b);

typedef struct {
    struct rb_root root;
    map_key_pt key_pt;
    map_cmp_pt cmp_pt;
} map_t;

#define map_data(ptr, type, member) rb_entry(ptr, type, member)

#define map_first(map) rb_first(&(map)->root)
#define map_next(node) rb_next(node)
#define map_empty(map) RB_EMPTY_ROOT(&(map)->root)

#define map_foreach(n, m) for ((n) = map_first(m); (n); (n) = map_next(n))
#define map_foreach_safe(n, next, m)                 \
    for ((n) = map_first(m); (n) && ({               \
                                 next = map_next(n); \
                                 1;                  \
                             });                     \
         (n) = (next))

static int
_map_def_cmp(void *a, void *b) {
    return strcmp((const char *)a, (const char *)b);
}

static inline void
map_init(map_t *map, map_key_pt key_pt, map_cmp_pt cmp_pt) {
    if (!cmp_pt) {
        cmp_pt = _map_def_cmp;
    }
    map->key_pt = key_pt;
    map->cmp_pt = cmp_pt;
    map->root.rb_node = NULL;
}

static inline int
map_push(map_t *map, void *key, map_node_t *node) {
    map_node_t **pnode = &(map->root.rb_node), *parent = NULL;

    while (*pnode) {
        int rc = map->cmp_pt(key, map->key_pt(*pnode));

        parent = *pnode;
        if (rc < 0)
            pnode = &((*pnode)->rb_left);
        else if (rc > 0)
            pnode = &((*pnode)->rb_right);
        else
            return -1;
    }

    rb_link_node(node, parent, pnode);
    rb_insert_color(node, &map->root);

    return 0;
}

static inline map_node_t *
map_find(map_t *map, void *key) {
    map_node_t *node = map->root.rb_node;
    while (node) {
        int rc;

        rc = map->cmp_pt(key, map->key_pt(node));
        if (rc < 0)
            node = node->rb_left;
        else if (rc > 0)
            node = node->rb_right;
        else
            return node;
    }
    return NULL;
}

static inline void
map_erase(map_t *map, map_node_t *node) {
    rb_erase(node, &map->root);
}

#endif /* _MAP_H_ */