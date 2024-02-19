/*  Copyright (C) 2019-2021 CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef __dnsjit_output_dnssim_ll_h
#define __dnsjit_output_dnssim_ll_h

#include <dnsjit/core/assert.h>

/* Utility macros for linked list structures.
 *
 * - "list" is the pointer to the first node of the linked list
 * - "list" can be NULL if there are no nodes
 * - every node has "next", which points to the next node (can be NULL)
 */

/* Append a node to the list.
 *
 * Only a single node can be appended - node->next must be NULL.
 */
#define _ll_append(list, node)                                                    \
    {                                                                             \
        glassert((node)->next == NULL, "node->next must be null when appending"); \
        if ((list) == NULL)                                                       \
            (list) = (node);                                                      \
        else if ((node) != NULL) {                                                \
            typeof(list) _current = (list);                                       \
            while (_current->next != NULL)                                        \
                _current = _current->next;                                        \
            _current->next = node;                                                \
        }                                                                         \
    }

/* Remove a node from the list.
 *
 * In strict mode, the node must be present in the list.
 */
#define _ll_remove_template(list, currname, cond, strict, once, dealloc)                           \
    do {                                                                                           \
        if (strict)                                                                                \
            glassert((list), "list can't be null when removing nodes");                            \
        if ((list) != NULL) {                                                                      \
            bool _removed = false;                                                                 \
            typeof(list)* currname = &(list);                                                      \
            while (*currname) {                                                                    \
                if ((cond)) {                                                                      \
                    typeof(list) _c = *currname;                                                   \
                    (*currname) = _c->next;                                                        \
                    _c->next = NULL;                                                               \
                    _removed = true;                                                               \
                    if ((dealloc))                                                                 \
                        free(_c);                                                                  \
                    if ((once))                                                                    \
                        break;                                                                     \
                } else {                                                                           \
                    currname = &(*currname)->next;                                                 \
                }                                                                                  \
            }                                                                                      \
            if (!_removed && (strict))                                                             \
                glfatal("list doesn't contain the node to be removed");                            \
        }                                                                                          \
    } while (0)

#define _ll_remove_node_template(list, node, strict) \
        _ll_remove_template((list), curr, *curr == (node), strict, true, false)

/* Remove the specified node from the list. */
#define _ll_remove(list, node) \
        _ll_remove_node_template((list), (node), true)

/* Remove the specified node from the list if it's present. */
#define _ll_try_remove(list, node) \
        _ll_remove_node_template((list), (node), false)

/* Remove all nodes for which `cond` is `true`. Here, `currname` is the name of
 * the pointer to the node currently checked by `cond`. I.e. in the first case,
 * `currname` will be `&list`, then `&list->next`, then `&list->next->next` etc.
 *
 * For `currname = c`, `cond` may be e.g. `(*c)->qry == qry`. */
#define _ll_remove_cond(list, currname, cond, dealloc) \
        _ll_remove_template((list), currname, (cond), false, false, (dealloc))

#endif
