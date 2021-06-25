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
#define _ll_remove_template(list, node, strict)                                                    \
    {                                                                                              \
        if (strict)                                                                                \
            glassert((list), "list can't be null when removing nodes");                            \
        if ((list) != NULL && (node) != NULL) {                                                    \
            if ((list) == (node)) {                                                                \
                (list)       = (node)->next;                                                       \
                (node)->next = NULL;                                                               \
            } else {                                                                               \
                typeof(list) _current = (list);                                                    \
                while (_current != NULL && _current->next != (node)) {                             \
                    if (strict)                                                                    \
                        glassert((_current->next), "list doesn't contain the node to be removed"); \
                    _current = _current->next;                                                     \
                }                                                                                  \
                if (_current != NULL) {                                                            \
                    _current->next = (node)->next;                                                 \
                    (node)->next   = NULL;                                                         \
                }                                                                                  \
            }                                                                                      \
        }                                                                                          \
    }

/* Remove a node from the list. */
#define _ll_remove(list, node) _ll_remove_template((list), (node), true)

/* Remove a node from the list if it's present. */
#define _ll_try_remove(list, node) _ll_remove_template((list), (node), false)

#endif
