/*
 * Copyright (c) 2011-2015 Intel Corporation.  All rights reserved.
 * Copyright (c) 2016 Cray Inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#ifndef _UET_LIST_H_
#define _UET_LIST_H_

#include <linux/stddef.h>

/*
 * Double-linked list
 */
struct uet_list_entry {
	struct uet_list_entry	*next;
	struct uet_list_entry	*prev;
};

#define UET_LIST_INIT(addr) { addr, addr }
#define DEFINE_UET_LIST(name) struct uet_list_entry name = UET_LIST_INIT(&name)

static inline void uet_list_init(struct uet_list_entry *head)
{
	head->next = head;
	head->prev = head;
}

static inline int uet_list_empty(struct uet_list_entry *head)
{
	return head->next == head;
}

static inline void
uet_list_insert_after(struct uet_list_entry *item, struct uet_list_entry *head)
{
	item->next = head->next;
	item->prev = head;
	head->next->prev = item;
	head->next = item;
}

static inline void
uet_list_insert_before(struct uet_list_entry *item, struct uet_list_entry *head)
{
	uet_list_insert_after(item, head->prev);
}

#define uet_list_insert_head uet_list_insert_after
#define uet_list_insert_tail uet_list_insert_before

static inline void uet_list_remove(struct uet_list_entry *item)
{
	item->prev->next = item->next;
	item->next->prev = item->prev;
}

static inline void uet_list_remove_init(struct uet_list_entry *item)
{
	uet_list_remove(item);
	uet_list_init(item);
}

#define uet_list_first_entry_or_null(head, type, member) ({	\
	struct uet_list_entry *pos = (head)->next;				\
	pos != (head) ? container_of((pos), type, member) : NULL;	\
})

#define uet_list_pop_front(head, type, container, member)			\
	do {								\
		container = container_of((head)->next, type, member);	\
		uet_list_remove((head)->next);				\
	} while (0)

#define uet_list_foreach(head, item) 						\
	for ((item) = (head)->next; (item) != (head); (item) = (item)->next)

#define uet_list_foreach_reverse(head, item) 					\
	for ((item) = (head)->prev; (item) != (head); (item) = (item)->prev)

#define uet_list_foreach_container(head, type, container, member)			\
	for ((container) = container_of((head)->next, type, member);		\
	     &((container)->member) != (head);					\
	     (container) = container_of((container)->member.next,		\
					type, member))

#define uet_list_foreach_container_reverse(head, type, container, member)		\
	for ((container) = container_of((head)->prev, type, member);		\
	     &((container)->member) != (head);					\
	     (container) = container_of((container)->member.prev,		\
					type, member))

#define uet_list_foreach_safe(head, item, tmp)					\
	for ((item) = (head)->next, (tmp) = (item)->next; (item) != (head);	\
             (item) = (tmp), (tmp) = (item)->next)

#define uet_list_foreach_reverse_safe(head, item, tmp)				\
	for ((item) = (head)->prev, (tmp) = (item)->prev; (item) != (head);	\
             (item) = (tmp), (tmp) = (item)->prev)

#define uet_list_foreach_container_safe(head, type, container, member, tmp)	\
	for ((container) = container_of((head)->next, type, member),		\
	     (tmp) = (container)->member.next;					\
	     &((container)->member) != (head);					\
	     (container) = container_of((tmp), type, member),			\
	     (tmp) = (container)->member.next)

#define uet_list_foreach_container_reverse_safe(head, type, container, member, tmp)\
	for ((container) = container_of((head)->prev, type, member),		\
	     (tmp) = (container)->member.prev;					\
	     &((container)->member) != (head);					\
	     (container) = container_of((tmp), type, member),			\
	     (tmp) = (container)->member.prev)

typedef int uet_list_func_t(struct uet_list_entry *item, const void *arg);

static inline struct uet_list_entry *
uet_list_find_first_match(struct uet_list_entry *head, uet_list_func_t *match,
		       const void *arg)
{
	struct uet_list_entry *item;

	uet_list_foreach(head, item) {
		if (match(item, arg))
			return item;
	}

	return NULL;
}

static inline struct uet_list_entry *
uet_list_remove_first_match(struct uet_list_entry *head, uet_list_func_t *match,
			 const void *arg)
{
	struct uet_list_entry *item;

	item = uet_list_find_first_match(head, match, arg);
	if (item)
		uet_list_remove(item);

	return item;
}

static inline void uet_list_insert_order(struct uet_list_entry *head, uet_list_func_t *order,
				      struct uet_list_entry *entry)
{
	struct uet_list_entry *item;

	item = uet_list_find_first_match(head, order, entry);
	if (item)
		uet_list_insert_before(entry, item);
	else
		uet_list_insert_tail(entry, head);
}

/* splices list at the front of the list 'head'
 *
 * BEFORE:
 * head:      HEAD->a->b->c->HEAD
 * to_splice: HEAD->d->e->HEAD
 *
 * AFTER:
 * head:      HEAD->d->e->a->b->c->HEAD
 * to_splice: HEAD->HEAD (empty list)
 */
static inline void uet_list_splice_head(struct uet_list_entry *head,
				     struct uet_list_entry *to_splice)
{
	if (uet_list_empty(to_splice))
		return;

	/* hook first element of 'head' to last element of 'to_splice' */
	head->next->prev = to_splice->prev;
	to_splice->prev->next = head->next;

	/* put first element of 'to_splice' as first element of 'head' */
	head->next = to_splice->next;
	head->next->prev = head;

	/* set list to empty */
	uet_list_init(to_splice);
}

/* splices list at the back of the list 'head'
 *
 * BEFORE:
 * head:      HEAD->a->b->c->HEAD
 * to_splice: HEAD->d->e->HEAD
 *
 * AFTER:
 * head:      HEAD->a->b->c->d->e->HEAD
 * to_splice: HEAD->HEAD (empty list)
 */
static inline void uet_list_splice_tail(struct uet_list_entry *head,
				     struct uet_list_entry *to_splice)
{
	uet_list_splice_head(head->prev, to_splice);
}

#endif /* _UET_LIST_H_ */
