#ifndef _NETSTACK_BASE_LIST_H_
#define _NETSTACK_BASE_LIST_H_

#define NS_LIST_ADD(item, list) do {		\
	item->prev = NULL;				        \
	item->next = list;				        \
	if (list != NULL) list->prev = item;    \
	list = item;					        \
} while(0)

#define NS_LIST_DEL(item, list) do {		                \
	if (item->prev != NULL) item->prev->next = item->next;	\
	if (item->next != NULL) item->next->prev = item->prev;	\
	if (list == item) list = item->next;	                \
	item->prev = item->next = NULL;			                \
} while(0)

#endif // _NETSTACK_BASE_LIST_H_