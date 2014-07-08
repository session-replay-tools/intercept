
#include <xcopy.h>

p_link_node
link_node_malloc(tc_pool_t *pool, void *data)
{
    p_link_node p;

    p = (p_link_node) tc_pcalloc(pool, sizeof(link_node));

    if (p != NULL) {
        p->data = data;
    }

    return p;
}


link_list *
link_list_create(tc_pool_t *pool)
{
    link_list *l = (link_list *) tc_pcalloc(pool, sizeof(link_list));

    if (l != NULL) {
        l->size      = 0;
        l->head.next = &(l->head);
        l->head.prev = &(l->head);
    }

    return l;
}

