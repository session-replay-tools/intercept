#include <xcopy.h>


tc_rbtree_t              tc_event_timer_rbtree;
static tc_rbtree_node_t  tc_event_timer_sentinel;


tc_event_timer_t* 
tc_event_add_timer(tc_pool_t *pool, tc_msec_t timer, void *data, 
        tc_event_timer_handler_pt handler)
{
    tc_msec_t         key;
    tc_event_timer_t *ev;

    ev = (tc_event_timer_t *) tc_palloc(pool, sizeof(tc_event_timer_t));
    if (ev != NULL) {
        ev->pool = pool;
        ev->handler = handler;
        ev->data = data;
        key = ((tc_msec_t) tc_current_time_msec) + timer;
        ev->timer.key = key;

        tc_rbtree_insert(&tc_event_timer_rbtree, &ev->timer);

        tc_log_debug1(LOG_DEBUG, 0, "add timer:%llu", ev);
        ev->timer_set = 1;
    }
    return ev;
}


/*
 * the event timer rbtree may contain the duplicate keys, however,
 * it should not be a problem, because we use the rbtree to find
 * a minimum timer value only
 */

tc_int_t
tc_event_timer_init(void )
{
    tc_rbtree_init(&tc_event_timer_rbtree, &tc_event_timer_sentinel,
                    tc_rbtree_insert_timer_value);

    return TC_OK;
}


tc_msec_t
tc_event_find_timer(void)
{
    tc_msec_int_t      timer;
    tc_rbtree_node_t  *node, *root, *sentinel;

    if (tc_event_timer_rbtree.root == &tc_event_timer_sentinel) {
        return TC_TIMER_INFINITE;
    }

    root = tc_event_timer_rbtree.root;
    sentinel = tc_event_timer_rbtree.sentinel;

    node = tc_rbtree_min(root, sentinel);

    timer = (tc_msec_int_t) (node->key - tc_current_time_msec);

    return (tc_msec_t) (timer > 0 ? timer : 0);
}


void
tc_event_expire_timers(void)
{
    tc_event_timer_t  *ev;
    tc_rbtree_node_t  *node, *root, *sentinel;

    sentinel = tc_event_timer_rbtree.sentinel;

    for ( ;; ) {

        root = tc_event_timer_rbtree.root;

        if (root == sentinel) {
            return;
        }

        node = tc_rbtree_min(root, sentinel);

        /* node->key <= tc_current_time */

        if ((tc_msec_int_t) (node->key - tc_current_time_msec) <= 0) {
            ev = (tc_event_timer_t *) ((char *) node -
                    offsetof(tc_event_timer_t, timer));

#if (TC_DEBUG)
            tc_log_debug1(LOG_DEBUG, 0, "del timer:%llu", ev);
#endif
            tc_rbtree_delete(&tc_event_timer_rbtree, &ev->timer);

            ev->timer_set = 0;

            ev->handler(ev);

            continue;
        }

        break;
    }

}

