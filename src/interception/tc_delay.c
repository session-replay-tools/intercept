
#include <xcopy.h>
#include <intercept.h>

static uint64_t     msg_item_cnt, msg_item_free_cnt,
                    msg_ls_cnt, msg_ls_free_cnt, msg_ls_destr_cnt, 
                    msg_delay_sent_cnt;

static hash_table  *table;

static struct msg_server_s *
copy_message(tc_pool_t *pool, struct msg_server_s *msg)
{
    struct msg_server_s *cmsg;

    cmsg = (struct msg_server_s *) tc_palloc(pool, sizeof(struct msg_server_s));
    if (cmsg != NULL) {
        memcpy(cmsg, msg, sizeof(struct msg_server_s));
    } else {
        tc_log_info(LOG_ERR, errno, "malloc error");
    }

    return cmsg;
}


void
tc_delay_del_obs(tc_event_timer_t *evt)
{
    delay_sess_t *s;

    s = evt->data;
    if (s != NULL) {
        if (!hash_del(table, s->pool, s->key)) {
            tc_log_info(LOG_WARN, 0, "no hash item for port transfer");
        }

        msg_ls_destr_cnt++;
        tc_destroy_pool(s->pool);
    } else {
        tc_log_info(LOG_ERR, 0, "delay session already deleted:%llu", evt);
    }
}


void
delay_table_init(tc_pool_t *pool, uint32_t size)
{
    table = hash_create(pool, size);
    hash_set_timeout(table, 30);
    msg_item_cnt       = 0;
    msg_item_free_cnt  = 0;
    msg_ls_cnt         = 0;
    msg_ls_destr_cnt   = 0;
    msg_delay_sent_cnt = 0;
}


void
delay_table_add(uint64_t key, struct msg_server_s *msg)
{
    tc_pool_t           *pool;
    p_link_node          ln;
    delay_sess_t        *s;
    struct msg_server_s *cmsg;

    s = (delay_sess_t *) hash_find(table, key);
    if (s == NULL) {
        pool = tc_create_pool(TC_DEFAULT_POOL_SIZE, 0);

        if (pool != NULL) {

            s = (delay_sess_t *) tc_pcalloc(pool, sizeof(delay_sess_t));
            if (s != NULL) {
                s->key = key;
                s->pool = pool;
                s->msg_list = link_list_create(s->pool);
                s->evt = tc_event_add_timer(s->pool, OUTPUT_INTERVAL, s, 
                        tc_delay_del_obs);
                msg_ls_cnt++;
                hash_add(table, s->pool, key, s);
            } else {
                return;
            }
        } else {
            return;
        }
    }

    cmsg = copy_message(s->pool, msg);
    if (cmsg != NULL) {
        ln   = link_node_malloc(s->pool, (void *) cmsg);
        link_list_append(s->msg_list, ln);

        msg_item_cnt++;
    }
}


void
delay_table_snd(uint64_t key, int fd)
{
    link_list        *msg_list;
    p_link_node       first;
    msg_server_t     *msg ;
    delay_sess_t     *s;

    s = (delay_sess_t *) hash_find(table, key);
    if (s == NULL || s->msg_list == NULL) {
        return; 
    }

    msg_list = s->msg_list;
    while (!link_list_is_empty(msg_list)) {
        first = link_list_pop_first(msg_list);
        msg = (first->data);

#if (TC_COMBINED)
        buffer_and_snd(fd, msg);
#else
        if (tc_socket_snd(fd, (char *) msg, MSG_SERVER_SIZE) == TC_ERR) {
            tc_intercept_release_tunnel(fd, NULL);
        }
#endif
        msg_delay_sent_cnt++;

        msg_item_free_cnt++;
        tc_pfree(s->pool, first);
    }

}


void
delay_table_destroy()
{
    if (table != NULL) {

        tc_log_info(LOG_NOTICE, 0, "destroy delay table,total:%u",
                table->total);
        tc_log_info(LOG_NOTICE, 0, "msg item free:%llu,total:%llu",
                msg_item_free_cnt, msg_item_cnt);
        tc_log_info(LOG_NOTICE, 0, "create msg list:%llu,free:%llu",
                msg_ls_cnt, msg_ls_free_cnt);
        tc_log_info(LOG_NOTICE, 0, "delay actual sent:%llu", 
                msg_delay_sent_cnt);
        table = NULL;
    }
}

