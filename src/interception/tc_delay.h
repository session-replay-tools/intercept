#ifndef  TC_DELAY_INCLUDED
#define  TC_DELAY_INCLUDED

#include <xcopy.h>
#include <intercept.h>

typedef struct delay_sess_s {
    uint64_t          key;
    link_list        *msg_list;
    tc_pool_t        *pool;
    tc_event_timer_t *evt;
}delay_sess_t;

void delay_table_init(tc_pool_t *pool, uint32_t size);
void delay_table_add(uint64_t key, struct msg_server_s *);
void delay_table_snd(uint64_t key, int fd);
void delay_table_destroy(void);

#endif /* TC_DELAY_INCLUDED */

