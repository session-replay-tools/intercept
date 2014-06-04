#ifndef  TC_TCION_INCLUDED
#define  TC_TCION_INCLUDED

int server_init(tc_event_loop_t *event_loop, char *ip, uint16_t port);
void server_run();
#if (TC_COMBINED)
void server_push(tc_event_timer_t *evt);
#endif
void server_stat(tc_event_timer_t *evt);
void server_over();

#endif /* TC_TCION_INCLUDED */

