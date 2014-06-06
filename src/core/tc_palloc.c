
#include <xcopy.h>

static void *tc_palloc_block(tc_pool_t *pool, size_t size);
static void *tc_palloc_large(tc_pool_t *pool, size_t size);


tc_pool_t *
tc_create_pool(size_t size, size_t pool_max)
{
    tc_pool_t  *p;

    if (size < TC_MIN_POOL_SIZE) {
        size = TC_MIN_POOL_SIZE;
    }

    p = tc_memalign(TC_POOL_ALIGNMENT, size);
    if (p != NULL) {
        p->d.last = (u_char *) p + sizeof(tc_pool_t);
        p->d.end = (u_char *) p + size;
        p->d.next = NULL;
        p->d.failed = 0;

        size = size - sizeof(tc_pool_t);
        
        if (pool_max && size >= pool_max) {
            p->max = pool_max;
        } else {
            p->max = (size < TC_MAX_ALLOC_FROM_POOL) ? 
                size : TC_MAX_ALLOC_FROM_POOL;
        }

        p->current = p;
        p->large = NULL;
        p->loop = NULL;

    }
    
    return p;
}


void 
create_pool_loop(tc_pool_t *p, size_t size)
{
    p->loop = tc_pcalloc(p, sizeof(tc_pool_loop_t));

    if (p->loop) {
        p->loop->start = tc_pcalloc(p, size);
        if (p->loop->start) {
            p->loop->end = p->loop->start + size;
            p->loop->last = p->loop->start;
            p->loop->last_freed = NULL;
            p->loop->wrap_around = 0;
        } else {
            tc_pfree(p, p->loop);
            p->loop = NULL;
        }
    }
}


void
tc_destroy_pool(tc_pool_t *pool)
{
    tc_pool_t          *p, *n;
    tc_pool_large_t    *l;

    for (l = pool->large; l; l = l->next) {

        if (l->alloc) {
            tc_free(l->alloc);
        }
    }

    for (p = pool, n = pool->d.next; /* void */; p = n, n = n->d.next) {
        tc_free(p);

        if (n == NULL) {
            break;
        }
    }
}


void *
tc_palloc(tc_pool_t *pool, size_t size)
{
    u_char     *m;
    tc_pool_t  *p;

    if (size <= pool->max) {

        p = pool->current;

        do {
            m = tc_align_ptr(p->d.last, TC_ALIGNMENT);

            if ((size_t) (p->d.end - m) >= size) {
                p->d.last = m + size;

                return m;
            }

            p = p->d.next;

        } while (p);

        return tc_palloc_block(pool, size);
    }

    return tc_palloc_large(pool, size);
}


void *
tc_pnalloc(tc_pool_t *pool, size_t size)
{
    u_char     *m;
    tc_pool_t  *p;

    if (size <= pool->max) {

        p = pool->current;

        do {
            m = p->d.last;

            if ((size_t) (p->d.end - m) >= size) {
                p->d.last = m + size;

                return m;
            }

            p = p->d.next;

        } while (p);

        return tc_palloc_block(pool, size);
    }

    return tc_palloc_large(pool, size);
}


void *
tc_palloc_loop(tc_pool_t *pool, size_t size)
{
    u_char         *m, *end;
    tc_pool_loop_t *loop;

    loop = pool->loop;

    if (size <= pool->max && loop) {

        if (!loop->wrap_around) {
            end = loop->end;
        } else {
            end = loop->last_freed;
            if (end == NULL) {
                return tc_palloc(pool, size);
            }
        }

        do {
            m = tc_align_ptr(loop->last, TC_ALIGNMENT);

            if (m > end) {
                return tc_palloc(pool, size);
            }

            if ((size_t) (end - m) >= size) {
                loop->last = m + size;
                return m;
            }

            if (!loop->wrap_around) {
                loop->wrap_around = 1;
                loop->last = loop->start;
                end = loop->last_freed;
                if (end == NULL) {
                    return tc_palloc(pool, size);
                }
            } else {
                return tc_palloc(pool, size);
            }

        } while (true);

    } else {
        return tc_palloc(pool, size);
    }
}


static void *
tc_palloc_block(tc_pool_t *pool, size_t size)
{
    u_char      *m;
    size_t       psize;
    tc_pool_t  *p, *new, *current;

    psize = (size_t) (pool->d.end - (u_char *) pool);

    m = tc_memalign(TC_POOL_ALIGNMENT, psize);
    if (m != NULL) {
        new = (tc_pool_t *) m;

        new->d.end = m + psize;
        new->d.next = NULL;
        new->d.failed = 0;

        m += sizeof(tc_pool_data_t);
        m = tc_align_ptr(m, TC_ALIGNMENT);
        new->d.last = m + size;

        current = pool->current;

        for (p = current; p->d.next; p = p->d.next) {
            if (p->d.failed++ > 4) {
                current = p->d.next;
            }
        }

        p->d.next = new;

        pool->current = current ? current : new;
    }

    return m;
}


static void *
tc_palloc_large(tc_pool_t *pool, size_t size)
{
    void              *p;
    tc_uint_t         n;
    tc_pool_large_t  *large;

    p = tc_alloc(size);
    if (p != NULL) {

        n = 0;

        for (large = pool->large; large; large = large->next) {
            if (large->alloc == NULL) {
                large->alloc = p;
                return p;
            }

            if (n++ > 3) {
                break;
            }
        }

        large = tc_palloc(pool, sizeof(tc_pool_large_t));
        if (large == NULL) {
            tc_free(p);
            return NULL;
        }

        large->alloc = p;
        large->next = pool->large;
        pool->large = large;
    }

    return p;
}


void *
tc_pmemalign(tc_pool_t *pool, size_t size, size_t alignment)
{
    void              *p;
    tc_pool_large_t  *large;

    p = tc_memalign(alignment, size);
    if (p != NULL) {

        large = tc_palloc(pool, sizeof(tc_pool_large_t));
        if (large == NULL) {
            tc_free(p);
            return NULL;
        }

        large->alloc = p;
        large->next = pool->large;
        pool->large = large;
    }

    return p;
}


tc_int_t
tc_pfree(tc_pool_t *pool, void *p)
{
    tc_pool_large_t  *l;

    for (l = pool->large; l; l = l->next) {
        if (p == l->alloc) {
            tc_free(l->alloc);
            l->alloc = NULL;

            return TC_OK;
        }
    }

    return TC_DECLINED;
}


tc_int_t
tc_pool_loop_free(tc_pool_t *pool, void *p)
{
    if (pool->loop) {
        if (pool->loop->start <= (u_char *) p && 
                pool->loop->end > (u_char *) p) 
        {
            if (pool->loop->last_freed > (u_char *) p) {
                pool->loop->wrap_around = 0;
            }
            pool->loop->last_freed = p;

            return TC_OK;

        } else {

            return tc_pfree(pool, p);
        }

    } else {

        return tc_pfree(pool, p);
    }
}


void *
tc_pcalloc(tc_pool_t *pool, size_t size)
{
    void *p;

    p = tc_palloc(pool, size);
    if (p) {
        tc_memzero(p, size);
    }

    return p;
}


