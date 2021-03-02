
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


ngx_uint_t  ngx_pagesize;
ngx_uint_t  ngx_pagesize_shift;
ngx_uint_t  ngx_cacheline_size;

/**
 * ��װ��malloc�����������������־ malloc = Memory_ALLOCation
 */
void *
ngx_alloc(size_t size, ngx_log_t *log)//1024(Byte), 0x80d1c4c
{
    void  *p;
    //分配一块内存
    //malloc是系统自带的方法用来分配内存，但是频繁使用这些函数分配和释放内存，会导致内存碎片，不容易让系统直接回收内存
    //分配一块内存
    p = malloc(size);
    //����ʧ��
    if (p == NULL) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                      "malloc(%uz) failed", size);
    }
    //����ɹ�
    ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, log, 0, "malloc: %p:%uz", p, size);

    return p;
}

/**
 * ����ngx_alloc����(calloc=call_alloc)���������ɣ������ngx_memzero���������ڴ������Ϊ0
 * #define ngx_memzero(buf, n)  (void) memset(buf, 0, n)
 */
void *
ngx_calloc(size_t size, ngx_log_t *log)
{
    void  *p;
    //调用内存分配函数ngx_alloc（上面那个）
    //调用内存分配函数
    p = ngx_alloc(size, log);

    if (p) {
        //���ڴ��ȫ������Ϊ0
        ngx_memzero(p, size);
    }

    return p;
}


#if (NGX_HAVE_POSIX_MEMALIGN)

void *
ngx_memalign(size_t alignment, size_t size, ngx_log_t *log)
{
    void  *p;
    int    err;

    err = posix_memalign(&p, alignment, size);

    if (err) {
        ngx_log_error(NGX_LOG_EMERG, log, err,
                      "posix_memalign(%uz, %uz) failed", alignment, size);
        p = NULL;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_ALLOC, log, 0,
                   "posix_memalign: %p:%uz @%uz", p, size, alignment);

    return p;
}

#elif (NGX_HAVE_MEMALIGN)

void *
ngx_memalign(size_t alignment, size_t size, ngx_log_t *log)
{
    void  *p;

    p = memalign(alignment, size);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                      "memalign(%uz, %uz) failed", alignment, size);
    }

    ngx_log_debug3(NGX_LOG_DEBUG_ALLOC, log, 0,
                   "memalign: %p:%uz @%uz", p, size, alignment);

    return p;
}

#endif
