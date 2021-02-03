
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


static ngx_inline void* ngx_palloc_small(ngx_pool_t* pool, size_t size,
	ngx_uint_t align);
static void* ngx_palloc_block(ngx_pool_t* pool, size_t size);
static void* ngx_palloc_large(ngx_pool_t* pool, size_t size);

/**
 * 创建一个内存池
 */
ngx_pool_t*
ngx_create_pool(size_t size, ngx_log_t* log)
{
	ngx_pool_t* p;
	/**
	 * 相当于分配一块内存 ngx_alloc(size, log)
	 */
	p = ngx_memalign(NGX_POOL_ALIGNMENT, size, log);
	if (p == NULL) {
		return NULL;
	}
	/**
	 * Nginx会分配一块大内存，其中内存头部存放ngx_pool_t本身内存池的数据结构
	 * ngx_pool_data_t	p->d 存放内存池的数据部分（适合小于p->max的内存块存储）
	 * p->large 存放大内存块列表
	 * p->cleanup 存放可以被回调函数清理的内存块（该内存块不一定会在内存池上面分配）
	 */
	p->d.last = (u_char*)p + sizeof(ngx_pool_t); //内存开始地址，指向ngx_pool_t结构体之后数据取起始位置
	p->d.end = (u_char*)p + size; //内存结束地址
	p->d.next = NULL; //下一个ngx_pool_t 内存池地址
	p->d.failed = 0; //失败次数

	size = size - sizeof(ngx_pool_t);
	p->max = (size < NGX_MAX_ALLOC_FROM_POOL) ? size : NGX_MAX_ALLOC_FROM_POOL;

	/* 只有缓存池的父节点，才会用到下面的这些  ，子节点只挂载在p->d.next,并且只负责p->d的数据内容*/
	p->current = p;
	p->chain = NULL;
	p->large = NULL;
	p->cleanup = NULL;
	p->log = log;

	return p;
}


/**
 * 销毁内存池。
 */
void
ngx_destroy_pool(ngx_pool_t* pool)
{
	ngx_pool_t* p, * n;
	ngx_pool_large_t* l;
	ngx_pool_cleanup_t* c;
	/* 首先清理pool->cleanup链表 */
	for (c = pool->cleanup; c; c = c->next) {
		/* handler 为一个清理的回调函数 */
		if (c->handler) {
			ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, pool->log, 0,
				"run cleanup: %p", c);
			c->handler(c->data);
		}
	}

#if (NGX_DEBUG)

	/*
	 * we could allocate the pool->log from this pool
	 * so we cannot use this log while free()ing the pool
	 */
	 /* 清理pool->large链表（pool->large为单独的大数据内存块）  */
	for (l = pool->large; l; l = l->next) {
		ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, pool->log, 0, "free: %p", l->alloc);
	}

	for (p = pool, n = pool->d.next; /* void */; p = n, n = n->d.next) {
		ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, pool->log, 0,
			"free: %p, unused: %uz", p, p->d.end - p->d.last);

		if (n == NULL) {
			break;
		}
	}

#endif

	for (l = pool->large; l; l = l->next) {
		if (l->alloc) {
			ngx_free(l->alloc);
		}
	}
	/* 对内存池的data数据区域进行释放 */
	for (p = pool, n = pool->d.next; /* void */; p = n, n = n->d.next) {
		ngx_free(p);

		if (n == NULL) {
			break;
		}
	}
}


void
ngx_reset_pool(ngx_pool_t* pool)
{
	ngx_pool_t* p;
	ngx_pool_large_t* l;

	for (l = pool->large; l; l = l->next) {
		if (l->alloc) {
			ngx_free(l->alloc);
		}
	}

	for (p = pool; p; p = p->d.next) {
		p->d.last = (u_char*)p + sizeof(ngx_pool_t);
		p->d.failed = 0;
	}

	pool->current = pool;
	pool->chain = NULL;
	pool->large = NULL;
}

/**
* 分配内存对齐NGX_ALIGNMENT的块align=1
*/
void*
ngx_palloc(ngx_pool_t* pool, size_t size)
{
#if !(NGX_DEBUG_PALLOC)
	if (size <= pool->max) {
		//分配小块内存
		return ngx_palloc_small(pool, size, 1);
	}
#endif
	//分配大块内存
	return ngx_palloc_large(pool, size);
}

/**
* 分配内存大小size的块，不做对齐align=0
*/
void*
ngx_pnalloc(ngx_pool_t* pool, size_t size)
{
#if !(NGX_DEBUG_PALLOC)
	if (size <= pool->max) {
		return ngx_palloc_small(pool, size, 0);
	}
#endif

	return ngx_palloc_large(pool, size);
}


static ngx_inline void*
ngx_palloc_small(ngx_pool_t* pool, size_t size, ngx_uint_t align)
{
	u_char* m;
	ngx_pool_t* p;

	p = pool->current;

	do {
		m = p->d.last;

		if (align) {
			//内存对齐NGX_ALIGNMENT的块align=1
			m = ngx_align_ptr(m, NGX_ALIGNMENT);
		}
		/*然后计算end值减去这个偏移指针位置的大小是否满足索要分配的size大小，
		如果满足，则移动last指针位置，并返回所分配到的内存地址的起始地址；*/
		if ((size_t)(p->d.end - m) >= size) {
			p->d.last = m + size;

			return m;
		}
		//如果不满足，则查找下一个链。
		p = p->d.next;

	} while (p);
	/*
	如果遍历完整个内存池链表均未找到合适大小的内存块供分配，则执行ngx_palloc_block()来分配。
	ngx_palloc_block()函数为该内存池再分配一个block，该block的大小为链表中前面每一个block大小的值。
	一个内存池是由多个block链接起来的。分配成功后，将该block链入该poll链的最后，
	同时，为所要分配的size大小的内存进行分配，并返回分配内存的起始地址。
	*/
	return ngx_palloc_block(pool, size);
}


static void*
ngx_palloc_block(ngx_pool_t* pool, size_t size)
{
	u_char* m;
	size_t       psize;
	ngx_pool_t* p, * new;
	//计算新开辟的内存池大小，大小和之前的pool一致
	psize = (size_t)(pool->d.end - (u_char*)pool);
	/*
	新开辟一块内存池
	执行按NGX_POOL_ALIGNMENT对齐方式的内存分配，假设能够分配成功，则继续执行后续代码片段。
	*/
	m = ngx_memalign(NGX_POOL_ALIGNMENT, psize, pool->log);
	if (m == NULL) {
		return NULL;
	}
	//初始化内存池的一些参数
	new = (ngx_pool_t*)m;

	new->d.end = m + psize;
	new->d.next = NULL;
	new->d.failed = 0;
	//让m指向该块内存ngx_pool_data_t结构体之后数据区起始位置 
	m += sizeof(ngx_pool_data_t);
	//m内存对齐到NGX_ALIGNMENT
	m = ngx_align_ptr(m, NGX_ALIGNMENT);
	new->d.last = m + size;
	//失败4次以上移动current指针
	for (p = pool->current; p->d.next; p = p->d.next) {
		if (p->d.failed++ > 4) {
			pool->current = p->d.next;
		}
	}

	p->d.next = new;

	return m;
}


static void*
ngx_palloc_large(ngx_pool_t* pool, size_t size)
{
	//这是一个static的函数，说明外部函数不会随便调用，而是提供给内部分配调用的，  
	//即nginx在进行内存分配需求时，不会自行去判断是否是大块内存还是小块内存，  
	//而是交由内存分配函数去判断，对于用户需求来说是完全透明的。
	void* p;
	ngx_uint_t         n;
	ngx_pool_large_t* large;
	//ngx_alloc是一个简单的封装，直接调用的malloc
	p = ngx_alloc(size, pool->log);
	if (p == NULL) {
		return NULL;
	}

	n = 0;
	/*将分配的内存链入pool的large链中，
      这里指原始pool在之前已经分配过large内存的情况。
	  */
	for (large = pool->large; large; large = large->next) {
		if (large->alloc == NULL) {
			large->alloc = p;
			return p;
		}

		if (n++ > 3) {
			break;
		}
	}
	/*当原始pool中没有large块时,比如新建的一块pool
      分配一块ngx_pool_large_t结构体来管理large内存
	*/
	large = ngx_palloc_small(pool, sizeof(ngx_pool_large_t), 1);
	if (large == NULL) {
		ngx_free(p);
		return NULL;
	}
	//将这块large加入pool
	large->alloc = p;
	large->next = pool->large;
	pool->large = large;

	return p;
}


void*
ngx_pmemalign(ngx_pool_t* pool, size_t size, size_t alignment)
{
	void* p;
	ngx_pool_large_t* large;

	p = ngx_memalign(alignment, size, pool->log);
	if (p == NULL) {
		return NULL;
	}

	large = ngx_palloc_small(pool, sizeof(ngx_pool_large_t), 1);
	if (large == NULL) {
		ngx_free(p);
		return NULL;
	}

	large->alloc = p;
	large->next = pool->large;
	pool->large = large;

	return p;
}


ngx_int_t
ngx_pfree(ngx_pool_t* pool, void* p)
{
	ngx_pool_large_t* l;

	for (l = pool->large; l; l = l->next) {
		if (p == l->alloc) {
			ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, pool->log, 0,
				"free: %p", l->alloc);
			ngx_free(l->alloc);
			l->alloc = NULL;

			return NGX_OK;
		}
	}

	return NGX_DECLINED;
}


void*
ngx_pcalloc(ngx_pool_t* pool, size_t size)
{
	void* p;

	p = ngx_palloc(pool, size);
	if (p) {
		ngx_memzero(p, size);
	}

	return p;
}


ngx_pool_cleanup_t*
ngx_pool_cleanup_add(ngx_pool_t* p, size_t size)
{
	ngx_pool_cleanup_t* c;

	c = ngx_palloc(p, sizeof(ngx_pool_cleanup_t));
	if (c == NULL) {
		return NULL;
	}

	if (size) {
		c->data = ngx_palloc(p, size);
		if (c->data == NULL) {
			return NULL;
		}

	}
	else {
		c->data = NULL;
	}

	c->handler = NULL;
	c->next = p->cleanup;

	p->cleanup = c;

	ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, p->log, 0, "add cleanup: %p", c);

	return c;
}


void
ngx_pool_run_cleanup_file(ngx_pool_t* p, ngx_fd_t fd)
{
	ngx_pool_cleanup_t* c;
	ngx_pool_cleanup_file_t* cf;

	for (c = p->cleanup; c; c = c->next) {
		if (c->handler == ngx_pool_cleanup_file) {

			cf = c->data;

			if (cf->fd == fd) {
				c->handler(cf);
				c->handler = NULL;
				return;
			}
		}
	}
}


void
ngx_pool_cleanup_file(void* data)
{
	ngx_pool_cleanup_file_t* c = data;

	ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, c->log, 0, "file cleanup: fd:%d",
		c->fd);

	if (ngx_close_file(c->fd) == NGX_FILE_ERROR) {
		ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
			ngx_close_file_n " \"%s\" failed", c->name);
	}
}


void
ngx_pool_delete_file(void* data)
{
	ngx_pool_cleanup_file_t* c = data;

	ngx_err_t  err;

	ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, c->log, 0, "file cleanup: fd:%d %s",
		c->fd, c->name);

	if (ngx_delete_file(c->name) == NGX_FILE_ERROR) {
		err = ngx_errno;

		if (err != NGX_ENOENT) {
			ngx_log_error(NGX_LOG_CRIT, c->log, err,
				ngx_delete_file_n " \"%s\" failed", c->name);
		}
	}

	if (ngx_close_file(c->fd) == NGX_FILE_ERROR) {
		ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
			ngx_close_file_n " \"%s\" failed", c->name);
	}
}


#if 0

static void*
ngx_get_cached_block(size_t size)
{
	void* p;
	ngx_cached_block_slot_t* slot;

	if (ngx_cycle->cache == NULL) {
		return NULL;
	}

	slot = &ngx_cycle->cache[(size + ngx_pagesize - 1) / ngx_pagesize];

	slot->tries++;

	if (slot->number) {
		p = slot->block;
		slot->block = slot->block->next;
		slot->number--;
		return p;
	}

	return NULL;
}

#endif
