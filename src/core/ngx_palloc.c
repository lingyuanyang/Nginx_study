
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
 * ����һ���ڴ��
 */
ngx_pool_t*
ngx_create_pool(size_t size, ngx_log_t* log)
{
	ngx_pool_t* p;
	/**
	 * �൱�ڷ���һ���ڴ� ngx_alloc(size, log)
	 */
	p = ngx_memalign(NGX_POOL_ALIGNMENT, size, log);
	if (p == NULL) {
		return NULL;
	}
	/**
	 * Nginx�����һ����ڴ棬�����ڴ�ͷ�����ngx_pool_t�����ڴ�ص����ݽṹ
	 * ngx_pool_data_t	p->d ����ڴ�ص����ݲ��֣��ʺ�С��p->max���ڴ��洢��
	 * p->large ��Ŵ��ڴ���б�
	 * p->cleanup ��ſ��Ա��ص�����������ڴ�飨���ڴ�鲻һ�������ڴ��������䣩
	 */
	p->d.last = (u_char*)p + sizeof(ngx_pool_t); //�ڴ濪ʼ��ַ��ָ��ngx_pool_t�ṹ��֮������ȡ��ʼλ��
	p->d.end = (u_char*)p + size; //�ڴ������ַ
	p->d.next = NULL; //��һ��ngx_pool_t �ڴ�ص�ַ
	p->d.failed = 0; //ʧ�ܴ���

	size = size - sizeof(ngx_pool_t);
	p->max = (size < NGX_MAX_ALLOC_FROM_POOL) ? size : NGX_MAX_ALLOC_FROM_POOL;

	/* ֻ�л���صĸ��ڵ㣬�Ż��õ��������Щ  ���ӽڵ�ֻ������p->d.next,����ֻ����p->d����������*/
	p->current = p;
	p->chain = NULL;
	p->large = NULL;
	p->cleanup = NULL;
	p->log = log;

	return p;
}


/**
 * �����ڴ�ء�
 */
void
ngx_destroy_pool(ngx_pool_t* pool)
{
	ngx_pool_t* p, * n;
	ngx_pool_large_t* l;
	ngx_pool_cleanup_t* c;
	/* ��������pool->cleanup���� */
	for (c = pool->cleanup; c; c = c->next) {
		/* handler Ϊһ������Ļص����� */
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
	 /* ����pool->large����pool->largeΪ�����Ĵ������ڴ�飩  */
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
	/* ���ڴ�ص�data������������ͷ� */
	for (p = pool, n = pool->d.next; /* void */; p = n, n = n->d.next) {
		ngx_free(p);

		if (n == NULL) {
			break;
		}
	}
}


/**
* �����ڴ��
*/
void
ngx_reset_pool(ngx_pool_t* pool)
{
	ngx_pool_t* p;
	ngx_pool_large_t* l;

	/* ����pool->large����pool->largeΪ�����Ĵ������ڴ�飩  */
	for (l = pool->large; l; l = l->next) {
		if (l->alloc) {
			ngx_free(l->alloc);
		}
	}

	/* ѭ�����������ڴ��data����� p->d.last��data�������ݲ�������*/
	for (p = pool; p; p = p->d.next) {
		p->d.last = (u_char*)p + sizeof(ngx_pool_t);
		p->d.failed = 0;
	}

	pool->current = pool;
	pool->chain = NULL;
	pool->large = NULL;
}

/**
* �����ڴ����NGX_ALIGNMENT�Ŀ�align=1
* �ڴ�ط���һ���ڴ棬����void����ָ��
*/
void*
ngx_palloc(ngx_pool_t* pool, size_t size)
{
#if !(NGX_DEBUG_PALLOC)
	/* �ж�ÿ�η�����ڴ��С���������pool->max�����ƣ�����Ҫ�ߴ������ڴ������� */
	if (size <= pool->max) {
		//����С���ڴ�
		return ngx_palloc_small(pool, size, 1);
	}
#endif
	//�������ڴ�
	return ngx_palloc_large(pool, size);
}

/**
* �����ڴ��Сsize�Ŀ飬��������align=0
* �ڴ�ط���һ���ڴ棬����void����ָ��
* �����Ƕ������
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
	/*
	* ѭ����ȡ�������p->d.next�ĸ�����ngx_pool_t�ڵ㣬
	* ���ʣ��Ŀռ��������size���򷵻�ָ���ַ
	*
	* ��ߵ�ѭ����ʵ�������ֻ��4�Σ�������Կ�ngx_palloc_block����
	* */
	do {
		m = p->d.last;

		if (align) {
			//�ڴ����NGX_ALIGNMENT�Ŀ�align=1
			/* �������,����ʧ�ڴ棬��������ڴ�ʹ���ٶ� */
			m = ngx_align_ptr(m, NGX_ALIGNMENT);
		}
		/*Ȼ�����endֵ��ȥ���ƫ��ָ��λ�õĴ�С�Ƿ�������Ҫ�����size��С��
		������㣬���ƶ�lastָ��λ�ã������������䵽���ڴ��ַ����ʼ��ַ��*/
		if ((size_t)(p->d.end - m) >= size) {
			p->d.last = m + size;

			return m;
		}
		//��������㣬�������һ������
		p = p->d.next;

	} while (p);
	/*
	��������������ڴ�������δ�ҵ����ʴ�С���ڴ�鹩���䣬��ִ��ngx_palloc_block()�����䡣
	ngx_palloc_block()����Ϊ���ڴ���ٷ���һ��block����block�Ĵ�СΪ������ǰ��ÿһ��block��С��ֵ��
	һ���ڴ�����ɶ��block���������ġ�����ɹ��󣬽���block�����poll�������
	ͬʱ��Ϊ��Ҫ�����size��С���ڴ���з��䣬�����ط����ڴ����ʼ��ַ��
	*/
	return ngx_palloc_block(pool, size);
}

/**
 * ����һ���µĻ���� ngx_pool_t
 * �µĻ���ػ������������ص� �������� ��pool->d->next��
 */
static void*
ngx_palloc_block(ngx_pool_t* pool, size_t size)
{
	u_char* m;
	size_t       psize;
	ngx_pool_t* p, * new;
	//�����¿��ٵ��ڴ�ش�С����С��֮ǰ��poolһ��
	psize = (size_t)(pool->d.end - (u_char*)pool);
	/*
	�¿���һ���ڴ��
	ִ�а�NGX_POOL_ALIGNMENT���뷽ʽ���ڴ���䣬�����ܹ�����ɹ��������ִ�к�������Ƭ�Ρ�
	*/
	m = ngx_memalign(NGX_POOL_ALIGNMENT, psize, pool->log);
	if (m == NULL) {
		return NULL;
	}
	//��ʼ���ڴ�ص�һЩ����
	new = (ngx_pool_t*)m;

	new->d.end = m + psize;
	new->d.next = NULL;
	new->d.failed = 0;
	//��mָ��ÿ��ڴ�ngx_pool_data_t�ṹ��֮����������ʼλ��
	/* ����size��С���ڴ�飬����mָ���ַ */
	m += sizeof(ngx_pool_data_t);
	//m�ڴ���뵽NGX_ALIGNMENT
	m = ngx_align_ptr(m, NGX_ALIGNMENT);
	new->d.last = m + size;
	//ʧ��4�������ƶ�currentָ��
	/**
	 * ����ص�pool���ݽṹ������ӽڵ��ngx_pool_t���ݽṹ
	 * �ӽڵ��ngx_pool_t���ݽṹ��ֻ�õ�pool->d�Ľṹ��ֻ��������
	 * ÿ���һ���ӽڵ㣬p->d.failed�ͻ�+1������ӳ���4���ӽڵ��ʱ��
	 * pool->current��ָ�����µ��ӽڵ��ַ
	 *
	 * ����߼���Ҫ��Ϊ�˷�ֹpool�ϵ��ӽڵ���࣬����ÿ��ngx_pallocѭ��pool->d.next����
	 * ��pool->current���ó����µ��ӽڵ�֮��ÿ�����ѭ��4�Σ�����ȥ�����������������
	 */
	for (p = pool->current; p->d.next; p = p->d.next) {
		if (p->d.failed++ > 4) {
			pool->current = p->d.next;
		}
	}

	p->d.next = new;

	return m;
}



/**
 * ��������ڴ���С����pool->max���Ƶ�ʱ��,��Ҫ������pool->large��
 */
static void*
ngx_palloc_large(ngx_pool_t* pool, size_t size)
{
	//����һ��static�ĺ�����˵���ⲿ�������������ã������ṩ���ڲ�������õģ�  
	//��nginx�ڽ����ڴ��������ʱ����������ȥ�ж��Ƿ��Ǵ���ڴ滹��С���ڴ棬  
	//���ǽ����ڴ���亯��ȥ�жϣ������û�������˵����ȫ͸���ġ�
	void* p;
	ngx_uint_t         n;
	ngx_pool_large_t* large;
	//ngx_alloc��һ���򵥵ķ�װ��ֱ�ӵ��õ�malloc
	/* ����һ���µĴ��ڴ�� */
	p = ngx_alloc(size, pool->log);
	if (p == NULL) {
		return NULL;
	}

	n = 0;
	/*��������ڴ�����pool��large���У�
      ����ָԭʼpool��֮ǰ�Ѿ������large�ڴ�������
	  */
	 /* ȥpool->large�����ϲ�ѯ�Ƿ���NULL�ģ�ֻ�����������²�ѯ3�Σ���Ҫ�жϴ����ݿ��Ƿ��б��ͷŵģ����û����ֻ������*/
	for (large = pool->large; large; large = large->next) {
		if (large->alloc == NULL) {
			large->alloc = p;
			return p;
		}

		if (n++ > 3) {
			break;
		}
	}
	/*��ԭʼpool��û��large��ʱ,�����½���һ��pool
      ����һ��ngx_pool_large_t�ṹ��������large�ڴ�
	*/
	large = ngx_palloc_small(pool, sizeof(ngx_pool_large_t), 1);
	if (large == NULL) {
		ngx_free(p);//�������ʧ�ܣ�ɾ���ڴ��
		return NULL;
	}
	//�����large����pool
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


/**
 * ���ڴ���ͷ�  pool->large
 */
ngx_int_t
ngx_pfree(ngx_pool_t* pool, void* p)
{
	ngx_pool_large_t* l;
	/* ��pool->large����ѭ������������ֻ�ͷ��������򣬲��ͷ�ngx_pool_large_t���ݽṹ*/
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

/**
 * ����һ���������ڻص����������ڴ����ڴ�
 * �ڴ���Ծ���p->d��p->large��
 *
 * ngx_pool_t�е�cleanup�ֶι�����һ������������������ÿһ���¼��һ���������Ҫ�ͷŵ���Դ��
 * �������������ÿ���ڵ�����������Դ���ȥ�ͷţ�����˵���ġ���Ҳ���ṩ�˷ǳ��������ԡ�
 * ��ζ�ţ�ngx_pool_t���������Թ����ڴ棬ͨ��������ƣ�Ҳ���Թ����κ���Ҫ�ͷŵ���Դ��
 * ���磬�ر��ļ�������ɾ���ļ��ȵȵġ��������ǿ�һ���������ÿ���ڵ������
 *
 * һ������������
 * 1. �ļ�������
 * 2. �ⲿ�Զ���ص����������������ڴ�
 */
ngx_pool_cleanup_t*
ngx_pool_cleanup_add(ngx_pool_t* p, size_t size)
{
	ngx_pool_cleanup_t* c;
	/* ����һ��ngx_pool_cleanup_t */
	c = ngx_palloc(p, sizeof(ngx_pool_cleanup_t));
	if (c == NULL) {
		return NULL;
	}

	/* ���size !=0 ��pool->d��pool->large����һ���ڴ�� */
	if (size) {
		c->data = ngx_palloc(p, size);
		if (c->data == NULL) {
			return NULL;
		}

	}
	else {
		c->data = NULL;
	}
	/* handlerΪ�ص����� */
	c->handler = NULL;
	c->next = p->cleanup;

	p->cleanup = c;

	ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, p->log, 0, "add cleanup: %p", c);

	return c;
}

/**
 * ��� p->cleanup�����ϵ��ڴ�飨��Ҫ���ļ���������
 * �ص�������ngx_pool_cleanup_file
 */
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

/**
 * �ر��ļ��ص�����
 * ngx_pool_run_cleanup_file����ִ�е�ʱ�����˴˺�����Ϊ�ص������ģ����ᱻ����
 */
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

/**
 * ɾ���ļ��ص�����
 */
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
