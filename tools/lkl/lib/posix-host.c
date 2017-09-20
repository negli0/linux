#include "./sim.h"
#include <stdlib.h>
#include <signal.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <lkl_host.h>

#include "../ns-3-dce/model/dce-semaphore.h"
#include "../ns-3-dce/model/dce-pthread.h"
#include "../ns-3-dce/model/dce-time.h"

struct lkl_mutex {
	pthread_mutex_t mutex;
};

struct lkl_sem {
	sem_t sem;
};

struct SimImported *g_imported;
struct SimKernel *g_kernel;

static void *sim_malloc(unsigned long size)
{
	return g_imported->malloc(g_kernel, size);
}

static void sim_free(void *buffer)
{
	g_imported->free(g_kernel, buffer);
}

static void print(const char *str, int len)
{
	// NOP
}

static void panic(void)
{
	// NOP
}

static struct lkl_sem* sem_alloc(int count)
{
	struct lkl_sem *sem;

	sem = g_imported->malloc(g_kernel, sizeof(struct lkl_sem));
	if (!sem) {
		return NULL;
	}
	if (g_imported->sem_init(g_kernel, (sem_t *)sem, 0, count) < 0) {
		lkl_printf("dce_sem_init: %s\n", strerror(errno));
		return NULL;
	}

	return sem;
}

static void sem_free(struct lkl_sem *sem)
{
	g_imported->sem_destroy(g_kernel, &sem->sem);
	g_imported->free(g_kernel, sem);
}

static void sem_up(struct lkl_sem *sem)
{
	g_imported->sem_post(g_kernel, (sem_t *)sem);
}

static void sem_down(struct lkl_sem *sem)
{
	int err;

	do {
		err = g_imported->sem_wait(g_kernel, &sem->sem);
	} while (err < 0 && errno == EINTR);

	if (err < 0 && errno != EINTR) {
		lkl_printf("sem_wait: %s\n", strerror(errno));
	}
}

static struct lkl_mutex* mutex_alloc(int recursive)
{
	struct lkl_mutex *_mutex = g_imported->malloc(g_kernel, sizeof(struct lkl_mutex));
	pthread_mutex_t *mutex = NULL;
	pthread_mutexattr_t attr;
	int ret;

	if (!_mutex) {
		return NULL;
	}

	if ((ret = g_imported->pthread_mutexattr_init(g_kernel, &attr)) < 0) {
		return NULL;
	}

	if (recursive) {
		ret = g_imported->pthread_mutexattr_settype(g_kernel, &attr, PTHREAD_MUTEX_RECURSIVE);
		if (ret < 0) {
			return NULL;
		}
	}

	if ((ret = g_imported->pthread_mutex_init(g_kernel, mutex, &attr)) < 0) {
		return NULL;
	}

	return _mutex;
}

static void mutex_free(struct lkl_mutex *_mutex)
{
	pthread_mutex_t *mutex = &_mutex->mutex;
	g_imported->pthread_mutex_destroy(g_kernel, mutex);
	sim_free(_mutex);
}

static void mutex_lock(struct lkl_mutex *mutex)
{
	// NOP
}

static void mutex_unlock(struct lkl_mutex *mutex)
{
	// NOP
}

static lkl_thread_t thread_create(void (*f)(void *), void *arg)
{
	// NOP
	
	return (lkl_thread_t) 0;
}

static void thread_detach(void)
{
	// NOP
}

static void thread_exit(void)
{
	// NOP
}

static int thread_join(lkl_thread_t tid)
{
	// NOP
	return 0;
}

static lkl_thread_t thread_self(void)
{
	return (lkl_thread_t)pthread_self();
}

static int thread_equal(lkl_thread_t a, lkl_thread_t b)
{
	// NOP
	return 0;
}

static struct lkl_tls_key* tls_alloc(void (*destructor)(void *))
{
	// NOP
	return NULL;
}

static void tls_free(struct lkl_tls_key *key)
{
	// NOP
}

static int tls_set(struct lkl_tls_key *key, void *data)
{
	// NOP
	return 0;
}

static void* tls_get(struct lkl_tls_key *key)
{
	// NOP
	return NULL;
}

static unsigned long long _time(void)
{
	struct timespec ts;
	g_imported->clock_gettime(g_kernel, CLOCK_MONOTONIC, &ts);

	return 1e9*ts.tv_sec + ts.tv_nsec;
}

static void* timer_alloc(void (*fn)(void *), void *arg)
{
	// NOP
	return NULL;
}

static int timer_set_oneshot(void *timer, unsigned long delta)
{
	// NOP
	return 0;
}

static void timer_free(void *timer)
{
	// NOP
}

static void* lkl_ioremap(long addr, int size)
{
	// NOP
	return NULL;
}

static int lkl_iomem_access(const __volatile__ void *addr, void *val, int size,
		int write)
{
	// NOP
	return 0;
}

static long gettid(void)
{
	// NOP
	return 0;
}

static void jmp_buf_set(struct lkl_jmp_buf *jmpb, void (*f)(void))
{
	// NOP
}

static void jmp_buf_longjmp(struct lkl_jmp_buf *jmpb, int val)
{
	// NOP
}


struct lkl_host_operations lkl_host_ops = {
	.print = print,
	.panic = panic,
	.thread_create = thread_create,
	.thread_detach = thread_detach,
	.thread_exit = thread_exit,
	.thread_join = thread_join,
	.thread_self = thread_self,
	.thread_equal = thread_equal,
	.sem_alloc = sem_alloc,
	.sem_free = sem_free,
	.sem_up = sem_up,
	.sem_down = sem_down,
	.mutex_alloc = mutex_alloc,
	.mutex_free = mutex_free,
	.mutex_lock = mutex_lock,
	.mutex_unlock = mutex_unlock,
	.tls_alloc = tls_alloc,
	.tls_free = tls_free,
	.tls_set = tls_set,
	.tls_get = tls_get,
	.time = _time,
	.timer_alloc = timer_alloc,
	.timer_set_oneshot = timer_set_oneshot,
	.timer_free = timer_free,
	.mem_alloc = sim_malloc,
	.mem_free = sim_free,
	.ioremap = lkl_ioremap,
	.iomem_access = lkl_iomem_access,
	.virtio_devices = lkl_virtio_devs,
	.gettid = gettid,
	.jmp_buf_set = jmp_buf_set,
	.jmp_buf_longjmp = jmp_buf_longjmp,
};

static int fd_get_capacity(struct lkl_disk disk, unsigned long long *res)
{
	return 0;
}

static int blk_request(struct lkl_disk disk, struct lkl_blk_req *req)
{
	return 0;
}

struct lkl_dev_blk_ops lkl_dev_blk_ops = {
	.get_capacity = fd_get_capacity,
	.request = blk_request,
};

