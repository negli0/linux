#include <stdlib.h>
#include <signal.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <lkl_host.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/list.h>

#include "./net-next-sim-2.6.36/arch/sim/include/sim.h"
#include "./net-next-sim-2.6.36/arch/sim/include/sim-init.h"
#include "./net-next-sim-2.6.36/arch/sim/include/sim-types.h"
#include "./net-next-sim-2.6.36/arch/sim/include/sim-printf.h"
#include "./net-next-sim-2.6.36/arch/sim/include/sim-assert.h"

struct SimTask {
	struct task_struct kernel_task;
	void *private;
};

extern struct SimTask *sim_task_create(void *private, unsigned long pid);

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
	// NOP
	struct lkl_sem *sem;
	return NULL;
}

static void sem_free(struct lkl_sem *sem)
{
	// NOP
}

static void sem_up(struct lkl_sem *sem)
{
	// NOP
}

static void sem_down(struct lkl_sem *sem)
{
	// NOP
}

static struct lkl_mutex* mutex_alloc(int recursive)
{
	// NOP
	return NULL;
}

static void mutex_free(struct lkl_mutex *mutex)
{
	// NOP
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
	struct SimTask task;
	
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
}

static lkl_thread_t thread_self(void)
{
	// NOP
}

static int thread_equal(lkl_thread_t a, lkl_thread_t b)
{
	// NOP
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

//static void* mem_alloc(unsigned long count)
//{
//	// NOP
//	return sim_malloc(count);
//}

//static void mem_free(void *addr)
//{
//	// NOP
//}

static unsigned long long time(void)
{
	// NOP
	return 0;
}

static void* timer_alloc(void (*fn)(void *), void *arg)
{
	// NOP
	
}

static int timer_set_oneshot(void *timer, unsigned long delta)
{
	// NOP
}

static void timer_free(void *timer)
{
	// NOP
}

static void* lkl_ioremap(long addr, int size)
{
	// NOP
}

static int lkl_iomem_access(const __volatile__ void *addr, void *val, int size,
		int write)
{
	// NOP
}

static long gettid(void)
{
	// NOP
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
	.time = time,
	.timer_alloc = timer_alloc,
	.timer_set_oneshot = timer_set_oneshot,
	.timer_free = timer_free,
	.print = print,
	.mem_alloc = sim_malloc,
	.mem_free = sim_free,
	.ioremap = lkl_ioremap,
	.iomem_access = lkl_iomem_access,
	.virtio_devices = lkl_virtio_devs,
	.gettid = gettid,
	.jmp_buf_set = jmp_buf_set,
	.jmp_buf_longjmp = jmp_buf_longjmp,
};
