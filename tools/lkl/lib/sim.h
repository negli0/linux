#include <stdarg.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <stdio.h>
#include <semaphore.h>

#ifdef __cplusplus
	extern "C" {
#endif

struct SimImported {
	int (*vprintf) (struct SimKernel *kernel, const char *str, va_list args);
	void *(*malloc) (struct SimKernel *kernel, unsigned long size);
	void (*free) (struct SimKernel *kernel, void *buffer);
	void *(*memcpy) (struct SimKernel *kernel, void *dst, const void *src, unsigned long size);
	void *(*memset) (struct SimKernel *kernel, void *dst, char value, unsigned long size);
	int (*atexit) (struct SimKernel *kernel, void (*function)(void));
	int (*access) (struct SimKernel *kernel, const char *pathname, int mode);
	char *(*getenv) (struct SimKernel *kernel, const char *name);
	int (*mkdir)(struct SimKernel *kernel, const char *pathname, mode_t mode);
	int (*open)(struct SimKernel *kernel, const char *pathname, int flags);
	int (*__fxstat) (struct SimKernel *kernel, int ver, int fd, void *buf);
	int (*fseek)(struct SimKernel *kernel, FILE *stream, long offset, int whence);
	void (*setbuf)(struct SimKernel *kernel, FILE *stream, char *buf);
	FILE *(*fdopen)(struct SimKernel *kernel, int fd, const char *mode);
	long (*ftell)(struct SimKernel *kernel, FILE *stream);
	int (*fclose)(struct SimKernel *kernel, FILE *fp);
	size_t (*fread)(struct SimKernel *kernel, void *ptr, size_t size, size_t nmemb, FILE *stream);
	size_t (*fwrite)(struct SimKernel *kernel, const void *ptr, size_t size, size_t nmemb, FILE *stream);

	int (*sem_init)(struct SimKernel *kernel, sem_t *sem, int pshared, unsigned int value);
	int (*sem_destroy) (struct SimKernel *kernel, sem_t *sem);
	int (*sem_post) (struct SimKernel *kernel, sem_t *sem);
	int (*sem_wait) (struct SimKernel *kernel, sem_t *sem);
	int (*sem_trywait) (struct SimKernel *kernel, sem_t *sem);
	int (*sem_timedwait) (struct SimKernel *kernel, sem_t *sem, const struct timespec *abs_timeout);
	int (*sem_getvalue) (struct SimKernel *kernel, sem_t *sem, int *sval);

	int (*pthread_mutexattr_init) (struct SimKernel *kernel, pthread_mutexattr_t *attr);
	int (*pthread_mutexattr_settype) (struct SimKernel *kernel, pthread_mutexattr_t *attr, int kind);
	int (*pthread_mutex_init) (struct SimKernel *kernel, pthread_mutex_t *mutex, const pthread_mutexattr_t *attr);
	int (*pthread_mutex_destroy) (struct SimKernel *kernel, pthread_mutex_t *mutex);

	int (*clock_gettime) (struct SimKernel *kernel, clockid_t c, struct timespec *tp);

	unsigned long (*random) (struct SimKernel *kernel);
	void *(*event_schedule_ns) (struct SimKernel *kernel, __u64 ns, void (*fn) (void *context), void *context,
			void (*pre_fn) (void));
	void (*event_cancel) (struct SimKernel *kernel, void *event);
	__u64 (*current_ns) (struct SimKernel *kernel);

	struct SimTask *(*task_start) (struct SimKernel *kernel, void (*callback) (void *), void *context);
	void (*task_wait) (struct SimKernel *kernel);
	struct SimTask *(*task_current) (struct SimKernel *kernel);
	int (*task_wakeup) (struct SimKernel *kernel, struct SimTask *task);
	void (*task_yield) (struct SimKernel *kernel);

	void (*dev_xmit) (struct SimKernel *kernel, struct SimDevice *dev, unsigned char *data, int len);
	void (*signal_raised) (struct SimKernel *kernel, struct SimTask *task, int sig);
	void (*poll_event) (int flag, void *context);
};

typedef void (*SimInit) (const struct SimImported *, struct SimKernel *kernel);

#ifdef __cplusplus
}
#endif
