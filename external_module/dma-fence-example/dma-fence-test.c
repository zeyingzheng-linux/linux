#include "stdio.h"
#include <stdlib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <poll.h>

#define DMA_FENCE_IN_CMD		_IOWR('f', 0, int)
#define DMA_FENCE_OUT_CMD		_IOWR('f', 1, int)
#define DMA_FENCE_SIGNAL_CMD	_IO('f', 2)

// #define BLOCKING_IN_KERNEL

int fd = -1;

static inline int sync_wait(int fd, int timeout)
{
	struct pollfd fds = {0};
	int ret;

	fds.fd = fd;
	fds.events = POLLIN;

	do {
		ret = poll(&fds, 1, timeout);
		if (ret > 0) {
			if (fds.revents & (POLLERR | POLLNVAL)) {
				errno = EINVAL;
				return -1;
			}
			return 0;
		} else if (ret == 0) {
			errno = ETIME;
			return -1;
		}
	} while (ret == -1 && (errno == EINTR || errno == EAGAIN));

	return ret;
}

static void * signal_pthread(void *arg)
{
	sleep(1);

	if (ioctl(fd, DMA_FENCE_SIGNAL_CMD) < 0) {
		perror("get out fence fd fail\n");
	}

	return NULL;
}

int main(void)
{

	int out_fence_fd;
	pthread_t tidp;

    fd = open("/dev/dma-fence", O_RDWR | O_NONBLOCK, 0);
	if (-1 == fd) {
		printf("Cannot open dma-fence dev\n");
		exit(1);
	}

	if(ioctl(fd, DMA_FENCE_OUT_CMD, &out_fence_fd) < 0) {
		perror("get out fence fd fail\n");
		close(fd);
		return -1;
	}

	printf("Get an out-fence fd = %d\n", out_fence_fd);

	if ((pthread_create(&tidp, NULL, signal_pthread, NULL)) == -1) {
		printf("create error!\n");
		close(out_fence_fd);
		close(fd);
		return -1;
	}

#ifdef BLOCKING_IN_KERNEL
	printf("Waiting out-fence to be signaled on KERNEL side ...\n");
	if(ioctl(fd, DMA_FENCE_IN_CMD, &out_fence_fd) < 0) {
		perror("get out fence fd fail\n");
		close(out_fence_fd);
		close(fd);
		return -1;
	}
#else
	printf("Waiting out-fence to be signaled on USER side ...\n");
	sync_wait(fd, -1);
#endif

	printf("out-fence is signaled\n");

	if (pthread_join(tidp, NULL)) {
		printf("thread is not exit...\n");
		return -1;
	}

	close(out_fence_fd);
	close(fd);

    return 0;
}