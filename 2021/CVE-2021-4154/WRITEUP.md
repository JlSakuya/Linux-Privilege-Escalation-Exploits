# BUG

The bug has been patched in upstream, but remained unfixed in many vendors' kernels, e.g. CentOS.

link to upstream's patch: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=3b0462726e7ef281c35a7a4ae33e93ee2bc9975b

# Primitive

We could set an arbitrary fd to fsconfig and eventually, the `struct file` of the fd will be freed by fs context after closing it.

So we gain an arbitrary free on file structure. I have proposed two different exploitation regarding this vulnerability. The first exploitation, by design, works among different versions of kernel on different architectures without **any** modification. The limitation is that it needs to overwrite a privileged file to gain privilege. If there is no such file, e.g. in a docker container, the approach won't work.

The second exploitation gives you more power than the first exploitation, it is like the traditional exploitation that can read/write on any kernel memory and execute any code. The downside is that it is not scalable, modification is needed for different versions of kernel.

# DirtyCred Exploitation

The first exploitation is inspired by Jann Horn's [double-put exploit](https://bugs.chromium.org/p/project-zero/issues/detail?id=808). The vulnerability being exploited is similar to the one here: we could free a file structure while having a reference to it.

Jann Horn's exploitation is brilliant: in a high-level view, it first opens an unprivileged file with write permission, then writes malicious content to it. During the time windows of checking permission and performing real writing, he replaced the underlying file structure with a privileged file structure(e.g. /etc/crontab, /etc/passwd), the malicious content will be written to the privileged file. 

In reality, there is a large time window between checking the file's write permission and performing writing. The following code shows this issue: `vfs_writev` first **checks** if the file has write permission, then prepares the io and **performs writing** in `do_readv_writev`.

In Jann's exploitation, he found a way to stabilize this exploitation. That he set up a userspace filesystem, where users can delay the time of importing user data (in `rw_copy_check_uvector`) to enlarge the time window of checking permission and performing writing. The userspace filesystem will cause a userfault in between these two operations. In the handler of userfault, he triggers the vulnerability to replace the file structure. After replacing the file structure, the malicious content will be written to the privileged file reliably.

```c
ssize_t vfs_writev(struct file *file, const struct iovec __user *vec,
           unsigned long vlen, loff_t *pos)
{ 
    if (!(file->f_mode & FMODE_WRITE))
        return -EBADF;
    if (!(file->f_mode & FMODE_CAN_WRITE))
        return -EINVAL;

    return do_readv_writev(WRITE, file, vec, vlen, pos);
}

static ssize_t do_readv_writev(int type, struct file *file,
                   const struct iovec __user * uvector,
                   unsigned long nr_segs, loff_t *pos)
{
    size_t tot_len;
    struct iovec iovstack[UIO_FASTIOV];
    struct iovec *iov = iovstack;
    ssize_t ret;
    io_fn_t fn;
    iov_fn_t fnv;
    iter_fn_t iter_fn;

    // userfault here
    ret = rw_copy_check_uvector(type, uvector, nr_segs,
                    ARRAY_SIZE(iovstack), iovstack, &iov);
    if (ret <= 0)
        goto out;

    tot_len = ret;
    ret = rw_verify_area(type, file, pos, tot_len);
    if (ret < 0)
        goto out;
    // perform writing
    ...
}
```
After he released his exploitation, kernel fixed this issue by moving `rw_copy_check_uvector` ahead of permission check:

```c
static ssize_t vfs_writev(struct file *file, const struct iovec __user *vec,
           unsigned long vlen, loff_t *pos, rwf_t flags)
{
    struct iovec iovstack[UIO_FASTIOV];
    struct iovec *iov = iovstack;
    struct iov_iter iter;
    ssize_t ret;

    // preparing io, where kernel could be paused using userfault
    ret = import_iovec(WRITE, vec, vlen, ARRAY_SIZE(iovstack), &iov, &iter);
    if (ret >= 0) {
        file_start_write(file);
        ret = do_iter_write(file, &iter, pos, flags);
        file_end_write(file);
        kfree(iov);
    }
    return ret;
}

static ssize_t do_iter_write(struct file *file, struct iov_iter *iter,
        loff_t *pos, rwf_t flags)
{
    size_t tot_len;
    ssize_t ret = 0;

    // checking permission
    if (!(file->f_mode & FMODE_WRITE))
        return -EBADF;
    if (!(file->f_mode & FMODE_CAN_WRITE))
        return -EINVAL;

    tot_len = iov_iter_count(iter);
    if (!tot_len)
        return 0;
    ret = rw_verify_area(WRITE, file, pos, tot_len);
    if (ret < 0)
        return ret;

    // performing writing
    if (file->f_op->write_iter)
        ret = do_iter_readv_writev(file, iter, pos, WRITE, flags);
    else
        ret = do_loop_readv_writev(file, iter, pos, WRITE, flags);
    if (ret > 0)
        fsnotify_modify(file);
    return ret;
}
```

Now, the procedure of writing a file is to
1. handle userspace io (where userfault could pause the kernel)
2. check the file permission
3. perform file writing

John's approach of stabilizing has been patched. It no longer works for latest kernel.

## New way of stabilizing
Since John's approach has been patched, I tried to figure out a new way to stabilize the exploitation while following the same high-level idea. And finally, I came up with a new approach to abusing file structure stably without using userfaultfd. The whole procedure is like the following. (please look at the raw txt for better layout)

   Thread 0: slow write               Thread 1: cmd write                      Thread 3: exploit
    __fdget_pos (no lock)            __fdget_pos (bypass lock)                             |
        |                                  |                                               |
        |                                  |                                               |
        \/                                \/                                               |
 ext4_file_write_iter (lock inode)    ext4_file_write_iter (wait for lock)                 |
        |                                  |                                               |
        |                                  |                                               |
        \/                                 |                                               \/
   normal write                            |                                      replace the file structure
        |                                  |
        |                                  |
        \/                                 |
write done, release inode lock             |
                                          \/
                                   get inode lock and then write
                                           |
                                          \/
                                        write done

### Racing write
In short, we will have three threads:

Thread 1 opens a writable file performing "slow write", which writes a very large amount of data to the file.

Thread 2 opens the same file as the first thread, but it will write malicious data to it.

Thread 3 will trigger the vulnerability and replace the underlying structure. (replace means freeing the file struct in thread 1 and 2, and reclaiming the memory slot of file structure with a privileged file structure)

### Prevent lock in __fdget_pos
```c
unsigned long __fdget_pos(unsigned int fd)
{
    unsigned long v = __fdget(fd);
    struct file *file = (struct file *)(v & ~3);

    if (file && (file->f_mode & FMODE_ATOMIC_POS)) {
        if (file_count(file) > 1) {
            v |= FDPUT_POS_UNLOCK;
            mutex_lock(&file->f_pos_lock);
        }
    }
    return v;
}
```
In `__fdget_pos`, if the current file has `FMODE_ATOMIC_POS` flag and has more than 1 refcount, there will be a lock to preventing a racing write. Once the file is locked, kernel will wait before performing writing. This is to prevent a file from being written in multiple threads, causing data loss. In our scenario, Since we open the same file in two different threads, which will have at least 3 refcount. So the kernel will pause in `__fdget_pos` waiting for the lock. However, this lock is before the permission check, locking the kernel here can't enlarge the time windows between checking and writing. As such, we should remove `FMODE_ATOMIC_POS` to prevent lock in the `__fdget_pos`.

```c
    /* POSIX.1-2008/SUSv4 Section XSI 2.9.7 */
    if (S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode))
        f->f_mode |= FMODE_ATOMIC_POS;
```
In `open` syscall, as long as the file is a regular file, it will have `FMODE_ATOMIC_POS` set. At first, I found that for files we have write permission, they are all regular files. After searching the kernel code, I realized that a soft link file will bypass this check so that it will not have `FMODE_ATOMIC_POS` set. As such, we could prevent the kernel  from being stuck in `__fdget_pos` function.

### Lock in ext4_file_write_iter

```c
static ssize_t
ext4_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
    struct inode *inode = file_inode(iocb->ki_filp);
    int o_direct = iocb->ki_flags & IOCB_DIRECT;
    int unaligned_aio = 0;
    int overwrite = 0;
    ssize_t ret;

    if (unlikely(ext4_forced_shutdown(EXT4_SB(inode->i_sb))))
        return -EIO;

#ifdef CONFIG_FS_DAX
    if (IS_DAX(inode))
        return ext4_dax_write_iter(iocb, from);
#endif

    if (!inode_trylock(inode)) {
        if (iocb->ki_flags & IOCB_NOWAIT)
            return -EAGAIN;
        inode_lock(inode);
    }
    ...
}
```

In `ext4_file_write_iter`, to prevent racing, it has a lock for inode. If a thread is writing a file and there is another thread writing to the same file, the second write will be paused until the inode lock is released. The good news is that this lock is in between the checking and writing.

So the idea is that in 1st thread, we write the file with a large amount of data, which will lock the inode for a period of time. Then in the 2nd thread, we write to the same file, we make sure kernel will not be stuck in `__fdget_pos`, then it goes to `ext4_file_write_iter` waiting for the lock of inode. At this time, we trigger the vulnerability and replace the file structure in thread 2 with a privileged file. When 2nd thread gets the lock, it will write to the privileged file with the malicious that we control. 

This technique is simple, but it only utilizes functions available in the default kernel configuration. I have attached the exploit that I wrote utilizing this method. It works on any architecture and any version of kernel as long as the kernel is vulnerable.

# ROP exploitation
Tl;dr,
1. Cross cache to corrupt memory from `file` object to `msg_msg`.
2. FREELIST_HARDENED could be bypassed, as I described [before](https://grsecurity.net/how_autoslab_changes_the_memory_unsafety_game). Current freelist hardening is weak.
3. Use `pipe_buffer` as an  **elastic** object to bypass kaslr and hijack kernel execution.


## Cross Cache
The cross-cache technique is simple, to cross cache from `filp` cache, I opened a lot of files and then free a bunch of them, which will free the slab cache of `filp`. Then I spray `struct msgseg` to reclaim the freed `filp` cache. One thing we should be careful about is that using a spray object whose slab cache's page size is the same as `filp` cache could improve the reliability.

## Bypass Freelist Hardened
Most people believe that bypassing freelist hardening requires leak of a xor'ed freelist pointer and a heap address, so that attackers can get the magic value (I have seen this claim in many academic papers). However, in reality, we could leak the magic without knowing heap address. And we can even leak heap address from xor'ed freelist pointer.

```c
static inline void set_freepointer(struct kmem_cache *s, void *object, void *fp)
{
    unsigned long freeptr_addr = (unsigned long)object + s->offset;

#ifdef CONFIG_SLAB_FREELIST_HARDENED
    BUG_ON(object == fp); /* naive detection of double free or corruption */
#endif

    *(void **)freeptr_addr = freelist_ptr(s, fp, freeptr_addr);
}
```

The weakness existing in freelist hardening is that if current freelist pointer is 0, which means no object is in the freelist,  the `fp` here will be 0 as well. As such, the xor'ed freelist pointer will be
```
magic_value ^ 0
```
which is the magic value itself. Leaking this value will easily bypass the freelist hardening.

In my exploitation, after crossing cache, I free the file structure through the vulnerability again, which will leave the xor'ed value on the heap, and could be obtained by reading the content of msg in userspace.


### Leak heap address
Since we have the magic value, I did the following operations to get the heap address.

1. reclaim the object (obj_A) freed by the vulnerability.
2. free an object (obj_B) in the same cache, and then free the obj_A again.

After this, the freelist pointer in obj_A will be
```
address_of_obj_B ^ magic_value
```

Leaking the content of obj_A gives me the heap address of obj_B


## Elastic object to bypass kaslr and hijack kernel execution
In [Andy's write-up](https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html), he utilized `struct pipe_buffer` to bypass kaslr and hijack execution. However, the normal allocation of `struct pipe_buffer` will go to kmalloc-1k. Which doesn't fullfill our scenario. We are using kmalloc-512.

[A elastic object](https://zplin.me/papers/ELOISE.pdf) means it could be allocated into any general kernel cache, depending on user input.

The `struct pipe_buffer` could be an elastic object, looking at the following code:

```c
int pipe_resize_ring(struct pipe_inode_info *pipe, unsigned int nr_slots)
{
    struct pipe_buffer *bufs;
    unsigned int head, tail, mask, n;

    /*
     * We can shrink the pipe, if arg is greater than the ring occupancy.
     * Since we don't expect a lot of shrink+grow operations, just free and
     * allocate again like we would do for growing.  If the pipe currently
     * contains more buffers than arg, then return busy.
     */
    mask = pipe->ring_size - 1;
    head = pipe->head;
    tail = pipe->tail;
    n = pipe_occupancy(pipe->head, pipe->tail);
    if (nr_slots < n)
        return -EBUSY;

    bufs = kcalloc(nr_slots, sizeof(*bufs),
               GFP_KERNEL_ACCOUNT | __GFP_NOWARN);
    if (unlikely(!bufs))
        return -ENOMEM;
}
```
It turns out the variable `nr_slots` can be controlled by users using syscall `fcntl`. Users can specify arbitrary value to allocate `pipe_buffer` into desired cache. In my case, I used 0x8 and 0xa. This is useful, because this is a very common property existing in android and general kernel, how to use `pipe_buffer` to leak kaslr and hijacking kernel execution could be referenced in Andy's write-up

## ROP

the ROP part shares a lot of similarities with [Andy's write-up](https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html).