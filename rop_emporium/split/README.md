# Split

## First look

```console
┌──(vein㉿vein)-[~/rop_emporium/split]
└─$ checksec split
[*] '/home/vein/rop_emporium/split/split'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

┌──(vein㉿vein)-[~/rop_emporium/split]
└─$ ./split     
split by ROP Emporium
x86_64

Contriving a reason to ask user for data...
> test
Thank you!

Exiting
```
The NX is enabled so it prevents running code into the stack, so we can't do a shellcode attack
```
## Static Analysis

```c
undefined8 main(void)

{
  setvbuf(stdout,(char *)0x0,2,0);
  puts("split by ROP Emporium");
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
  puts("Contriving a reason to ask user for data...");
  printf("> ");
  read(0,local_28,0x60);
  puts("Thank you!");
  return;
}
```
```c

void usefulFunction(void)

{
  system("/bin/ls");
  return;
}
```
We open Ghidra and we saw that a pwnme() function is called by the main.
We see that has a buffer overflow in the local_28 variable cause it's 32 bytes long
and the read() takes up to 96 = 0x60

# Exploitation
Challeneg description talks about a string that we maybe need to solve it.
We found it with rabin2 but we also can with Ghidra and with pwndbg.
It's the "/bin/cat flag.txt"
```console
┌──(vein㉿vein)-[~/rop_emporium/split]
└─$ rabin2 -z split  
[Strings]
nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x000007e8 0x004007e8 21  22   .rodata ascii split by ROP Emporium
1   0x000007fe 0x004007fe 7   8    .rodata ascii x86_64\n
2   0x00000806 0x00400806 8   9    .rodata ascii \nExiting
3   0x00000810 0x00400810 43  44   .rodata ascii Contriving a reason to ask user for data...
4   0x0000083f 0x0040083f 10  11   .rodata ascii Thank you!
5   0x0000084a 0x0040084a 7   8    .rodata ascii /bin/ls
0   0x00001060 0x00601060 17  18   .data   ascii /bin/cat flag.txt
What we want to do is to navigate to usefulFunction() function and put inside the system()
the string 
