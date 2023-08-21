# ret2win 

This challenge is a easy buffer overflow attack.

## Basic file checks
The NX is enabled, so we can't execute code in the stack to do a shellcode attack 
![Alt Text](checksec.png)

## View the Source Code
So we disassemble it and we saw that is a ret2win() function
which it prints the flag when it be called
![Alt Text](ret2win_func.png)

The problem here it is that the ret2win() func, is never called by the main
so are not able to get the flag. That's where the ret2win attack comes (obviously).

## Exploit
The first thing that we want to do is to crash the program to be able to control it
we found the the offset to be 40 with pwndbg

We need a ret gadget to return to cause it's a x64 bit binary and not x32
We found it with ropper
![Alt Text](ret_gadget.png)

After these we wrote a simply python script with pwntools and we took the flag!
![Alt Text](successful_pwntools_exploit.png)

We even write a manual exploit in terminal using python2 that has a lot of fun.
![Alt Text](successful_manualexploit.png)
