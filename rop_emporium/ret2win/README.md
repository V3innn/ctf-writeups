# ret2win 

This challenge is a easy buffer overflow attack.

## Basic file check
The NX is enabled, so we can't execute code in the stack to do a shellcode attack 
![Alt Text](checksec.png)

So we disassemble it and we saw that is a ret2win() function
which it prints the flag when it be called
![Alt Text](ret2win_func.png)


