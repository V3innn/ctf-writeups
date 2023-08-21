# ret2win 

This challenge is a easy buffer overflow attack.

## Basic file checks
The NX is enabled, so we can't execute code in the stack to do a shellcode attack 
![Alt Text](checksec.png)

## View the Source Code
So we disassemble it and we saw that is a ret2win() function
which it prints the flag when it be called
![Alt Text](ret2win_func.png)


