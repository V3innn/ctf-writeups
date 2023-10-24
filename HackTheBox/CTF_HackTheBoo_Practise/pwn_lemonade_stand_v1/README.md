# Lemonade Stand v1 

This challenge is an basic ret2win attack.

## Basic file checks

We see that the RELRO is full enabled so can't write anything in the GOT table to perform a "GOT overwrite" attack.
The NX is also enabled, so that means we can't stored input or data cannot be executed as code to perform a shellcode attack.
![Alt Text](img/checksec.png)

