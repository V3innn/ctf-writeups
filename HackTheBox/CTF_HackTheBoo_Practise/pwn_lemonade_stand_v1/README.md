# Lemonade Stand v1 

This challenge is an basic ret2win attack.

## Basic file checks

We see that the RELRO is full enabled so can't write anything in the GOT table to perform a "GOT overwrite" attack. \
The NX is also enabled, so that means we can't stored input or data cannot be executed as code to perform a shellcode attack.
![Alt Text](img/checksec.png)

## View the Source Code

We used Ghidra to disassemble the binary.\
The first thing that we want to do is to go to Functions section and select the main() to see\
what the binary is actually doing and what funtions are called.\
```c
void main(void)

{
  long lVar1;
  
  setup();
  puts("\x1b[1;33m");
  cls();
  do {
    while( true ) {
      while (lVar1 = menu(), lVar1 == 1) {
        buy_normal();
      }
      if (lVar1 == 2) break;
      error("We don\'t sell grapes!");
    }
    buy_large();
  } while( true );
}
```

We saw that the main is calling two funcrions buy_normal()" and buy_large().\
We navigate to them and we saw that both of them they calling a save_creds() func.\
![Alt Text](img/buy_large().png) 

This is where the interesting thing starts.
