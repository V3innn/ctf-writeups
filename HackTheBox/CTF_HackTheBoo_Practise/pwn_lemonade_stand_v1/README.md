# Lemonade Stand v1 

This challenge is an basic ret2win attack.

## Basic file checks

We see that the RELRO is full enabled so can't write anything in the GOT table to perform a "GOT overwrite" attack. \
The NX is also enabled, so that means we can't stored input or data cannot be executed as code to perform a shellcode attack.
![Alt Text](img/checksec.png)

## View the Source Code

We used Ghidra to disassemble the binary.\
The first thing that we want to do is to go to Functions section and select the main() to see\
what the binary is actually doing and what funtions are called.
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
We navigate to them and we saw that both of them they calling a save_creds() func.
```c
void buy_large(void)

{
  if (COINS < 6) {
    error("You don\'t have enough coins!");
    save_creds();
  }
  else {
    printf("\n%s[+] Enjoy your large lemonade!\n%s",&DAT_0040101e,&DAT_00400c88);
    COINS = COINS - 5;
  }
  return;
}
```

This is where the interesting thing starts. \
We see that we have a buffer overflow in the local_48 variable cause the size of it is 64 bytes and read can take 74 bytes

```assembly 
        00400ac7 48 8d 45 c0     LEA        RAX=>local_48,[RBP + -0x40]
```

```c

void save_creds(void)

{
  long lVar1;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  undefined8 local_18;
  undefined8 local_10;
  
  local_28 = 0;
  local_20 = 0;
  local_18 = 0;
  local_10 = 0;
  buffer = 0;
  local_40 = 0;
  local_38 = 0;
  local_30 = 0;
  puts(
      "\n\nI can give you a free lemonade but I need your information for next time so you can pay m e back!\n"
      );
  printf("1. Yes\n2. No thanks\n\n>> ");
  lVar1 = read_num();
  if (lVar1 == 1) {
    printf("\nPlease tell me your name: ");
    read(0,&local_28,30);
    printf("\nPlease tell me your surname: ");
    read(0,&local_48,74);
    puts("Thanks a lot! Here is your lemonade!\n");
  }
  return;
}
```
