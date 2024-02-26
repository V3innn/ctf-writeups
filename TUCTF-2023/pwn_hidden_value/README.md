# Hidden Value

## Challenge Description
```text
Easy

There's a hidden value in this program, can you find it?
nc chal.tuctf.com 30011
```

## Protections
The NX is enabled so can't execute shellcode on the stack but it won't bother us
```console
┌──(vein㉿vein)-[~/tuctf/pwn_hidden-value]
└─$ checksec hidden-value 
[*] '/home/vein/tuctf/pwn_hidden-value/hidden-value'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## First Look
We run the program and that what it looks like:
```console
┌──(vein㉿vein)-[~/tuctf/pwn_hidden-value]
└─$ ./hidden-value            
Enter your name: leo
Hello, leo
! Nothing special happened.
```
## Static Analysis in Ghidra

We open the program in Ghidra and we go directly to main to see what is happening
```c

undefined8 main(void)

{
  char local_78 [112];
  
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stdout,(char *)0x0,2,0);
  printf("Enter your name: ");
  fgets(local_78,100,stdin);
  greet_user(local_78);
  return 0;
}
```
We see that after we insert our name in the program,one function is called with it as function's input -> greet_user(local_78);

```c
void greet_user(char *param_1)

{
  char local_38 [44];
  int local_c;
  
  local_c = 0x12345678;
  strcpy(local_38,param_1);
  if (local_c == L'\xdeadbeef') {
    hidden_command();
  }
  else {
    printf("Hello, %s! Nothing special happened.\n",local_38);
  }
  return;
}
```

```c
void hidden_command(void)

{
  char local_78 [104];
  FILE *local_10;
  
  puts("Congratulations! You have executed the hidden command.");
  local_10 = fopen("flag","r");
  fgets(local_78,100,local_10);
  printf("The flag is: %s\n",local_78);
  return;
}
```
Here is the problem. We don't have immediately in the main a buffer overflow but in the buffer of main will cause a bof in greet_user() cause in the
first one the buffer size is 112 and the others is 44. So after 44 bytes we have a bof and we can overwrite the value of local c to deadbeef to execute
hidden_command() funtion that will that will give us the flag







