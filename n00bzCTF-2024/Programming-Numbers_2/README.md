

					![](attachment/b525cca891743bde0dd6216253c5fda9.png)

## Challenge's Description

Let's see if you can do more than just counting... (Part 1 was in [n00bzCTF 2023](https://github.com/n00bzUnit3d/n00bzCTF2023-OfficalWriteups/tree/master/Misc/Numbers). There are no attachments. Note: There are only 3 different types of questions. Author: `NoobMaster`

It's a programming-crypto challenge without any attachments provided, only an instance.
The challenge tells us that there are only three different types of questions and and these are:

1) The greatest common divisor of 2 numbers 
2) The least common multiple of 2 numbers
3)  And the greatest prime factor

We interact with the instance to see how the challenge look like and we got this:

```sh
┌──(vein㉿vein)-[~/sec/n00bzCTF2024/programming-Numbers_2]
└─$ nc challs.n00bzunit3d.xyz 10356
Welcome to Numbers 2! Time to step up the game...
Current round: 1 of 100
Give me the greatest common divisor of 111 and 157:
```

We must give the correct answer of the above 3 math questions to get the flag. Of course, it it would take a very long time to calculate the numbers manually, so we'll write a script that will do it for us.
With a little search on the internet we found an application of the algorithms we need to calculate the numbers. 
We changed them according to our needs and we hardcoded the receive of the response from the remote instance to extract only the numbers and not the text to avoid errors.

```python
#!/usr/bin/env python3
from pwn import *
import math

r = remote('challs.n00bzunit3d.xyz', 10003)

#context.log_level = 'debug'

def lcm(a, b):
    return abs(a * b) // math.gcd(a, b)

def greatest_prime_factor(n):
    prime_factor = -1
    while n % 2 == 0:
        prime_factor = 2
        n //= 2
    for i in range(3, int(math.sqrt(n)) + 1, 2):
        while n % i == 0:
            prime_factor = i
            n //= i
    if n > 2:
        prime_factor = n
    return prime_factor


for i in range(1, 101):
    r.recvuntil(b'of 100\n')
    response = r.recvuntil(b':').decode()

    if 'greatest common divisor' in response:
        part = response.split('of ')[1]
        x_str, y_str = part.split(' and ')
        x = int(x_str)
        y = int(y_str.strip(':'))
        solve = math.gcd(x, y)
        r.sendline(str(solve))
        if i == 100:
            print(r.recvall())

    elif 'least common multiple' in response:
        part = response.split('of ')[1]
        x_str, y_str = part.split(' and ')
        x = int(x_str)
        y = int(y_str.strip(':'))
        solve = lcm(x, y)
        r.sendline(str(solve))
        if i == 100:
            print(r.recvall())

    elif 'greatest prime factor' in response:
        x_str = response.split('of ')[1].strip(':')
        x = int(x_str)
        solve = greatest_prime_factor(x)
        r.sendline(str(solve))
        if i == 100:
            print(r.recvall())
```

And we successfully took the flag!

```sh
┌──(vein㉿vein)-[~/sec/n00bzCTF2024/programming-Numbers_2]
└─$ ./solve.py
[+] Opening connection to challs.n00bzunit3d.xyz on port 10003: Done
  r.sendline(str(solve))
[+] Receiving all data: Done (82B)
[*] Closed connection to challs.n00bzunit3d.xyz port 10003
b" Correct!\nGood job! Here's your flag: n00bz{numb3r5_4r3_fun_7f3d4a_b7d10e075c82}\n\n"
```
