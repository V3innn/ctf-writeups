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