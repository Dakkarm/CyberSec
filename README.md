USEFUL WEBSITES:

Pt.1
- https://gchq.github.io/CyberChef/
- https://crackstation.net/
- https://www.mycompiler.io/it/new/python

SQL INJECTION: ' or 1=1--
_____________________________________________________

Pt.2
- [Jumps Codes] http://www.unixwiz.net/techtips/x86-jumps.html
- http://ref.x86asm.net/coder64.html
- https://man7.org/linux/man-pages/man2/ptrace.2.html
- [Peda] https://github.com/longld/peda
- [pwntools] https://docs.pwntools.com/en/stable/
- [pwntools tutorial] https://github.com/Gallopsled/pwntools-tutorial
- [PTL & GOT] https://www.technovelty.org/linux/plt-and-got-the-key-to-code-sharing-and-dynamic-libraries.html
- [ROP with Radare2] https://github.com/JonathanSalwan/ROPgadget
- [HOW to find gadgets using rax] ROPgadget --binary ./a.out | grep “rax”
- [Other ROP tools] - https://docs.pwntools.com/en/stable/rop/rop.html
                    - https://scoding.de/ropper/
  
_____________________________________________________

gcc file.c -o file_senza_c     /////       chmod +x file_senza_c
comando per continuare a digitare su terminale dopo gdb    ->     p.interactive() // da usare solo su python

_____________________________________________________

Useful gdb-peda commands:

- disas nome_funzione
- b *indirizzo 	         [mette breakpoint]

- x/s nome_funzione   
- x nome_funzione        [esamina la funzione]

- pattern [size] [file]

es:
- gdb-peda$ pattern create 100 input
- :> Writing pattern of 100 chars to filename "input"
- gdb-peda$ r < input
- :> Starting program: /tmp/bof < input

- layout asm   [fa vedere l'interno della funzione in modo diverso   (si vede nome func + offset)]

- jump *(nome_funzione+offset) [salti a quell'istruzione]      (prima fai breakpoint, poi usa questa, poi fai run)
es: jump *(main+140)

GDB Guide
- https://youtu.be/HtNKhBWBvts?si=Cq4RvojowaZE4tJ7
- https://youtu.be/Tmdnsre9z7s?si=U1CLaNJ35TxtuIIu
- https://youtu.be/X5JHPtd1IJQ?si=wQ1PIwZDGBwnzUVr

_____________________________________________________

gadget exercises

1_split
2_callme
3_write4

______________________________________________________

grep === CTRL + F

grep -oE 'spritz{.*?}' nome_textfile.txt

______________________________________________________
