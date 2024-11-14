#!/usr/bin/env python3

substituted_text = """
OHPPHSEP: CLHUSA, VHKL, MECLP. SAL CEPUY AHY XS HUU CEO FN EOL KHO: SAL MXPHSL QXOW, WEUY PEWLP. 
HS AXD YLHSA, SAL CEPYD AL DMEQL YPEBL ZEROSULDD KLO ERS SE DLH.
WEUY PEWLP: KN SPLHDRPL? XS'D NERPD XV NER CHOS XS. VXOY XS! X ULVS HUU SAL CEPUY AHD SALPL!
OHPPHSEP: HOY DE KLO DLS DXWASD EO SAL WPHOY UXOL, XO MRPDRXS EV SALXP YPLHKD HOY VXOY SAL WPLHS SPLHDRPL ULVS 
FLAXOY, SAL EOL MXLZL. 
SAL CEPUY AHD SPRUN LOSLPLY H WPLHS MXPHSL LPH! CLHPXOW SAL DSPHC AHS DCEPO RMEO AXK FN SAL WPLHS MXPHSL, 
DAHOQD, KEOQLN Y. URVVN ALHYD ERS SE SAL DLH EO H GERPOLN EO SAL PEHY SE FLZEKL QXOW EV SAL MXPHSLD! 

DMPXST{ZEOWPHST_R_VEROY_SAL_EOL_MXLZL!}"""

# I already know the part in front of the flag: spritz
# so I can start build the subsititution

# use the lower case letter so it is easier replace the chars in the text
solved = substituted_text.replace("D", "s")
solved = solved.replace("M", "p")
solved = solved.replace("P", "r")
solved = solved.replace("X", "i")
solved = solved.replace("S", "t")
solved = solved.replace("T", "z")

print(solved)

# in the text, you can then see that there are a lot of repetition of 
# the 'tAL' sequence, it could be 'the'
solved = solved.replace("A", "h")
solved = solved.replace("L", "e")

print(solved)


# after this substitution, you find the word 'pirHte', that looks 
# very similar to pirate
solved = solved.replace("H", "a")

print(solved)


# this helps to recognize the part at the beginning of the sentence
# OarratEr
solved = solved.replace("O", "n")
solved = solved.replace("E", "o")

print(solved)


# and in the flag you can find pieZe, remember that we want to change all the 
# upper case letters
solved = solved.replace("Z", "c")

# lookinga at different words, ('anY', 'entereY')
solved = solved.replace("Y", "d")
solved = solved.replace("W", "g")

# 'goUd' roger
solved = solved.replace("U", "l")
solved = solved.replace("R", "u")
solved = solved.replace("N", "y") # my treasure

# again from the flag, and now you have it
solved = solved.replace("V", "f")

# to finish it
solved = solved.replace("C", "w") # power
solved = solved.replace("K", "m") # fame
solved = solved.replace("C", "w") # wealth
solved = solved.replace("F", "b") # by
solved = solved.replace("Q", "k") # monkey
solved = solved.replace("B", "v") # drove

print(solved)

