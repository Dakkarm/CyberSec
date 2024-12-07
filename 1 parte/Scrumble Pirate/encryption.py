#!/usr/bin/env python3

import string
import random

alphabet = list(string.ascii_uppercase)

text = """
Narrator: Wealth, fame, power. The world had it all won by one man: the Pirate King, Gold Roger. 
At his death, the words he spoke drove countless men out to sea.
Gold Roger: My treasure? It's yours if you want it. Find it! I left all the world has there!
Narrator: And so men set sights on the Grand Line, in pursuit of their dreams and find the great treasure left 
behind, the One Piece. 
The world has truly entered a Great Pirate Era! Wearing the straw hat sworn upon him by the great pirate, 
Shanks, Monkey D. Luffy heads out to the sea on a journey on the road to become King of the Pirates! 

spritz{congratz_u_found_the_one_piece!}"""

text = text.upper()

# print(random.shuffle(alphabet))

substitution_alphabet = ['H','F','Z','Y','L','V','W','A','X','G','Q','U','K','O','E','M','J','P','D','S','R','B','C','I','N','T']

substituted_text = ""
for c in text:
    if c in alphabet:
        substituted_text += substitution_alphabet[alphabet.index(c)]
    else:
        substituted_text += c
        
print(substituted_text)
