after decompiling the program with ghidra, i can see that the correct inputs are randomly generated at runtime.

I can patch the JZ instructions to JMP in order to make the program accept every input!

```c
  for (local_c4 = 0; local_c4 < 0x96; local_c4 = local_c4 + 1) {
    puts("Nice ");
    sleep(1);
  }
```
this part would make me wait 150s just to know if i did everything correctly or not.
I don't have that much time. 
I replaced a JLE with a NOP so it only gets executed once!

```
  printf("\nShould I get you...");
  for (local_c4 = 0; local_c4 < 0x96; local_c4 = local_c4 + 1) {
    puts("...");
    sleep(1);
```
same for this one!

and that's it!!


```
/ / /\ \ \___| | ___ ___  _ __ ___   ___  | |_ ___   /__   \ |__   ___    /___\/ _|/ _(_) ___ ___ 
\ \/  \/ / _ \ |/ __/ _ \| '_ ` _ \ / _ \ | __/ _ \    / / \/ '_ \ / _\  //  // |_| |_| |/ __/ _ \
 \  /\  /  __/ | (_| (_) | | | | | |  __/ | || (_) |  / /  | | | |  __/ / \_//|  _|  _| | (_|  __/
  \/  \/ \___|_|\___\___/|_| |_| |_|\___|  \__\___/   \/   |_| |_|\___| \___/ |_| |_| |_|\___\___|

We are ready to start your interview to be a regional manager, are you ready? [Y]/n
Y
Can you tell me your name, surname, and your current position?

Ok great, now tell me your hobby bewteen these choices.
0 - Eat
1 - Badminton
2 - Battlestar galactica
3 - Annoying people
4 - Play Lol
3
Perfect hobby for a regional manager!

Should I get you...
spritz{th4ts_wh4t_sh3_s41d}
```
