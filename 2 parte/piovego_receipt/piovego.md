i can see that i need to provide the correct inputs.
I decompiled the program using ghidra.

```
  iVar1 = strcmp(local_48,"Patate-Prezzemolate");
  if (iVar1 != 0) {
    puts("Nah who likes that??!? You\'re not ready for this job, go study more!");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
```
the first input then is Patate-Prezzemolate

```
  printf("\nHow many potatoes do you need for 100 people? ");
  __isoc99_scanf(&DAT_004022a8,&local_18);
  if (local_18 * 3 == 0xa8) {

    printf("\nGood, and how much parsley? ");
    __isoc99_scanf(&DAT_004022a8,&local_14);
    if (local_14 == 0x7b) {
      uVar1 = 1;
      goto LAB_00401411;
    }

```

the second and third inputs are then 56 (it's 168/3) and 123

now for the last input
```
  if (sVar1 == 5) {
    if (local_28 == 'S') {
      if (local_26 == 'e') {
        if (local_24 == 'T') {
          if (local_27 == 'w') {
            if (local_25 == '4') {
              uVar2 = 1;
```
The decompilation isn't super intuitive but the correct input is Swe4T.
(in the decompiled code, the first char of the input is called local_28, the second one is local_27... and so on.
so the first one must be 'S', the second one 'w'....)

the full output of the program, including the flag is:
```


    █ ▄▄  ▄█ ████▄     ▄   ▄███▄     ▄▀  ████▄ 
    █   █ ██ █   █      █  █▀   ▀  ▄▀    █   █ 
    █▀▀▀  ██ █   █ █     █ ██▄▄    █ ▀▄  █   █ 
    █     ▐█ ▀████  █    █ █▄   ▄▀ █   █ ▀████ 
     █     ▐         █  █  ▀███▀    ███        
      ▀               █▐                       
                      ▐                        


Dear Student, we have just received your application for the position of cook for the piovego canteen. 
We need to check you're ready for this job...
First! What is the most appreaciated plate of our canteen? Patate-Prezzemolate

Great! Now let's see if you know how to prepare them :)
How many potatoes do you need for 100 people? 56

Good, and how much parsley? 123
Wow, it seems you have studied!! :)
But now comes the really hard question:


What is the super iper mega special and secret ingredient?? Swe4T
Yes YeS YESS! Sweat and hard work are the ingredients for success!! Welcome on board!!!
SPRITZ{D15gUsT!nG!!} 
```

