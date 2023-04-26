# BlackLotus-Z2A-Challenge
BlackLotus-Z2A-Challenge, Nothing to see here 4 now , please move along 


First things first
![Capture23](https://user-images.githubusercontent.com/25670930/234439907-a5ecfec7-16f0-48a3-89b8-97c362a927c2.PNG)

Now if we open this is ida 

![Capture23](https://user-images.githubusercontent.com/25670930/234440026-71be8ed0-abef-480f-ae5e-68b3be6e1140.PNG)

I renamed every function to indicate some logic it does, let's start with first function, do_syscall()
![Capture23](https://user-images.githubusercontent.com/25670930/234440293-966385b2-17a7-4407-b280-4bfe9556e1fb.PNG)

We imediatly notice the use of syscalls, whhich it's a known method to make the life of an analyst harder when it comes to dynamic analysis.

For those who are not familiar with syscall's in windows here is a cool video made by oalabs(https://www.youtube.com/watch?v=Uba3SQH2jNE). Please watch it cause i did too and it helped me a lot to understand what happens in this function

If we inspect the "pseudo-code" resolved by ida we see it looks like this 

![Capture4](https://user-images.githubusercontent.com/25670930/234440494-7221a172-ad83-4325-8b4b-3110547e807c.PNG)

If we inspect statically solve_hash it looks like this

![1](https://user-images.githubusercontent.com/25670930/234447160-aa81b9e3-b7b8-412e-b12e-970d80805a06.PNG)

![2](https://user-images.githubusercontent.com/25670930/234447174-9738ab7b-baca-41e6-bab1-1c36e7d9d622.PNG)

From a pseudo-perspective it looks like this 

![4](https://user-images.githubusercontent.com/25670930/234447356-0d7e2a7f-7805-40c5-a20d-d2225026e62a.PNG)

Please reffer to solve_hash.py to see my "emulation" of this in case you wanna see a piece of automation and you wanna find out what the syscall are resolve by hasing lookup algorithm. But non of the less this is part of a project called SysWhispers2 or at least that's what i pressume the malware's authors used as inspiration. None of the less please reffer to the upper videoclip of oalabs for better understanding.

Anyways the anti_debug function is easily bypass-able and well knows(https://anti-debug.checkpoint.com/techniques/debug-flags.html#manual-checks-ntglobalflag). The way to bypass it is to have scyllahide installed and NtGlobalFlag checked(which you should have by default on if you use x86dbg).None of the less this is what you are supposed to check

![4](https://user-images.githubusercontent.com/25670930/234480088-acccc7a7-8b42-4ecc-ba08-cb82327f141f.PNG)

And this is how the anti-debug "pseudo-function" looks like

![4](https://user-images.githubusercontent.com/25670930/234480305-b14585f5-7e68-402f-8c5f-fda63beed78a.PNG)

Pretty simple if you aks me 


=============================================================================
Following the execution order after this next function is

![4](https://user-images.githubusercontent.com/25670930/234481129-696bd5ee-938e-44a1-8e1f-71132d935545.PNG)

Again if we inspect to see what it does 

![Capture4](https://user-images.githubusercontent.com/25670930/234481218-2bd855a3-40f8-449a-a197-4c3cd149b795.PNG)

If simply checks a flag in teb to see if the current process(the exe in our case) is being debugged. This is yet again easily bypassable as it's a known method(https://anti-debug.checkpoint.com/techniques/debug-flags.html#manual-checks-peb-beingdebugged-flag) same way we used scyllahide this time you must have checked  
![Capturez](https://user-images.githubusercontent.com/25670930/234481604-a76ed10c-ca39-44d2-b300-7a5a35f11445.PNG) 

which should be on by default



