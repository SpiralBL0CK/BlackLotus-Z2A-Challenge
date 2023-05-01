# BlackLotus-Z2A-Challenge
BlackLotus-Z2A-Challenge, Nothing to see here 4 now , please move along 


First things first
![Capture23](https://user-images.githubusercontent.com/25670930/234439907-a5ecfec7-16f0-48a3-89b8-97c362a927c2.PNG)

Now if we open this is ida 

![Capture23](https://user-images.githubusercontent.com/25670930/234440026-71be8ed0-abef-480f-ae5e-68b3be6e1140.PNG)

I renamed every function to indicate some logic it does, let's start with first function, do_syscall()
![Capture23](https://user-images.githubusercontent.com/25670930/234440293-966385b2-17a7-4407-b280-4bfe9556e1fb.PNG)

We imediatly notice the use of syscalls, which it's a known method to make the life of an analyst harder when it comes to dynamic analysis.

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

Next we have check_inmemory_ldr function which looks like this 

![1](https://user-images.githubusercontent.com/25670930/234482308-767c0940-36b5-458d-9012-a73ffbb7a687.PNG)

![2](https://user-images.githubusercontent.com/25670930/234482321-9239fab6-a526-401f-addd-b5cbf5af4868.PNG)

Now for the purpose of the function analysis if we ask kind enough x86dbg we can see that if we run till syscall instruction x86dbg will be kind enough to return us the syscall it is about the execute . In our case

![2](https://user-images.githubusercontent.com/25670930/235189641-8a128581-ff8e-4b86-9d00-5bca940e9b17.PNG)

Now based on the current context we can presume that Ntsetinformationthread we be used as some sort of anti analysis trick. Surely enough if we do a quick google search we come to find this   https://ntquery.wordpress.com/tag/ntqueryinformationthread/

Fortunatelly easily bypass-able just nop+ret patch-it  :)


=============================================================================

Following the execution order after this next function is

![4](https://user-images.githubusercontent.com/25670930/234481129-696bd5ee-938e-44a1-8e1f-71132d935545.PNG)

Again if we inspect to see what it does 

![Capture4](https://user-images.githubusercontent.com/25670930/234481218-2bd855a3-40f8-449a-a197-4c3cd149b795.PNG)

If simply checks a flag in teb to see if the current process(the exe in our case) is being debugged. This is yet again easily bypassable as it's a known method(https://anti-debug.checkpoint.com/techniques/debug-flags.html#manual-checks-peb-beingdebugged-flag) same way we used scyllahide this time you must have checked  
![Capturez](https://user-images.githubusercontent.com/25670930/234481604-a76ed10c-ca39-44d2-b300-7a5a35f11445.PNG) 

which should be on by default

=============================================================================

Now custom_hash2_and_aplib_possible which looks like this 

![2](https://user-images.githubusercontent.com/25670930/235200955-8ca34417-4d6a-4136-a51f-aa70c591c650.PNG)

And from a graph perspective

![3](https://user-images.githubusercontent.com/25670930/235201010-473cb758-4593-4e9a-9b80-ae60e59a5b87.PNG)

Please reffer to decompress_aplib.py to see the "emulation" of this function.

Exploring get_ntdll_and_unhook2 it looks like this

![1](https://user-images.githubusercontent.com/25670930/235202145-ca0bcf54-8c61-4ee5-821b-830f60fdf68d.PNG)

![2](https://user-images.githubusercontent.com/25670930/235202174-4433ec1f-2f42-424a-a473-52deb64c4200.PNG)


From a graph view it looks like this 

![1](https://user-images.githubusercontent.com/25670930/235202425-4a91b4b4-5a04-411f-9482-d570273514fb.PNG)

Not too shabby :))

Bakctracking a little we have aplib_decompress, now it looks like this 

![1](https://user-images.githubusercontent.com/25670930/235202700-aab40eda-cfa0-4e90-b512-1d6fc1f78b0f.PNG)

From a static code analysis looks like this  

![1](https://user-images.githubusercontent.com/25670930/235204049-6b05445e-12d0-4328-a335-74e6102dc72c.PNG)

![2](https://user-images.githubusercontent.com/25670930/235204072-1533dc98-5fac-4de4-aa41-d2f217e12a21.PNG)

![3](https://user-images.githubusercontent.com/25670930/235204089-cd06ae8e-88a7-4052-8c00-cebdad89e0a3.PNG)

![4](https://user-images.githubusercontent.com/25670930/235204107-056b0815-2d2a-4314-9c37-6c0bc7e686ba.PNG)

Mhmm a little big nothing to worry here folks it's doable :)

=============================================================================

Going further with the analysis process, on the unexplained functions we have some_hasing and ntquertyinformationprocess_anti_debug, thoese have not been explained. check_if_being_debug_through_teb and anti_debug has already been explained fortunatelly because they were used in the upper function/functions, so please read upper sections if wanna revise the knowledge about them. I would like to start first with ntquertyinformationprocess_anti_debug and afterwards finish with some_hasing. 
Inspecting it we see the same function called 3 times.

![1234](https://user-images.githubusercontent.com/25670930/235452022-34cd8dc2-7053-4882-801b-fdd20a9c56d0.PNG)

And from an assembly stance 

![1](https://user-images.githubusercontent.com/25670930/235452617-ab40e71d-2ac0-43ac-adbf-36cb8a126c6b.PNG)

![2](https://user-images.githubusercontent.com/25670930/235452621-735d8e05-78c1-4872-933a-8b1ef02dcb52.PNG)


For convinience i have already named it, which is ntquertyinformationprocess_ProcessDebugPort. From where did i knwon the function which were called were ntquertyinformationprocess_ProcessDebugPort? Inspecting them reveals an already saw function call/known algorithms to us

![1](https://user-images.githubusercontent.com/25670930/235452441-e9f85ce6-e461-4ae0-9e93-88d7ce7c50c0.PNG)




