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
