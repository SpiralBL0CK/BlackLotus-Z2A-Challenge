# BlackLotus-Z2A-Challenge
BlackLotus-Z2A-Challenge, Nothing to see here 4 now , please move along 


First things first
![Capture23](https://user-images.githubusercontent.com/25670930/234439907-a5ecfec7-16f0-48a3-89b8-97c362a927c2.PNG)

For aesthetic purposes soley, I will shamesly borrow(steal) :)) from ```@darthmaulware(Ryan “DM” Smith)``` solution the yara detection rules just to make it look proffesional. Go check his twitter he's a fking cool person! Ps. Ryan please don't get mad bc i stole that :))) and thx for support in discord :) 

Please check his work also :) 

https://gitlab.com/malre-rcs/zero2automated/-/blob/main/solutions/bi_weekly_challenge/BlackLotus_20230321/BlackLotus_HTTP_Downloader.ipynb

```
rule Blacklotus_HTTP_Downloader
{
        meta:
            description = "Rule to detect Blacklotus HTTP Downloader"
            author = "Darth Maulware"
            sha256 = "d68f668b4240f9518e4f80499d93d8c5a1eddece0771658c33ae916cc54f5a66"

        strings:
            $opcode1 = {48 89 4C 24 08 48 89 54 24 10 4C}
            $opcode2 = {89 44 24 18 4C 89 4C 24 20 48 83}
            $opcode3 = {EC 28 B9 31 62 D7 2E 90 90 E8 ??}
            $opcode4 = {?? ?? ?? 48 83 C4 28 48 8B 4C 24}
            $opcode5 = {08 48 8B 54 24 10 4C 8B 44 24 18}
            $opcode6 = {4C 8B 4C 24 20 4C 8B D1 90 90}

        condition:
            (uint16(0) == 0x5a4d and filesize < 500KB and all of them)
}
```

Also for aesthetical reasone i will also steal this because it looks cool :) again sorry ryan please don't get mad on me :)

```
        C:\\Users\\REM\\Desktop>capa.exe -f pe -r capa-rules-5.0.0 d68f668b4240f9518e4f80499d93d8c5a1eddece0771658c33ae916cc54f5a66.exe
        matching: 100%|████████| 124/124 [00:02<00:00, 46.96 functions/s, skipped 1 library functions (0%)]

        +------------------------+------------------------------------------------------------------------------------+
        | ATT&CK Tactic          | ATT&CK Technique                                                                   |
        |------------------------+------------------------------------------------------------------------------------|
        | DEFENSE EVASION        | Obfuscated Files or Information T1027                                              |
        | DISCOVERY              | Process Discovery T1057                                                            |
        | EXECUTION              | Shared Modules T1129                                                               |
        +------------------------+------------------------------------------------------------------------------------+

        +-----------------------------+-------------------------------------------------------------------------------+
        | MBC Objective               | MBC Behavior                                                                  |
        |-----------------------------+-------------------------------------------------------------------------------|
        | ANTI-BEHAVIORAL ANALYSIS    | Debugger Detection::Process Environment Block BeingDebugged [B0001.035]       |
        |                             | Debugger Detection::Process Environment Block NtGlobalFlag [B0001.036]        |
        | CRYPTOGRAPHY                | Encrypt Data::RC4 [C0027.009]                                                 |
        |                             | Generate Pseudo-random Sequence::RC4 PRGA [C0021.004]                         |
        | DATA                        | Encode Data::XOR [C0026.002]                                                  |
        | DEFENSE EVASION             | Obfuscated Files or Information::Encoding-Standard Algorithm [E1027.m02]      |
        +-----------------------------+-------------------------------------------------------------------------------+

        +------------------------------------------------------+------------------------------------------------------+
        | CAPABILITY                                           | NAMESPACE                                            |
        |------------------------------------------------------+------------------------------------------------------|
        | execute syscall instruction (35 matches)             | anti-analysis                                        |
        | check for PEB BeingDebugged flag (2 matches)         | anti-analysis/anti-debugging/debugger-detection      |
        | check for PEB NtGlobalFlag flag                      | anti-analysis/anti-debugging/debugger-detection      |
        | encode data using XOR (2 matches)                    | data-manipulation/encoding/xor                       |
        | encrypt data using RC4 PRGA (2 matches)              | data-manipulation/encryption/rc4                     |
        | get process heap flags                               | host-interaction/process                             |
        | get ntdll base address (3 matches)                   | linking/runtime-linking                              |
        | parse PE header (2 matches)                          | load-code/pe                                         |
        | resolve function by parsing PE exports (2 matches)   | load-code/pe                                         |
        +------------------------------------------------------+------------------------------------------------------+
```

tbh if i were you i wouldn't trust 100% capa(at least in this specific case) because here it say the sample uses rc4 when actually sample uses aes but whatever , as mentioned this is strictly for aesthetics :)

Before we start you will encounter through this report a lot of  

![1](https://github.com/SpiralBL0CK/BlackLotus-Z2A-Challenge/assets/25670930/f97005e4-d526-4596-9b25-f0a76ef32b02)

Please ignore this as ida fails to properly dissasamble this in assembly this is 

![1](https://github.com/SpiralBL0CK/BlackLotus-Z2A-Challenge/assets/25670930/d8b8ebec-baab-4c11-8bfd-a2ce43b38ce4)

And this crashes the debugger ? why ?

because it tries to write at address 0, which in hacker folklor is know as writing at null pointer address which was something exploited widely in order to obtain CE(code execution), and this has been obviously mitigated.

And such with the current mitigation if you try to write at 0 it will crash that process in our case the malware & consequently the debugger.


Now if we open this is ida 

![1](https://user-images.githubusercontent.com/25670930/236251310-3982a808-5603-4274-967d-74766d4efebe.PNG)


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

If you use the aplib_decompress.py emulation script you should end up with something like this 

![1](https://github.com/SpiralBL0CK/BlackLotus-Z2A-Challenge/assets/25670930/3f500374-270f-4f79-96b4-69f37bd124fb)

Cool thing i didn't notice on other blogs/analysis was this if we take a look again at ida's pseudo code for ntdll_and_unhook2 

![1](https://github.com/SpiralBL0CK/BlackLotus-Z2A-Challenge/assets/25670930/d6846678-ca81-40a6-b91d-3bee1fca1f07)

you'll see a interesting memcpy

at one point when i was doing the dynamica analysis i noticed another dll being loaded, which was another version of ntdll

![1](https://github.com/SpiralBL0CK/BlackLotus-Z2A-Challenge/assets/25670930/9d700404-1047-49f5-97f2-70232e2c547d)

if we look in debugger it looks like this 

![1](https://github.com/SpiralBL0CK/BlackLotus-Z2A-Challenge/assets/25670930/1e7813bd-e7f5-490a-904c-3ee17792b769)

i was not able to detect what was hooked/patched but if someone knows please do a pull request and edit this document.
Also in my attempts to find what gets hooked i tried to do bindiff between the two ntdlls and unfortunatelly i found nothing but it might be because i was already doing diff on system dll which was infected so
not a clean run so maybe that's why ¯\_(ツ)_/¯

![1](https://github.com/SpiralBL0CK/BlackLotus-Z2A-Challenge/assets/25670930/13c55268-1b69-489e-886b-5d54a89898a2)


=============================================================================

Going further with the analysis process, on the unexplained functions we have some_hasing and ntquertyinformationprocess_anti_debug, thoese have not been explained. check_if_being_debug_through_teb and anti_debug has already been explained fortunatelly because they were used in the upper function/functions, so please read upper sections if wanna revise the knowledge about them. I would like to start first with ntquertyinformationprocess_anti_debug and afterwards finish with some_hasing.

Inspecting it we see the same function called 3 times.

![1234](https://user-images.githubusercontent.com/25670930/235452022-34cd8dc2-7053-4882-801b-fdd20a9c56d0.PNG)

And from an assembly stance 

![1](https://user-images.githubusercontent.com/25670930/235452617-ab40e71d-2ac0-43ac-adbf-36cb8a126c6b.PNG)

![2](https://user-images.githubusercontent.com/25670930/235452621-735d8e05-78c1-4872-933a-8b1ef02dcb52.PNG)


For convinience i have already named it, which is ntquertyinformationprocess_ProcessDebugPort. From where did i knwon the function which were called were ntquertyinformationprocess_ProcessDebugPort? Inspecting them reveals an already saw function call/known algorithms to us

![1](https://user-images.githubusercontent.com/25670930/235452441-e9f85ce6-e461-4ae0-9e93-88d7ce7c50c0.PNG)

What about the comments made in ida ? Well if you search ntqueryinformationprocess on google we come along a good resource about anti debugging(https://anti-debug.checkpoint.com/techniques/debug-flags.html) . If we follow allong we can see it explain us that based on certain values passed as parameters to this functions it can be used as an anti-debuggin method.

For example for the first call we can see the following stack arguments in the debugger 

![1](https://user-images.githubusercontent.com/25670930/235453530-0d02843a-5ce4-469d-bf53-bceb179d1463.PNG)

If we now go and check msdn page for ntqueryinformationprocess

![1](https://user-images.githubusercontent.com/25670930/235453925-af8dca82-57ed-45ce-be1a-c331f75f25f2.PNG)

Same process repeats for the next two syscalls

![2](https://user-images.githubusercontent.com/25670930/235454831-4949e203-2619-4947-b52f-040f53d60c27.PNG)

which 0x1e is specific for ProcessDebugObjectHandle anti-debug method(https://www.apriorit.com/dev-blog/367-anti-reverse-engineering-protection-techniques-to-use-before-releasing-software)

and finally ProcessDebugFlags

![2](https://user-images.githubusercontent.com/25670930/235455063-026b69be-e9e3-43e5-a4fe-87a77f106f06.PNG)

So how do we bypass them ?! Take a chill pill fam, cause ScyllaHide has about back braw

![obama-pew](https://user-images.githubusercontent.com/25670930/235455334-fb2d901d-14e7-4fdb-8280-774a04dae763.gif)

As you can see

![1](https://user-images.githubusercontent.com/25670930/235455461-fc86f3d7-d65a-4621-8cbc-4278ff9a69fa.PNG)

So we safe! Not quite, while ScyllaHide has our back for the first 2 syscall, for the last syscall we have to do it manually ! and wtf do i do ???
Well simple solution! we return from this function so like from the whole ntquertyinformationprocess_anti_debug and set eax to 0 . So under normal circumasnces it looks like this

![1](https://user-images.githubusercontent.com/25670930/235456335-c2fb717b-8e5a-43cc-96d6-155680a50f27.PNG)

And with our "help" it looks like this and we safely let the execution go :)

![1](https://user-images.githubusercontent.com/25670930/235456479-488d4478-4c1d-470a-862f-0180ed8f8705.PNG)

=============================================================================

Now some_hasing , you' lready know the drill

![1](https://user-images.githubusercontent.com/25670930/235466444-884d8ea4-05ae-4d94-bf9e-a7aab9cb6192.PNG)

And now pseudo-code 

![2](https://user-images.githubusercontent.com/25670930/235466535-3b1d3f9d-77e7-40e9-bb50-3939630c3ef6.PNG)

We notice a strange thing here. Ida's pseudo-code fails here... because if we follow the graph after call_syscall there are more instruction to disassamble. So what we do here now ? Well we will relly on the debugger here to dynamically analyse this code...

So we see that the syscall it does is 

![1](https://user-images.githubusercontent.com/25670930/235469632-c9c95e4e-8ed0-471e-9434-dd36a88dd2f7.PNG)

Now if we look ntquerydefaultlocale google shows that this is an undocumented api which takes 2 arguments(http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FLocale%2FNtQueryDefaultLocale.html). Cool so what it does ? It returns current Locale Identifier. Cool so wtf is a Locale Identifier? From msdn (https://learn.microsoft.com/en-us/windows/win32/intl/locale-identifiers) a 32-bit value that consists of a language identifier and a sort order identifier. On a tl;dr note what language you speak on that pc :) 

Afterwards it check to see if api didn't fail to execute and if it didn't fail to execute it takes the value returned by ntquerydefaultlocale, substract 0x419 compares it with 0x26(probably a constant) as you can see in the picture below.

![1](https://user-images.githubusercontent.com/25670930/235471316-4f4b0ab7-7f73-44fd-a2d1-639a805b7eee.PNG)

If it is not smaller or equal to 0x26 it compares it with 0x818 otherwise does same comparisson with 0x819 as you can clearly see

![2](https://user-images.githubusercontent.com/25670930/235471604-a616e6c6-7f33-49fd-8af6-c0003addcf91.PNG)

So wtf is happening here ? any why these specific constants. Well I'll be straight to point. While searching for different constants i came around this article(https://www.cnblogs.com/DirWang/p/17281690.html#autoid-8-0-0), a researcher which has already analysed blacklotus better than I could. And as someone said once: "You can't cheat in malware analysis , you can just make your work easier". So what the researcher said is that basically this function checks for specific constants which identify what language is spoken on the computer . In his article he provides a link to this(https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-LCID/[MS-LCID].pdf) which is like a standard document from microsoft with every language identifier. 

Now using our hax00r l33t logic we can deduct that probably 0x26 it like an offset used , so like any 0x26 next language identifiers after 0x419,which are 

![2](https://user-images.githubusercontent.com/25670930/235473482-5d16d8bc-c89c-444b-9f66-6a48e0981306.PNG)

If we also inspect that document we can also see that 0x818 corresponds to 

![2](https://user-images.githubusercontent.com/25670930/235472738-ea4b0039-ef9d-4bf7-b3b3-cafcd37825d3.PNG)

and 0x819 to

![2](https://user-images.githubusercontent.com/25670930/235472801-c9f1f290-6df0-4cb5-bb4d-27a6a1e92d4d.PNG)
 
And we know from previous "investigations"/online reports that this malware dind't run on certain PC from certain regions of the world,  so we can conclude that this function checks to see on which region is the infected machine.

=============================================================================

Crazy ham00brg33r up to now , fam what next ? We server some_more_syscall function. Aight! So what you got there ack! Here it is 

![1](https://user-images.githubusercontent.com/25670930/235475787-25bba373-97ea-47f4-90b4-0c06eceef0c8.PNG)

We want more! Sure thing dawg! 

![2](https://user-images.githubusercontent.com/25670930/235475880-3d59a01a-ad84-4f54-9a90-2807e16cd327.PNG)

![3jgukd](https://user-images.githubusercontent.com/25670930/235475937-908fa0b3-bd72-44d7-9855-90d7d7523eed.png)

![1](https://user-images.githubusercontent.com/25670930/235476679-6f8085a7-c172-4702-93ce-0fe5b57a2cb8.PNG)

Hmmmm

![1](https://user-images.githubusercontent.com/25670930/235477151-5ee808a6-b0c5-4fd1-9d63-80f9d37bc996.PNG)

So check to see if kerneldebugger is present(https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntexapi/system_information_class.htm)(0x23) , checky checky!

So what ack! We we g0t pcr(piles and combinations party)

![2](https://user-images.githubusercontent.com/25670930/235477585-24f84c06-5ef9-4eaf-9dd1-aad3f30a7dbe.PNG)

=============================================================================

Now if we inspect iterate_over_modules() function it looks like this 

![1](https://user-images.githubusercontent.com/25670930/236223219-c1823707-206b-4f71-9a9c-cbd1665e214b.PNG)

From a "pseudo-code" perspective it looks like 

![2](https://user-images.githubusercontent.com/25670930/236224238-794e57d6-adbf-49fe-bf76-779154527783.PNG)

From a standalone pov it looks like the assembly and ida's pseudo-code match, so what is the logic of this function do ? well pretty simple, it iterates over the in memory modules(dll's) and checks against a list of hashes :)
  v4[0] = 0x1E7EACEF;
  v4[1] = 0x4468A620;
  v4[2] = 0x68536B95;
  v4[3] = 0x73EBBB53;
  v4[4] = 0xDA165168;
  v4[5] = 0xB24D33A7;
  v4[6] = 0xB1E2CEC6;
  v4[7] = 0x5136992;
  v4[8] = 0x98C500D9;
  v4[9] = 0x3E0169B6;

And if no in memory dll's were found to have same hash we return 0 , else 1 and we crash the debugger. And so such a conclusion we can say this is another anti-analysis method. Correct but what about each of the hash values ? Well i'll cheat again(as someone said once you can't cheat at malware analysis, only make your life more easier :) ). The upper afro-mentioned asian researcher was kind enough to provide us a list of values from which the values were derived 

sbiedll.dll
dbghelp.dll
api_log.dll
dir_watch.dll
pstorec.dll
vmcheck.dll
wpespy.dll
cmdvrt64.dll
avghookx.dll
snxhk.dll

Now to dynamically see if the any values correspond to any dll mentioned

![2](https://user-images.githubusercontent.com/25670930/236228752-3ccba910-db44-429c-9a32-68ddd05d4b79.PNG)

And sure enough it does :) 

But how did i end-up coming wit the conclusion that the algorithms checks agains these values ? well when i emulated a piece of this malware i had to re-implement 
iterate_over_module_name_and_hash(in solve_hash_syscalls.py file ) and in this function we have  

![1](https://user-images.githubusercontent.com/25670930/236233701-6d6ae83f-a8fc-4906-810f-089ea70d4b80.PNG)

where x(passed argument) in this case is v2 which is an array(a pointer) of values which gets increments(where it point in array) as long as it doesn't match any values from the upper already mentioned values. Man that's a mouthfull :P

Cool beans! Next

=============================================================================

iterate_over_modules2 roughly same story here 

![1](https://user-images.githubusercontent.com/25670930/236229272-a3987e6f-d0ab-4c8e-ba6c-57358dd1bd74.PNG)

And pseudo-code

![2](https://user-images.githubusercontent.com/25670930/236229408-54cc456d-e053-41df-92af-ec9e30d49430.PNG)

Roughly same story only different hashes :)

  v5[0] = 0x7D73878E;
  v5[1] = 0xEF36424B;
  v5[2] = 0xAF64BC2B;
  v5[3] = 0x1DBBC879;
  v5[4] = 0xAE6D1D56;
  v5[5] = 0x7B3242F2;
  v5[6] = 0x14D922B9;
  v5[7] = 0x4C92DF53;

which correspond to 

sample.exe
bot.exe
sandbox.exe
malware.exe
test.exe
klavme.exe
myapp.exe
testapp.exe

=============================================================================

iterate_over_modules3 same story here 

![1](https://user-images.githubusercontent.com/25670930/236249754-215715e5-3272-4046-a33b-003f009e4c8d.PNG)

And pseudo-code

![2](https://user-images.githubusercontent.com/25670930/236249790-42551140-7225-4573-86b0-f5c56f5b28b5.PNG)

same story different hashes :)

  v4[0] = 0x42D12D59;
  v4[1] = 0xEC5D7AA;
  v4[2] = 0x861E460F;
  v4[3] = 0x84BCC8DB;
  v4[4] = 0x6474D72B;
  v4[5] = 0xB8B9C504;
  v4[6] = 0x69A0620E;
  v4[7] = 0x6017EE43;
  v4[8] = 0xE93BE2E0;
  v4[9] = 0x149EFC55;
  v4[10] = 0xE3FA84A4;
  v4[11] = 0x7CFDD7AF;
  v4[12] = 0x5B098C67;
  v4[13] = 0x2F1FB18E;
  v4[14] = 0xFE8F2B18;
  
which correspond to 

prl_cc.exe
prl_tools.exe
qemu-ga.exe
vmtoolsd.exe
vmwaretray.exe
vmwareuser.exe
VGAuthService.exe
vmacthlp.exe
vboxservice.exe
vboxtray.exe
VMSrvc.exe
VMUSrvc.exe
xenservice.exe

=============================================================================

Anti_debug_measure_1 i ended up renaimg it to anti_debug_measure2_RtlAddVectoredExceptionHandler_int3. Why , you' see in a minute. So it looks like this 

![1](https://github.com/SpiralBL0CK/BlackLotus-Z2A-Challenge/assets/25670930/d40fcb14-5440-411d-ac5e-c82cfd54444e)

And from a pseudo-code perspective it looks like this

![1](https://github.com/SpiralBL0CK/BlackLotus-Z2A-Challenge/assets/25670930/895a7803-dba0-4d36-8c31-6c82cf8eeeb5)

So what in the f is this ? well it's basically creating an exception handler for __debugbreak(int 3) which will execute code whenever int3 is raised. I ended up searching for more and came around this 

(https://blog.lexfo.fr/dridex-malware.html) which is a cool resource which let's us know this is simply an anti-debug mechanism, and for our case we just run this function we ignore sub_13F2820D0 which

gets triggered whenever we execute int3 and patch eax to 0 :) so in memory execution looks like this :)

Before patch 

![1](https://github.com/SpiralBL0CK/BlackLotus-Z2A-Challenge/assets/25670930/2b2f8f9a-69b8-4bc8-9a85-539211ff6390)

After patch

![1](https://github.com/SpiralBL0CK/BlackLotus-Z2A-Challenge/assets/25670930/dde34235-646e-440c-92bc-5085ac335d2b)

After that you exit the function and also edit rax/eax to 0 so you skip the jne to crash debugger

![1](https://github.com/SpiralBL0CK/BlackLotus-Z2A-Challenge/assets/25670930/4704cf22-e387-4efa-96e1-c15b0eb6bba5)



=============================================================================

Anti_debug_measure_2 which i later changed to anti_debug_measure2_RtlAddVectoredExceptionHandler_int2

![1](https://github.com/SpiralBL0CK/BlackLotus-Z2A-Challenge/assets/25670930/985da43f-a513-4396-be51-3f3a311ca45b)

![2](https://github.com/SpiralBL0CK/BlackLotus-Z2A-Challenge/assets/25670930/dd27ab22-7579-4425-99ee-2940ecf04a0e)

Again nothing new under the sun same thing just hookin other int/syscall this time int2, same trick to bypass use dynamically patching return value to bypass it :)

If you search for anti analysis 2dh on google a bunch of stuff will appear so yeah you can use that as a reference to learn more about that i didn't spend a lot of time with this :)

For this one even if you say try to step over it will end up at ret as here

![1](https://github.com/SpiralBL0CK/BlackLotus-Z2A-Challenge/assets/25670930/b259ffd5-7a65-45ae-8d4b-66ef09764da3)

and to bypass this simply execute till return and you are good :)

=============================================================================

So now comes anti_debug measure heap which i later renamed iterate_over_current_process_and_check_again_hases

![1](https://github.com/SpiralBL0CK/BlackLotus-Z2A-Challenge/assets/25670930/6cd89ba6-a1c6-4f31-8da0-f7d7962a6745)

And a cool feature of this function is that this uses ntquerysysteminformation inside iterate_over_current_process_and_hash_check to list all the running processes. This is how iterate_over_current_process_and_hash_check looks like 

![1](https://github.com/SpiralBL0CK/BlackLotus-Z2A-Challenge/assets/25670930/27c5ee3d-fbd7-4c87-8db8-37b606694565)

![2](https://github.com/SpiralBL0CK/BlackLotus-Z2A-Challenge/assets/25670930/4d60c67e-2be7-4a82-a53e-1009629e6ebb)

Cool beans but how tf did i came to the conclusion that iterate_over_current_process_and_hash_check does what the name suggest, well first it's the ntquerysysteminformation call , which if you search on google you will see it used to get a list of running processes, and than i simply took and educated guess based on the following code snippet ```LODWORD(v4) = RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, 8u, v10);
    v3 = v4;  v5 = ntquerysysteminformation(); v6 = v3; ....  memcpy(v9, v6[8], *(v6 + 28)); v9[*(v6 + 28) >> 1] = 0; if ( some_hash_0x1003F(v9) == a1 )``` that it would copy the list of processes iterate over each on and compare each hash from the previous array with whatever process was running. Now again kudos to the asian's research blog because idk how tf he came to get the actual name of v4 array values. Please reffer to iterate_over_modules.py in case you wanna see how i emulated this. 
 
Ps. if you debug dynamically this function you will end up hitting int 2d again, and solution is same as mentioned above only that you basically run till return 0xf times, which basically walks the hev and after that if you wanna be sure you hit return from iterate_over_current_process_and_check_again_hases just put a br at the end of this function and you are safe :)

=============================================================================
anti_debug_measure_heap

![1](https://github.com/SpiralBL0CK/BlackLotus-Z2A-Challenge/assets/25670930/18498120-4d05-49c2-9360-45c164611025)

![2](https://github.com/SpiralBL0CK/BlackLotus-Z2A-Challenge/assets/25670930/70122f89-0382-4ff2-908d-9bc1be891b08)

![1](https://github.com/SpiralBL0CK/BlackLotus-Z2A-Challenge/assets/25670930/18a0a666-55e1-4d48-8aba-7f3a013062f0)

So yeah we fortunate this is not that big , and what's more we have already implemented demangle_strings. Now i have re-implemented this for bigger arrays please go see anti_debug_measure.py .

this basically checks against 

```
   \Registry\Machine\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters 
   \Registry\Machine\SYSTEM\ControlSet001\Services\vioscsi
   \Registry\Machine\SYSTEM\ControlSet001\Services\VirtIO-FS Service
   \Registry\Machine\SYSTEM\ControlSet001\Services\VirtioSerial
   \Registry\Machine\SYSTEM\ControlSet001\Services\BALLOON
   \Registry\Machine\SYSTEM\ControlSet001\Services\BalloonService
   \Registry\Machine\SYSTEM\ControlSet001\Services\netkvm
   \Registry\Machine\SOFTWARE\VMware, Inc.\VMware Tools
   \Registry\Machine\HARDWARE\ACPI\DSDT\VBOX__
   \Registry\Machine\HARDWARE\ACPI\FADT\VBOX__
   \Registry\Machine\HARDWARE\ACPI\RSDT\VBOX__
   \Registry\Machine\SOFTWARE\Oracle\VirtualBox Guest Additions
   \Registry\Machine\SYSTEM\ControlSet001\Services\VBoxGuest
   \Registry\Machine\SYSTEM\ControlSet001\Services\VBoxMouse
   \Registry\Machine\SYSTEM\ControlSet001\Services\VBoxService
   \Registry\Machine\SYSTEM\ControlSet001\Services\VBoxSF
   \Registry\Machine\SYSTEM\ControlSet001\Services\VBoxVideo
  ```
=============================================================================

Now get_oem_key

![1](https://github.com/SpiralBL0CK/BlackLotus-Z2A-Challenge/assets/25670930/3846d578-3c02-4d5e-ae90-b3ec68f5b11c)

![2](https://github.com/SpiralBL0CK/BlackLotus-Z2A-Challenge/assets/25670930/d600db39-c7e2-4f2f-82dd-7793aa795e7a)

![3](https://github.com/SpiralBL0CK/BlackLotus-Z2A-Challenge/assets/25670930/33da15c1-dd54-4401-ae0a-49afc6e07594)

![4](https://github.com/SpiralBL0CK/BlackLotus-Z2A-Challenge/assets/25670930/fb77ce5b-4d0e-42da-b3d5-ec24636770bd)

![5](https://github.com/SpiralBL0CK/BlackLotus-Z2A-Challenge/assets/25670930/51f56d83-b1f2-4e3f-a24c-9af12e6c34a2)

![1](https://github.com/SpiralBL0CK/BlackLotus-Z2A-Challenge/assets/25670930/73e717a5-c998-4e77-89ec-0d6d88299940)

![2](https://github.com/SpiralBL0CK/BlackLotus-Z2A-Challenge/assets/25670930/654051fa-afe9-418a-8d10-c0c4f8580d33)

First it demmangles string to
```
   \Registry\Machine\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0
   \Registry\Machine\SYSTEM\ControlSet001\Control\SystemInformation
   \Registry\Machine\HARDWARE\Description\System
   Identifier
   SystemManufacturer
   SystemBiosVersion
   VMWARE
   QEMU
   VBOX
```

And than queries    
   \Registry\Machine\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0
   \Registry\Machine\SYSTEM\ControlSet001\Control\SystemInformation
   \Registry\Machine\HARDWARE\Description\System

and checks their values against qemu,vbox,VMWARE as it can be seen in ida snippet and x86 window :)

![1](https://github.com/SpiralBL0CK/BlackLotus-Z2A-Challenge/assets/25670930/a2614414-cf03-4dce-844a-4d671a04247c)

![2](https://github.com/SpiralBL0CK/BlackLotus-Z2A-Challenge/assets/25670930/03ed130e-0ea4-461f-9f28-49d474e14f61)

As it can be seen in first snippet it checks vmware against whatever values was stored in my vm at the time at the analysis :)

not big deal just run this function until ret and change eax when retuning to 0 :) to bypass this anti anaylsis method :)

=============================================================================

now get_oem_from_firmware

![1](https://github.com/SpiralBL0CK/BlackLotus-Z2A-Challenge/assets/25670930/84d67352-f64f-4936-9dc3-16329a869fc5)

![2](https://github.com/SpiralBL0CK/BlackLotus-Z2A-Challenge/assets/25670930/9eebee0c-3b0d-4dd1-a801-b921b71b50ce)

![3](https://github.com/SpiralBL0CK/BlackLotus-Z2A-Challenge/assets/25670930/5371da27-a89f-475f-9006-aefb2dfa4b20)

![4](https://github.com/SpiralBL0CK/BlackLotus-Z2A-Challenge/assets/25670930/d2f97f15-1625-456d-9603-0703d8cf38d2)

![5](https://github.com/SpiralBL0CK/BlackLotus-Z2A-Challenge/assets/25670930/1e7a272f-9827-4eae-b508-303b5fe7c684)



