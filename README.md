# BEKernelDriverUpdated
This is a repo of my previous BEKernelDriver but updated to add better protections and a more detailed setup. also with a good bit of code cleanup. This driver as of (8/3/2024) Does work with BattlEye games (Tested on Escape From Tarkov, DayZ, Rainbow Six Siege)
# Project
As said this does work on BattlEye, It uses CR3 for Read/Write and a ObCreateObject Communication Hook (Hijacking Method) that is undetected {if setup correctly}, This in theory can work on EAC EOS & some low level EAC based games but you will need to fix the CR3 Shuffling or add a buffer catch to make sure that once reading fails you can re-cache the CR3 without the system blue-screening. Either create a customary or use a CR3 Bypass traditional to CPU Bit Register Resolving or just find a way to catch bad reads or bad CR3 before reading so that you can re-cache the CR3 and get the new one. (It resets every 10-20 Minutes~ In game) but there is no resolver so it will blue screen on EAC.
# Plans
I plan to update this whenever it needs it but I removed all the useless code and projects for PsRoutines and etc because that is not needed just get a Patchguard Bypass like EFIGuard.
# Setup
```cpp
Setup:

- in (main.cpp) add hook driver & add hook settings
- in (impl/communication/interface.h) change driver handle identifier after the last \\
- in (processhyde/Hide.cpp) change executable name to hide to the usermode application
- Use VMProtect or another code mutator to make sure driver doesnt get signature scanned (as its public and BE/EAC will reverse it)

- get patchguard bypass.

- use my PdFwKrnl Mapper [github.com/i32-Sudo] or another mapper (DO NOT MANUAL MAP OR USE KDMAPPER, THIS IS DTC)
```
# Contact
If you want an actually good Kernel Level Cheat that is UD My discord is -> `_ambitza`
