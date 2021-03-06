# hiding-your-syscalls


## What is this?
This repository contains all of the source code from my blog post about avoiding direct syscall detections, which you can find [here](https://passthehashbrowns.github.io/hiding-your-syscalls).

The original detection that I wrote focused around locating a syscall instruction and determining whether or not it came from within the loaded copy of NTDLL. If it did not, then it may indicate direct syscall use. To bypass this detection, I patch the syscall stub with a jmp instruction to a legitimate syscall instruction inside of NTDLL. This means that the syscall comes from within NTDLL and then returns control to our code like normal.

### Normal
This project contains the source code to patch a "normal" syscall stub with a jmp instruction. It will parse the loaded NTDLL to find the address of the first Nt function (NtAcceptConnectPort) and patch a jump to that address + 18 bytes (the address of the syscall instruction).

### With Syswhispers
This project is a slightly modified version of Normal. Instead of a plain syscall stub it will instead use the Syscall stubs generated by Syswhispers. Pretty much the same thing but it will modify the stub in-place rather than making a copy. Also changes the number of bytes read since Syswhispers stubs are longer. Note that each Syswhispers stub also needs to include an extra 11 bytes to accomodate the jmp instruction that we're patching in since it's done in-place. You can see an example of this in SyscallsStubs.asm.

### Jumping without reading from NTDLL
This project contains an enum of offsets for all of the Nt functions in NTDLL. Instead of parsing NTDLL for a syscall stub, we can instead grab an offset from that table. This helps us avoid the scenario where an EDR has hooked the relevant ReadProcessMemory functions and may flag an RPM call to within NTDLL, and we can't use a direct syscall to do it since that would come from outside NTDLL and trigger the detection that I mentioned earlier.

Build_19041_Ntdll_Offsets.txt contains a dump of the NTDLL offsets from my machine, which is build 19041. I'm not sure how this will vary across Windows versions, as syscall numbers change across versions. To that end, I've also included a snippet of C in GetNTDLLOffsets.c that you can run to get the NTDLL offsets for a different version of Windows.

### frida_stalker_syscalls.js
This file contains some Frida bindings that will use Frida's code tracing engine, Stalker, to inspect every instruction in a process for syscalls. If a syscall is found, it will verify whether or not that syscall came from within the bounds of the loaded copy of NTDLL's address space. If it didn't then it may be an indicator of a direct syscall.
