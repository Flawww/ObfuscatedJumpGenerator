# Obfuscated Jumps
Lightweight library which allows the dynamic generation of obfuscated jumps and/or function calls for x86.

Usually calls or jumps are implemented in assembly as a simple `call` or `jmp` to a certain address, which makes these calls very easy to follow even in static analysis of the binary. To make this a bit harder, obfuscation can be utilized. A jump pad is dynamically allocated and has shellcode written to it which should be hard to follow with static analysis, adding a layer of pain for the reverser.

The generated shellcode can be tweaked by changing the parameters at the top of [obfuscated_jump_generator.h](obfuscated_jump_generator.h), the available parameters are `MIN_OBFUSCATION_OPERATIONS, MAX_OBFUSCATION_OPERATIONS, MAX_INDIVIDUAL_OPERATIONS, MAX_JUNK_OPERATIONS`.

## Example of generated shellcode
```assembly
PUSH EDX
MOV EDX, F2993ECFh
XOR EDX, 931F310h
XCHG EDX, EDX
MOV EDX, EDX
XOR EDX, 8A76A15Dh
XCHG EDX, EDX
XOR EDX, B8B82BF2h
SUB EDX, CCCCCCCCh
MOV EAX, EDX
POP EDX
JMP EAX
```

## Compilation
Only tested with the MSVC compiler, but should work fine for any modern c++ compiler with support for compiling x86 executables.
The `test.cpp` example file is windows-only, but the library implementation is cross platform.

## Example Usage
To generate an obfuscated jump-pad for the function `printf`:
```c++
    std::random_device rd;
    std::mt19937 mt(rd());
    uint8_t* buf = (uint8_t*)VirtualAlloc(nullptr, 0x100, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    // generate obfuscated call to printf
    auto generator = shellcode_jmp_generator(&mt);
    auto obfu_printf = (int(__cdecl*)(const char*, ...))(buf);
    generator.write_to_buf(buf, (uint32_t)printf);
    
    // call the obfuscated shellcode:
    obfu_printf("Hello world");
```

## Limitations
Currently only works for x86. Support for x64 will be added if I ever find the motivation and time for it.