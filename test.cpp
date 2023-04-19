#include <Windows.h>
#include "obfuscated_jump_generator.h"

int test_fn(int a, void* obfu_printf) {
    ((int(__cdecl*)(const char*, ...))obfu_printf)("Obfuscated printf: %i\n", a);
    return a + 1;
}

int main()
{
    std::random_device rd;
    std::mt19937 mt(rd());

    int tot = 0;
    auto buf = (uint8_t*)VirtualAlloc(nullptr, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    // generate obfuscated call to test_fn
    auto generator = shellcode_jmp_generator(&mt);
    auto fn = (int(__cdecl*)(int, void*))(buf + tot);
    tot += generator.write_to_buf(buf + tot, (uint32_t)test_fn);

    // generate obfuscated call to printf
    generator = shellcode_jmp_generator(&mt);
    auto obfu_printf = (void*)(buf + tot);
    tot += generator.write_to_buf(buf + tot, (uint32_t)printf);

    // call test_fn and obfuscated printf a bunch of times
    for (int i = 0; i < 10000; i++) {
        fn(i, obfu_printf);
    }

    std::getchar();
    return 0;
}