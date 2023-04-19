#pragma once
#include <random>
#include <cstdint>

#define MIN_OBFUSCATION_OPERATIONS 3
#define MAX_OBFUSCATION_OPERATIONS 8
#define MAX_INDIVIDUAL_OPERATIONS 3
#define MAX_JUNK_OPERATIONS 3

class shellcode_jmp_generator {
public:
    shellcode_jmp_generator(std::mt19937* gen);

    // returns amount of bytes written (MAX 64)
    int write_to_buf(uint8_t* buf, uint32_t final_addr);

    uint8_t m_shellcode[64]; // 64 bytes is enough for our purpose
    size_t m_used_bytes;
private:
    int generate_shellcode();

    uint32_t m_accum_value;

    std::mt19937* m_gen;
    size_t m_last_obfu_offset;
    int m_last_obfu_type;
};

enum registers_t {
    EAX,
    ECX,
    EDX,
    ESI,

    NUM_REGISTERS
};

enum operation_t {
    ADD,
    SUB,
    XOR,
    JUNK_XCHG,
    JUNK_MOV,
    MOV,
    MOV_EAX, // moves register into eax
    PUSH,
    POP,
    JMP_EAX,
};

constexpr const char* operation_names[] = {
    "ADD",
    "SUB",
    "XOR",
    "JUNK_XCHG",
    "JUNK_MOV",
    "MOV",
    "MOV_EAX",
    "PUSH",
    "POP",
    "JMP_EAX",
};

constexpr const char* register_names[] = {
    "EAX",
    "ECX",
    "EDX",
    "ESI",
};