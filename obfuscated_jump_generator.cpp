#include "obfuscated_jump_generator.h"

// returns size of write
int write_operation(uint8_t* buf, int reg, int op, uint32_t value = 0 /* only required for ADD, SUB & XOR */);

#define WRITE_OPERATION(op) m_used_bytes += write_operation(m_shellcode + m_used_bytes, reg, op)
#define WRITE_OPERATION_VALUE(op, val) m_used_bytes += write_operation(m_shellcode + m_used_bytes, reg, op, val)


shellcode_jmp_generator::shellcode_jmp_generator(std::mt19937* gen) {
    m_last_obfu_offset = 0;
    m_gen = gen;
    m_used_bytes = 0;
    generate_shellcode();

}

// returns amount of bytes written (MAX 64)
int shellcode_jmp_generator::write_to_buf(uint8_t* buf, uint32_t final_addr) {
    memcpy(buf, m_shellcode, m_used_bytes);
    switch (m_last_obfu_type) {
    case ADD:
    {
        *(uint32_t*)(buf + m_last_obfu_offset) = final_addr - m_accum_value;
    }
    break;
    case SUB:
    {
        *(uint32_t*)(buf + m_last_obfu_offset) = m_accum_value- final_addr;
    }
    break;
    case XOR:
    {
        *(uint32_t*)(buf + m_last_obfu_offset) = final_addr ^ m_accum_value;
    }
    break;
    }

    int max_pad = 64 - m_used_bytes;
    auto rand_dis = std::uniform_int_distribution<uint32_t>(0, max_pad - 1);

    return std::min(uint32_t(m_used_bytes) + rand_dis(*m_gen), 64u);
}

int shellcode_jmp_generator::generate_shellcode() {
    auto rand_dis = std::uniform_int_distribution<uint32_t>(0, UINT32_MAX);
    // using eax as the register is faster so we mostly want to do that, but give it a solid 25% to use a non-eax register
    int reg = EAX;
    if (!(rand_dis(*m_gen) % 4)) {
        reg = (rand_dis(*m_gen) % (NUM_REGISTERS - 1)) + 1; // pick non-eax register
    }

    if (reg != EAX) {
        WRITE_OPERATION(PUSH);
    }

    m_accum_value = rand_dis(*m_gen);
    WRITE_OPERATION_VALUE(MOV, m_accum_value);

    // perpare counters
    int num_obfuscations = 0;
    int num_operations[5];
    memset(num_operations, 0, 5 * sizeof(int));

    // fill shellcode with "garbage"
    bool stop = false;
    while (true) {
        int operation = rand_dis(*m_gen) % 5;
        if (operation > XOR) { // not obfusction operation, it's a junk one
            if (num_operations[operation] >= MAX_JUNK_OPERATIONS)
                continue;

            WRITE_OPERATION(operation);
            num_operations[operation]++;
        }
        else {
            if (num_operations[operation] >= MAX_INDIVIDUAL_OPERATIONS)
                continue;

            uint32_t value = rand_dis(*m_gen); // random num for the instruction

            // calculate accum
            switch (operation) {
            case ADD:
            {
                m_accum_value += value;
            }
            break;
            case SUB:
            {
                m_accum_value -= value;
            }
            break;
            case XOR:
            {
                m_accum_value ^= value;
            }
            break;
            }

            WRITE_OPERATION_VALUE(operation, value);
            num_operations[operation]++;
            num_obfuscations++;

            if (!stop)
                stop = (rand_dis(*m_gen) % 3); // 66% chance to stop

            if ((stop && num_obfuscations >= MIN_OBFUSCATION_OPERATIONS) || (num_obfuscations >= MAX_OBFUSCATION_OPERATIONS))
                break;
        }
    }
        
    // write the final instruction that gets overriden at a later time to decide the final address
    m_last_obfu_type = rand_dis(*m_gen) % 3;
    WRITE_OPERATION_VALUE(m_last_obfu_type, 0xCCCCCCCC);
    m_last_obfu_offset = m_used_bytes - 4;

    // not eax, we need to move final value into eax 
    if (reg != EAX) {
        WRITE_OPERATION(MOV_EAX);
        WRITE_OPERATION(POP);
    }

    // finally write the jump
    WRITE_OPERATION(JMP_EAX);

    return m_used_bytes;
}

#define PRINT_OPERATIONS 0
int write_operation(uint8_t* buf, int reg, int op, uint32_t value) {
#if PRINT_OPERATIONS
    if (op <= XOR || op == MOV) {
        printf("%s %s, %Xh\n", operation_names[op], register_names[reg], value);
    }
    else {
        if (op == JMP_EAX)
            printf("JMP EAX\n");
        if (op == MOV_EAX)
            printf("MOV EAX, %s\n", register_names[reg]);
        if (op == PUSH || op == POP)
            printf("%s %s\n", operation_names[op], register_names[reg]);
        if (op == JUNK_MOV)
            printf("MOV %s, %s\n", register_names[reg], register_names[reg]);
        if (op == JUNK_XCHG) {
            int r = reg;
            if (reg == EAX)
                r = EDX;
            printf("XCHG %s, %s\n", register_names[r], register_names[r]);
        }
    }
#endif

    int size = 0;
    int offset = 0; // used for operands that has a value (xor add sub)
    switch (op) {
    case ADD:
    {
        switch (reg) {
        case EAX:
        {
            *buf = 0x05;
            size = 5;
            offset = 1;
        }
        break;
        case ECX:
        {
            *(uint16_t*)(buf) = 0xC181; // 81 C6 <imm32>
            size = 6;
            offset = 2;
        }
        break;
        case EDX:
        {
            *(uint16_t*)(buf) = 0xC281; // 81 C6 <imm32>
            size = 6;
            offset = 2;
        }
        break;
        case ESI:
        {
            *(uint16_t*)(buf) = 0xC681; // 81 C6 <imm32>
            size = 6;
            offset = 2;
        }
        break;
        }
        *(uint32_t*)(buf + offset) = value;
    }
    break;
    case SUB:
    {
        switch (reg) {
        case EAX:
        {
            *buf = 0x2D;
            size = 5;
            offset = 1;
        }
        break;
        case ECX:
        {
            *(uint16_t*)(buf) = 0xE981; // 81 C6 <imm32>
            size = 6;
            offset = 2;
        }
        break;
        case EDX:
        {
            *(uint16_t*)(buf) = 0xEA81; // 81 C6 <imm32>
            size = 6;
            offset = 2;
        }
        break;
        case ESI:
        {
            *(uint16_t*)(buf) = 0xEE81; // 81 C6 <imm32>
            size = 6;
            offset = 2;
        }
        break;
        }
        *(uint32_t*)(buf + offset) = value;
    }
    break;
    case XOR:
    {
        switch (reg) {
        case EAX:
        {
            *buf = 0x35;
            size = 5;
            offset = 1;
        }
        break;
        case ECX:
        {
            *(uint16_t*)(buf) = 0xF181;
            size = 6;
            offset = 2;
        }
        break;
        case EDX:
        {
            *(uint16_t*)(buf) = 0xF281;
            size = 6;
            offset = 2;
        }
        break;
        case ESI:
        {
            *(uint16_t*)(buf) = 0xF681;
            size = 6;
            offset = 2;
        }
        break;
        }
        *(uint32_t*)(buf + offset) = value;
    }
    break;
    case JUNK_XCHG:
    {
        switch (reg) {
        case EAX:
        case EDX:
        {
            *(uint16_t*)(buf) = 0xD287;
        }
        break;
        case ECX:
        {
            *(uint16_t*)(buf) = 0xC987;
        }
        break;
        case ESI:
        {
            *(uint16_t*)(buf) = 0xF687;
        }
        break;
        }
        size = 2;
    }
    break;
    case JUNK_MOV:
    {
        switch (reg) {
        case EAX:
        {
            *(uint16_t*)(buf) = 0xC089;
        }
        break;
        case ECX:
        {
            *(uint16_t*)(buf) = 0xC989;
        }
        break;
        case EDX:
        {
            *(uint16_t*)(buf) = 0xD289;
        }
        break;
        case ESI:
        {
            *(uint16_t*)(buf) = 0xF689;
        }
        break;
        }
        size = 2;
    }
    break;
    case MOV_EAX:
    {
        switch (reg) {
        case ECX:
        {
            *(uint16_t*)(buf) = 0xC889;
        }
        break;
        case EDX:
        {
            *(uint16_t*)(buf) = 0xD089;
        }
        break;
        case ESI:
        {
            *(uint16_t*)(buf) = 0xF089;
        }
        break;
        }
        size = 2;
    }
    break;
    case MOV:
    {
        switch (reg) {
        case EAX:
        {
            *buf = 0xB8;
        }
        break;
        case ECX:
        {
            *buf = 0xB9;
        }
        break;
        case EDX:
        {
            *buf = 0xBA;
        }
        break;
        case ESI:
        {
            *buf = 0xBE;
        }
        break;
        }
        size = 5;
        offset = 1;
        *(uint32_t*)(buf + offset) = value;
    }
    break;
    case PUSH:
    {
        switch (reg) {
        case ECX:
        {
            *(uint8_t*)(buf) = 0x51;
            size = 1;
        }
        break;
        case EDX:
        {
            *(uint8_t*)(buf) = 0x52;
            size = 1;
        }
        break;
        case ESI:
        {
            *(uint8_t*)(buf) = 0x56;
            size = 1;
        }
        break;
        }
    }
    break;
    case POP:
    {
        switch (reg) {
        case ECX:
        {
            *(uint8_t*)(buf) = 0x59;
            size = 1;
        }
        break;
        case EDX:
        {
            *(uint8_t*)(buf) = 0x5A;
            size = 1;
        }
        break;
        case ESI:
        {
            *(uint8_t*)(buf) = 0x5E;
            size = 1;
        }
        break;
        }
    }
    break;
    case JMP_EAX:
    {
        *(uint16_t*)(buf) = 0xE0FF;
        size = 2;
    }
    break;
    }

    return size;
}