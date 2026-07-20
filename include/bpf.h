#ifndef _BPF_H
#define _BPF_H

#include <stdint.h>

// BPF instruction structure
struct bpf_insn {
    uint8_t  code;       // opcode
    uint8_t  dst_reg:4;  // dest register
    uint8_t  src_reg:4;  // source register
    int16_t  off;        // signed offset
    int32_t  imm;        // signed immediate constant
};

// BPF instruction classes
#define BPF_CLASS(code) ((code) & 0x07)
#define BPF_LD      0x00
#define BPF_LDX     0x01
#define BPF_ST      0x02
#define BPF_STX     0x03
#define BPF_ALU     0x04
#define BPF_JMP     0x05
#define BPF_RET     0x06
#define BPF_ALU64   0x07

// BPF size modifiers
#define BPF_SIZE(code) ((code) & 0x18)
#define BPF_W       0x00    // 32-bit
#define BPF_H       0x08    // 16-bit
#define BPF_B       0x10    // 8-bit
#define BPF_DW      0x18    // 64-bit

// BPF mode
#define BPF_MODE(code) ((code) & 0xe0)
#define BPF_IMM     0x00
#define BPF_ABS     0x20
#define BPF_IND     0x40
#define BPF_MEM     0x60
#define BPF_ATOMIC  0xc0

// ALU/ALU64 operations
#define BPF_OP(code) ((code) & 0xf0)
#define BPF_ADD     0x00
#define BPF_SUB     0x10
#define BPF_MUL     0x20
#define BPF_DIV     0x30
#define BPF_OR      0x40
#define BPF_AND     0x50
#define BPF_LSH     0x60
#define BPF_RSH     0x70
#define BPF_NEG     0x80
#define BPF_MOD     0x90
#define BPF_XOR     0xa0
#define BPF_MOV     0xb0
#define BPF_ARSH    0xc0
#define BPF_END     0xd0

// Jump operations
#define BPF_JA      0x00
#define BPF_JEQ     0x10
#define BPF_JGT     0x20
#define BPF_JGE     0x30
#define BPF_JSET    0x40
#define BPF_JNE     0x50
#define BPF_JSGT    0x60
#define BPF_JSGE    0x70
#define BPF_CALL    0x80
#define BPF_EXIT    0x90
#define BPF_JLT     0xa0
#define BPF_JLE     0xb0
#define BPF_JSLT    0xc0
#define BPF_JSLE    0xd0

// Source modifier
#define BPF_SRC(code) ((code) & 0x08)
#define BPF_K       0x00
#define BPF_X       0x08

// Function prototypes for BPF instruction decoding
const char *get_class_name(uint8_t code);
const char *get_size_name(uint8_t code);
const char *get_alu_op_name(uint8_t code);
const char *get_jmp_op_name(uint8_t code);

// Dump a single BPF instruction
// Returns 1 if the next instruction should be skipped (LD_IMM64), 0 otherwise
int dump_bpf_insn(struct bpf_insn *insn, size_t idx);

#endif /* _BPF_H */
