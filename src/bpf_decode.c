#include <stdio.h>
#include "bpf.h"

const char *get_class_name(uint8_t code) {
    switch (BPF_CLASS(code)) {
        case BPF_LD: return "LD";
        case BPF_LDX: return "LDX";
        case BPF_ST: return "ST";
        case BPF_STX: return "STX";
        case BPF_ALU: return "ALU";
        case BPF_JMP: return "JMP";
        case BPF_RET: return "RET";
        case BPF_ALU64: return "ALU64";
        default: return "UNKNOWN";
    }
}

const char *get_size_name(uint8_t code) {
    switch (BPF_SIZE(code)) {
        case BPF_W: return "W";
        case BPF_H: return "H";
        case BPF_B: return "B";
        case BPF_DW: return "DW";
        default: return "?";
    }
}

const char *get_alu_op_name(uint8_t code) {
    switch (BPF_OP(code)) {
        case BPF_ADD: return "ADD";
        case BPF_SUB: return "SUB";
        case BPF_MUL: return "MUL";
        case BPF_DIV: return "DIV";
        case BPF_OR: return "OR";
        case BPF_AND: return "AND";
        case BPF_LSH: return "LSH";
        case BPF_RSH: return "RSH";
        case BPF_NEG: return "NEG";
        case BPF_MOD: return "MOD";
        case BPF_XOR: return "XOR";
        case BPF_MOV: return "MOV";
        case BPF_ARSH: return "ARSH";
        case BPF_END: return "END";
        default: return "UNKNOWN";
    }
}

const char *get_jmp_op_name(uint8_t code) {
    switch (BPF_OP(code)) {
        case BPF_JA: return "JA";
        case BPF_JEQ: return "JEQ";
        case BPF_JGT: return "JGT";
        case BPF_JGE: return "JGE";
        case BPF_JSET: return "JSET";
        case BPF_JNE: return "JNE";
        case BPF_JSGT: return "JSGT";
        case BPF_JSGE: return "JSGE";
        case BPF_CALL: return "CALL";
        case BPF_EXIT: return "EXIT";
        case BPF_JLT: return "JLT";
        case BPF_JLE: return "JLE";
        case BPF_JSLT: return "JSLT";
        case BPF_JSLE: return "JSLE";
        default: return "UNKNOWN";
    }
}

int dump_bpf_insn(struct bpf_insn *insn, size_t idx) {
    printf("[%4zu] code=0x%02x dst=%d src=%d off=%d imm=%d | ",
           idx, insn->code, insn->dst_reg, insn->src_reg, insn->off, insn->imm);
    
    uint8_t cls = BPF_CLASS(insn->code);
    
    // Check if this is a 64-bit immediate load (uses 2 instructions)
    int is_imm64 = (cls == BPF_LD && BPF_MODE(insn->code) == BPF_IMM && 
                    BPF_SIZE(insn->code) == BPF_DW);
    
    if (cls == BPF_ALU || cls == BPF_ALU64) {
        printf("%s_%s", cls == BPF_ALU64 ? "ALU64" : "ALU", get_alu_op_name(insn->code));
        if (BPF_SRC(insn->code) == BPF_X) {
            printf(" r%d, r%d", insn->dst_reg, insn->src_reg);
        } else {
            printf(" r%d, 0x%x", insn->dst_reg, insn->imm);
        }
    } else if (cls == BPF_JMP) {
        printf("JMP_%s", get_jmp_op_name(insn->code));
        if (BPF_OP(insn->code) == BPF_CALL) {
            printf(" %d", insn->imm);
        } else if (BPF_OP(insn->code) == BPF_EXIT) {
            // No operands
        } else if (BPF_OP(insn->code) == BPF_JA) {
            printf(" %+d", insn->off);
        } else {
            if (BPF_SRC(insn->code) == BPF_X) {
                printf(" r%d, r%d, %+d", insn->dst_reg, insn->src_reg, insn->off);
            } else {
                printf(" r%d, 0x%x, %+d", insn->dst_reg, insn->imm, insn->off);
            }
        }
    } else if (cls == BPF_LDX) {
        printf("LDX_%s [r%d%+d], r%d", get_size_name(insn->code), 
               insn->src_reg, insn->off, insn->dst_reg);
    } else if (cls == BPF_STX) {
        printf("STX_%s [r%d%+d], r%d", get_size_name(insn->code),
               insn->dst_reg, insn->off, insn->src_reg);
    } else if (cls == BPF_ST) {
        printf("ST_%s [r%d%+d], 0x%x", get_size_name(insn->code),
               insn->dst_reg, insn->off, insn->imm);
    } else if (cls == BPF_LD) {
        if (BPF_MODE(insn->code) == BPF_IMM && BPF_SIZE(insn->code) == BPF_DW) {
            // 64-bit immediate is split across this instruction and the next
            // Lower 32 bits are in this insn->imm, upper 32 bits in next insn->imm
            printf("LD_IMM64 r%d, 0x%x [lower 32 bits; next insn has upper 32]", 
                   insn->dst_reg, insn->imm);
        } else {
            printf("LD_%s_%s", get_size_name(insn->code), 
                   BPF_MODE(insn->code) == BPF_ABS ? "ABS" : 
                   BPF_MODE(insn->code) == BPF_IND ? "IND" : "?");
        }
    } else {
        printf("%s (details not decoded)", get_class_name(insn->code));
    }
    
    printf("\n");
    
    return is_imm64 ? 1 : 0;  // Return 1 if next insn is part of this one
}
