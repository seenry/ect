"""BPF instruction encoding: the constants from the old include/bpf.h, plus
decoding of the 8-byte instruction.

An opcode byte is read three ways at once -- class, then either (size, mode)
for the load/store classes or (op, src) for ALU and JMP -- which is why the
accessors below are separate functions rather than one decode step.
"""

import struct
from dataclasses import dataclass

# ── Instruction classes (low 3 bits) ────────────────────────────────────
LD, LDX, ST, STX, ALU, JMP, JMP32, ALU64 = range(8)
# 0x06 was BPF_RET in classic BPF; eBPF reassigned it to the 32-bit compare
# class, whose operands are the low halves of the two registers.

# ── Size (bits 3-4), for the load/store classes ─────────────────────────
W, H, B, DW = 0x00, 0x08, 0x10, 0x18

# ── Mode (top 3 bits) ───────────────────────────────────────────────────
IMM, ABS, IND, MEM, ATOMIC = 0x00, 0x20, 0x40, 0x60, 0xc0

# ── ALU / JMP operation (high nibble) ───────────────────────────────────
ADD, SUB, MUL, DIV, OR, AND, LSH, RSH, NEG, MOD, XOR, MOV, ARSH, END = (
    0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60,
    0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0)

JA, JEQ, JGT, JGE, JSET, JNE, JSGT, JSGE = (
    0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70)
CALL, EXIT, JLT, JLE, JSLT, JSLE = 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0

# ── Source modifier (bit 3), for ALU and JMP ────────────────────────────
K, X = 0x00, 0x08

# A whole opcode byte rather than a field: BPF_LD | BPF_IMM | BPF_DW, the
# two-slot wide immediate load.
LD_IMM64 = LD | IMM | DW

INSN_SIZE = 8

def cls(code):  return code & 0x07
def size(code): return code & 0x18
def mode(code): return code & 0xe0
def op(code):   return code & 0xf0
def src(code):  return code & 0x08


@dataclass(frozen=True)
class Insn:
    """One 8-byte BPF instruction.

    `dst` and `src` are the two nibbles of the second byte -- dst is the low
    one, which is what a little-endian target's `__u8 dst_reg:4` allocates.
    `off` is signed 16-bit and `imm` signed 32-bit, both as the ISA defines
    them; sign extension to 64 bits is the caller's business because it
    differs per instruction.
    """
    code: int
    dst: int
    src: int
    off: int
    imm: int

    @property
    def cls(self):  return cls(self.code)
    @property
    def size(self): return size(self.code)
    @property
    def mode(self): return mode(self.code)
    @property
    def op(self):   return op(self.code)
    @property
    def is_imm(self):  return src(self.code) == K
    @property
    def is_jmp(self):  return self.cls in (JMP, JMP32)
    @property
    def is_nop_jump(self):
        """A jump to the immediately following instruction: no control flow at
        all.  clang emits a lot of them."""
        return self.is_jmp and self.op == JA and self.off == 0


def decode(blob):
    """Decode a byte string into a list of Insn."""
    out = []
    for (code, regs, off, imm) in struct.iter_unpack("<BBhi", blob):
        out.append(Insn(code, regs & 0x0f, (regs >> 4) & 0x0f, off, imm))
    return out


def size_bytes(code):
    return {B: 1, H: 2, W: 4}.get(size(code), 8)


def width_name(nbytes):
    return {1: "W8", 2: "W16", 4: "W32"}.get(nbytes, "W64")


ALU_BINOP = {
    ADD: "AddOp", SUB: "SubOp", AND: "AndOp", OR: "OrOp", XOR: "XorOp",
    MUL: "MulOp",
    DIV: "DivOp",   # unsigned; x/0 = 0, as in BPF
    MOD: "ModOp",   # unsigned; x%0 = x, as in BPF
}

CLASS_NAME = {LD: "LD", LDX: "LDX", ST: "ST", STX: "STX",
              ALU: "ALU", JMP: "JMP", JMP32: "JMP32", ALU64: "ALU64"}
SIZE_NAME = {W: "W", H: "H", B: "B", DW: "DW"}
ALU_OP_NAME = {ADD: "ADD", SUB: "SUB", MUL: "MUL", DIV: "DIV", OR: "OR",
               AND: "AND", LSH: "LSH", RSH: "RSH", NEG: "NEG", MOD: "MOD",
               XOR: "XOR", MOV: "MOV", ARSH: "ARSH", END: "END"}
JMP_OP_NAME = {JA: "JA", JEQ: "JEQ", JGT: "JGT", JGE: "JGE", JSET: "JSET",
               JNE: "JNE", JSGT: "JSGT", JSGE: "JSGE", CALL: "CALL",
               EXIT: "EXIT", JLT: "JLT", JLE: "JLE", JSLT: "JSLT",
               JSLE: "JSLE"}
