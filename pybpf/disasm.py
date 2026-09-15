"""Rendering one BPF instruction as text, for bpf_dump."""

from . import bpf


def _hex32(v):
    """C's `printf("0x%x", (int)v)`: the two's-complement pattern."""
    return "0x%x" % (v & 0xffffffff)


def format_insn(in_, idx):
    """The decoded line for one instruction, without a trailing newline."""
    head = ("[%4d] code=0x%02x dst=%d src=%d off=%d imm=%d | "
            % (idx, in_.code, in_.dst, in_.src, in_.off, in_.imm))
    c = in_.cls
    body = ""

    if c in (bpf.ALU, bpf.ALU64):
        body = "%s_%s" % ("ALU64" if c == bpf.ALU64 else "ALU",
                          bpf.ALU_OP_NAME.get(in_.op, "UNKNOWN"))
        if bpf.src(in_.code) == bpf.X:
            body += " r%d, r%d" % (in_.dst, in_.src)
        else:
            body += " r%d, %s" % (in_.dst, _hex32(in_.imm))
    elif c in (bpf.JMP, bpf.JMP32):
        # Same operand shape; JMP32 just compares the low 32 bits.
        body = "%s_%s" % ("JMP32" if c == bpf.JMP32 else "JMP",
                          bpf.JMP_OP_NAME.get(in_.op, "UNKNOWN"))
        if in_.op == bpf.CALL:
            body += " %d" % in_.imm
        elif in_.op == bpf.EXIT:
            pass
        elif in_.op == bpf.JA:
            body += " %+d" % in_.off
        elif bpf.src(in_.code) == bpf.X:
            body += " r%d, r%d, %+d" % (in_.dst, in_.src, in_.off)
        else:
            body += " r%d, %s, %+d" % (in_.dst, _hex32(in_.imm), in_.off)
    elif c == bpf.LDX:
        body = "LDX_%s [r%d%+d], r%d" % (bpf.SIZE_NAME.get(in_.size, "?"),
                                         in_.src, in_.off, in_.dst)
    elif c == bpf.STX:
        body = "STX_%s [r%d%+d], r%d" % (bpf.SIZE_NAME.get(in_.size, "?"),
                                         in_.dst, in_.off, in_.src)
    elif c == bpf.ST:
        body = "ST_%s [r%d%+d], %s" % (bpf.SIZE_NAME.get(in_.size, "?"),
                                       in_.dst, in_.off, _hex32(in_.imm))
    elif c == bpf.LD:
        if in_.mode == bpf.IMM and in_.size == bpf.DW:
            # The 64-bit immediate is split across this instruction and the
            # next: low half here, high half in the next imm.
            body = ("LD_IMM64 r%d, %s [lower 32 bits; next insn has upper 32]"
                    % (in_.dst, _hex32(in_.imm)))
        else:
            body = "LD_%s_%s" % (
                bpf.SIZE_NAME.get(in_.size, "?"),
                "ABS" if in_.mode == bpf.ABS else
                "IND" if in_.mode == bpf.IND else "?")
    else:
        body = "%s (details not decoded)" % bpf.CLASS_NAME.get(c, "UNKNOWN")

    return head + body


def is_imm64(in_):
    """True if the following instruction is the upper half of this one."""
    return in_.cls == bpf.LD and in_.mode == bpf.IMM and in_.size == bpf.DW
