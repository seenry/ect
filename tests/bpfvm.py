"""A reference interpreter for the BPF subset bpf_to_ir translates.

Deliberately written from the ISA rather than from the translator, so that
agreeing with it says something.  Registers are 64-bit; a 32-bit ALU op
computes on the low halves and ZERO-EXTENDS the result, which is the part
lowerings most often get wrong.
"""

from pybpf import bpf

M64 = (1 << 64) - 1
M32 = (1 << 32) - 1


def _s(v, bits):
    """Reinterpret an unsigned value as signed at `bits` width."""
    return v - (1 << bits) if v >> (bits - 1) else v


def _alu(op, x, y, bits):
    m = (1 << bits) - 1
    if op == bpf.ADD:  return (x + y) & m
    if op == bpf.SUB:  return (x - y) & m
    if op == bpf.AND:  return x & y
    if op == bpf.OR:   return x | y
    if op == bpf.XOR:  return x ^ y
    if op == bpf.MUL:  return (x * y) & m
    if op == bpf.DIV:  return 0 if y == 0 else (x // y) & m
    if op == bpf.MOD:  return x if y == 0 else (x % y) & m
    if op == bpf.MOV:  return y & m
    if op == bpf.NEG:  return (-x) & m
    if op == bpf.LSH:  return (x << (y & (bits - 1))) & m
    if op == bpf.RSH:  return (x >> (y & (bits - 1))) & m
    if op == bpf.ARSH:
        k = y & (bits - 1)
        return (_s(x, bits) >> k) & m
    raise AssertionError("unhandled ALU op 0x%x" % op)


def _cmp(op, a, b, bits):
    sa, sb = _s(a, bits), _s(b, bits)
    return {
        bpf.JEQ:  a == b,   bpf.JNE:  a != b,
        bpf.JGT:  a > b,    bpf.JGE:  a >= b,
        bpf.JLT:  a < b,    bpf.JLE:  a <= b,
        bpf.JSGT: sa > sb,  bpf.JSGE: sa >= sb,
        bpf.JSLT: sa < sb,  bpf.JSLE: sa <= sb,
        bpf.JSET: (a & b) != 0,
    }[op]


class Halt(Exception):
    pass


def run(insns, regs=None, fuel=100000):
    """Execute until EXIT.  Returns r0."""
    r = [0] * 11
    if regs:
        r.update if False else None
        for k, v in regs.items():
            r[k] = v & M64
    pc = 0
    for _ in range(fuel):
        if pc >= len(insns):
            return r[0]
        in_ = insns[pc]
        c = in_.cls

        if in_.code == bpf.LD_IMM64:
            v = ((insns[pc + 1].imm & M32) << 32) | (in_.imm & M32)
            r[in_.dst] = v
            pc += 2
            continue

        if c in (bpf.ALU, bpf.ALU64):
            bits = 64 if c == bpf.ALU64 else 32
            op = in_.op
            x = r[in_.dst] & ((1 << bits) - 1)
            if op == bpf.END:
                nb = in_.imm // 8
                v = r[in_.dst] & ((1 << in_.imm) - 1) if in_.imm != 64 else r[in_.dst]
                if c == bpf.ALU64 or bpf.src(in_.code) == bpf.X:   # swap
                    v = int.from_bytes(v.to_bytes(nb, "little"), "big")
                r[in_.dst] = v & M64            # assigned through a uN: zero-extends
                pc += 1
                continue
            if op == bpf.NEG:
                y = 0
            elif in_.is_imm:
                # A 64-bit op sign-extends its immediate; a 32-bit one uses
                # the 32-bit pattern.
                y = (in_.imm & M64) if bits == 64 else (in_.imm & M32)
            else:
                y = r[in_.src] & ((1 << bits) - 1)
            res = _alu(op, x, y, bits)
            r[in_.dst] = res if bits == 64 else (res & M32)   # zero-extend
            pc += 1
            continue

        if c in (bpf.JMP, bpf.JMP32):
            op = in_.op
            if op == bpf.EXIT:
                return r[0]
            if op == bpf.JA:
                pc += 1 + in_.off
                continue
            if op == bpf.CALL:
                raise Halt("CALL is not modelled")
            bits = 32 if c == bpf.JMP32 else 64
            a = r[in_.dst] & ((1 << bits) - 1)
            b = ((in_.imm & M64) if bits == 64 else (in_.imm & M32)) \
                if in_.is_imm else (r[in_.src] & ((1 << bits) - 1))
            pc += 1 + (in_.off if _cmp(op, a, b, bits) else 0)
            continue

        raise Halt("class 0x%x is not modelled" % c)
    raise Halt("out of fuel")
