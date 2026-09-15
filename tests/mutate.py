"""Mutating a BPF object, and deciding by EXECUTION whether the mutation
changed the program.

K2's proposal distribution (src/search/proposals.cc) is deliberately blind --
replace an operand, replace an instruction, nop one out -- and its SMT
equivalence checker is the filter that decides which proposals are valid.  So
there is no catalogue of "these preserve semantics" to borrow.

We do not need one.  With a concrete interpreter for the lowered IR we can
decide each pair empirically, and the two directions are not symmetric:

  * a seed on which the two lowered programs produce DIFFERENT observable
    output is a PROOF that they are inequivalent, so the checker answering
    Equivalent would be a soundness bug.  Sound.

  * agreement on every seed we tried is only evidence, not proof, so a
    NotEquivalent verdict there is something to triage rather than a failure.

That asymmetry is the opposite of the usual metamorphic-testing intuition, and
it matters here: the both-rejected disjunct makes "Equivalent" cheap, so the
direction that actually pins the checker down is the inequivalent one.

Mutations are same-length and in place, so no jump offset or relocation needs
fixing up.
"""

import random
import re
import struct

from pybpf import bpf
from pybpf.elf import Elf, SHF_EXECINSTR

_REGION = re.compile(r"\(mr_id (\d+)\) \(mr_len (\d+)\)")


def regions_of(ir_text):
    """The regions a program declares: id -> length in bytes."""
    return {int(a): int(b) for a, b in _REGION.findall(ir_text)}


def observable(runner, ir_text, seeds):
    """What the equivalence checker compares, as the extracted evaluator
    reports it: the emitted packet, then every region's final contents and
    access extent.  A rejecting run reports only "reject", so two runs that
    both reject are indistinguishable -- which is exactly how the checker
    treats them."""
    return tuple(runner.observe(ir_text, seeds))


def prog_section(blob):
    """(section index, byte offset, instruction count) of the program."""
    e = Elf(blob)
    for s in e.sections:
        if s.size and (s.flags & SHF_EXECINSTR):
            return s.index, s.offset, s.size // bpf.INSN_SIZE
    raise ValueError("no executable section")


def _patch(blob, off, code=None, regs=None, imm=None, joff=None):
    b = bytearray(blob)
    if code is not None:
        b[off] = code
    if regs is not None:
        b[off + 1] = regs
    if joff is not None:
        b[off + 2:off + 4] = struct.pack("<h", joff)
    if imm is not None:
        b[off + 4:off + 8] = struct.pack("<i", imm)
    return bytes(b)


def mutations(blob, rng=None):
    """Yield (name, mutated blob).  Same length, in place, one instruction.

    Deterministic: the alternative opcode is the next one in a fixed order,
    not a random pick, so a label like `aluop@3 AND->OR` names the same edit
    on every run and can be referred to from a fixture table.  `rng` is
    accepted and ignored, for callers that pass one."""
    _, base, n = prog_section(blob)
    insns = bpf.decode(blob[base:base + n * bpf.INSN_SIZE])

    for i, ins in enumerate(insns):
        off = base + i * bpf.INSN_SIZE
        c = ins.cls

        if c in (bpf.ALU, bpf.ALU64) and ins.is_imm and ins.op != bpf.END:
            yield ("imm@%d %d->%d" % (i, ins.imm, ins.imm + 1),
                   _patch(blob, off, imm=ins.imm + 1))
            if ins.imm != 0:
                yield ("imm@%d ->0" % i, _patch(blob, off, imm=0))

        if c in (bpf.ALU, bpf.ALU64) and ins.op in bpf.ALU_BINOP:
            order = sorted(bpf.ALU_BINOP)
            alt = order[(order.index(ins.op) + 1) % len(order)]
            yield ("aluop@%d %s->%s" % (i, bpf.ALU_OP_NAME[ins.op],
                                        bpf.ALU_OP_NAME[alt]),
                   _patch(blob, off, code=(ins.code & ~0xf0) | alt))

        if c in (bpf.ALU, bpf.ALU64):
            # Swap the class: a 64-bit op becomes 32-bit, which zero-extends.
            other = bpf.ALU if c == bpf.ALU64 else bpf.ALU64
            yield ("aluwidth@%d" % i,
                   _patch(blob, off, code=(ins.code & ~0x07) | other))

        if c in (bpf.JMP, bpf.JMP32) and ins.op not in (bpf.JA, bpf.EXIT, bpf.CALL):
            order = [bpf.JEQ, bpf.JNE, bpf.JGT, bpf.JGE, bpf.JLT,
                     bpf.JLE, bpf.JSGT, bpf.JSGE, bpf.JSLT, bpf.JSLE]
            alt = order[(order.index(ins.op) + 1) % len(order)] \
                if ins.op in order else bpf.JEQ
            yield ("jmpop@%d %s->%s" % (i, bpf.JMP_OP_NAME[ins.op],
                                        bpf.JMP_OP_NAME[alt]),
                   _patch(blob, off, code=(ins.code & ~0xf0) | alt))
            if ins.off > 1:
                yield ("jmpoff@%d %+d->%+d" % (i, ins.off, ins.off - 1),
                       _patch(blob, off, joff=ins.off - 1))

        if c in (bpf.LDX, bpf.STX) and ins.mode == bpf.MEM:
            for nm, sz in (("W8", bpf.B), ("W16", bpf.H), ("W32", bpf.W)):
                if sz != ins.size:
                    yield ("memwidth@%d ->%s" % (i, nm),
                           _patch(blob, off, code=(ins.code & ~0x18) | sz))
                    break
            yield ("memoff@%d %+d->%+d" % (i, ins.off, ins.off + 1),
                   _patch(blob, off, joff=ins.off + 1))

        # K2's mod_random_inst_as_nop: delete by turning into `JA +0`.
        if c not in (bpf.JMP, bpf.JMP32):
            yield ("nop@%d" % i, _patch(blob, off, code=bpf.JMP | bpf.JA,
                                        regs=0, joff=0, imm=0))


# ── the checker's counterexample ────────────────────────────────────────

import re as _re

_MEM = _re.compile(r"\|\s*mem\(\s*mem_([01]+)\s*\)\s*:\s*len=(\d+)\s*:=\s*\[(.*)\]")


def parse_witness(stdout):
    """Turn EqCheck's SAT valuation into seeds for the runner.

    Region variables are named mem_<n> where n is the region id in BINARY
    (pos_to_string prints a positive's bits), so mem_1010 is region 10.  A
    cell prints as `value:type`, or `err` for ErrorVal -- which cannot be
    seeded, and a witness containing one is reported rather than used.
    """
    seeds, poisoned = [], []
    for line in stdout.splitlines():
        m = _MEM.search(line)
        if not m:
            continue
        region = int(m.group(1), 2)
        for off, tok in enumerate(c.strip() for c in m.group(3).split(",")):
            if ":" not in tok:
                poisoned.append((region, off, tok))
                continue
            val, _ty = tok.rsplit(":", 1)
            seeds.append((region, off, 1, int(val) & 0xff))
    return seeds, poisoned
