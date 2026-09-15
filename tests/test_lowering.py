"""Property-based tests for the lowering itself.

The interesting property is semantic: for a randomly generated BPF program,
running the LOWERED IR must produce the same return value as running the
original bytecode.  That needs two independent interpreters --

  tests/bpfvm.py    the BPF ISA, written from the ISA
  EqCheck --serve   the EXTRACTED evaluator, driven through tests/irrunner.py

-- and it exercises, on every example, the whole tier of the translator that
has no other oracle: the 32-bit narrow/widen dance, the synthesized shifts and
byte swaps, emit_condition's arm-swapping, block splitting, and the
program-counter threading that sequences the transformer chain.

Generation is restricted to what the translator claims to support: no memory,
no calls, no register shifts, and forward jumps only.  A generated program
that the translator rejects is therefore itself a failure.
"""

import io
import os
import sys

from hypothesis import given, settings, strategies as st, HealthCheck, assume

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import bpfvm
from irrunner import emitted_u32, shared
from sexp import coq_list, parse
from mkobj import insn, build
from pybpf import bpf
from pybpf.translate import Translator, CTX_XDP_MD

M32 = (1 << 32) - 1

# A small register file and a small pool of immediates, deliberately.  With
# 32-bit immediates drawn at random, two compared values are essentially never
# EQUAL, and the "or equal" jump forms differ from their strict counterparts
# only at equality -- so a JSGE compiled as JSGT would never be caught.  Ties
# have to be made likely on purpose.
REGS = st.integers(min_value=0, max_value=5)
_POOL = [0, 1, -1, 2, 7, -7, 8, 255, 256, -256, 0x7fffffff, -2**31,
         0xff, 0x8000, 42, -42]
IMMS = st.one_of(
    st.sampled_from(_POOL),                          # collide often
    st.integers(min_value=-8, max_value=8),
    st.integers(min_value=-2**31, max_value=2**31 - 1),
)

_ALU = [bpf.ADD, bpf.SUB, bpf.AND, bpf.OR, bpf.XOR, bpf.MUL, bpf.DIV,
        bpf.MOD, bpf.MOV]
_SHIFT = [bpf.LSH, bpf.RSH, bpf.ARSH]          # constant only; by-register is rejected
_JMP = [bpf.JEQ, bpf.JNE, bpf.JGT, bpf.JGE, bpf.JLT, bpf.JLE,
        bpf.JSGT, bpf.JSGE, bpf.JSLT, bpf.JSLE, bpf.JSET]


@st.composite
def descriptors(draw, max_len=16):
    """A list of instruction descriptors.  Jump offsets are patched afterwards,
    once the body length is known, so every jump goes forward and lands inside
    the program."""
    n = draw(st.integers(min_value=1, max_value=max_len))
    out = []
    for _ in range(n):
        kind = draw(st.sampled_from(
            ["alu64", "alu32", "shift64", "shift32", "neg", "end",
             "jmp", "jmp32", "tie", "tie32", "narrow"]))
        out.append((kind,
                    draw(st.sampled_from(_ALU if kind.startswith("alu")
                                         else _SHIFT if kind.startswith("shift")
                                         else _JMP if kind.startswith(("jmp", "tie"))
                                         else [bpf.MOV])),
                    draw(REGS), draw(REGS), draw(IMMS),
                    draw(st.booleans()),                 # use a register operand
                    draw(st.integers(min_value=1, max_value=6)),   # jump distance
                    draw(st.sampled_from([16, 32, 64]))))          # END width
    return out


def assemble(descs):
    """Descriptors -> instruction bytes.

    A prologue defines every register, since the verifier rejects reading an
    undefined one and the translator's preamble assumes that cannot happen.
    An epilogue then folds the whole register file into r0 -- see below."""
    body = []          # [bytes]
    jumps = []         # (index in body, requested distance)

    for r in range(10):
        body.append(insn(bpf.ALU64 | bpf.MOV | bpf.K, dst=r, imm=(r * 37) - 5))

    for (kind, op, dst, src, imm, use_reg, dist, ew) in descs:
        if kind == "alu64":
            body.append(insn(bpf.ALU64 | op | (bpf.X if use_reg else bpf.K),
                             dst=dst, src=src, imm=imm))
        elif kind == "alu32":
            body.append(insn(bpf.ALU | op | (bpf.X if use_reg else bpf.K),
                             dst=dst, src=src, imm=imm))
        elif kind == "narrow":
            # A 32-bit op with a NEGATIVE immediate, as the last write to a
            # register.  Its result must be zero-extended, and a lowering that
            # sign-extends instead differs only in the register's high half --
            # invisible unless something folds that half down, which is what
            # the epilogue is for.
            body.append(insn(bpf.ALU | op | bpf.K, dst=dst,
                             imm=-(abs(imm) or 1)))
        elif kind.startswith("shift"):
            # The raw immediate, NOT pre-masked: masking the shift count to
            # the operand width is the translator's job, and pre-masking here
            # would hide a wrong mask.
            body.append(insn((bpf.ALU64 if kind == "shift64" else bpf.ALU)
                             | op | bpf.K, dst=dst, imm=imm))
        elif kind == "neg":
            body.append(insn((bpf.ALU64 if use_reg else bpf.ALU) | bpf.NEG,
                             dst=dst))
        elif kind == "end":
            body.append(insn((bpf.ALU64 if use_reg else bpf.ALU)
                             | bpf.END | (bpf.X if use_reg else bpf.K),
                             dst=dst, imm=ew))
        elif kind in ("tie", "tie32"):
            # Two registers set to the SAME value, then compared.  The "or
            # equal" jump forms differ from their strict counterparts only at
            # equality, and with random immediates two computed values are
            # essentially never equal -- so ties have to be constructed.
            a, b = dst, (dst + 1) % 6
            body.append(insn(bpf.ALU64 | bpf.MOV | bpf.K, dst=a, imm=imm))
            body.append(insn(bpf.ALU64 | bpf.MOV | bpf.K, dst=b, imm=imm))
            jumps.append((len(body), dist))
            body.append(insn((bpf.JMP32 if kind == "tie32" else bpf.JMP)
                             | op | bpf.X, dst=a, src=b, off=0))
        else:                                   # a forward conditional jump
            jumps.append((len(body), dist))
            body.append(insn((bpf.JMP32 if kind == "jmp32" else bpf.JMP)
                             | op | (bpf.X if use_reg else bpf.K),
                             dst=dst, src=src, off=0, imm=imm))

    # Patch every jump to a forward target inside the body.
    for idx, dist in jumps:
        off = max(0, min(dist, len(body) - idx - 1))
        old = body[idx]
        body[idx] = old[:2] + off.to_bytes(2, "little", signed=True) + old[4:]

    # An epilogue that makes the whole register file observable.
    #
    # Only r0's low 32 bits are emitted, and add/sub/and/or/xor/mul propagate
    # low bits from low bits -- so a difference confined to a register's HIGH
    # half, which is exactly what a wrong 32-bit zero-extension produces, never
    # reaches the output.  Folding each register's high half down and xoring
    # everything into r0 makes those differences visible.
    for reg in range(1, 10):
        body.append(insn(bpf.ALU64 | bpf.XOR | bpf.X, dst=0, src=reg))
        body.append(insn(bpf.ALU64 | bpf.RSH | bpf.K, dst=reg, imm=32))
        body.append(insn(bpf.ALU64 | bpf.XOR | bpf.X, dst=0, src=reg))
    # and r0's own high half (r9 is spent by now, so it is free scratch)
    body.append(insn(bpf.ALU64 | bpf.MOV | bpf.X, dst=9, src=0))
    body.append(insn(bpf.ALU64 | bpf.RSH | bpf.K, dst=9, imm=32))
    body.append(insn(bpf.ALU64 | bpf.XOR | bpf.X, dst=0, src=9))
    body.append(insn(bpf.JMP | bpf.EXIT))
    return body, 10


def lower(insn_blobs):
    """Assemble, translate, and return the IR text (raising if the translator
    reported anything)."""
    obj = build(insn_blobs)
    t = Translator()
    buf = io.StringIO()
    rc = t.run(obj, CTX_XDP_MD, buf)
    assert rc == 0, "translator refused a supported program"
    assert not t.had_error, "translator reported an unsupported construct"
    return buf.getvalue()


SETTINGS = settings(max_examples=500, deadline=None,
                    suppress_health_check=[HealthCheck.too_slow])


@given(descriptors())
@SETTINGS
def test_lowering_preserves_the_return_value(descs):
    """The property that matters: the lowered IR returns what the bytecode
    returns.  Only the low 32 bits are observable -- the deparser emits r0 as
    a u32, which is what an eBPF program's return value is."""
    blobs, _ = assemble(descs)
    insns = bpf.decode(b"".join(blobs))
    try:
        want = bpfvm.run(insns) & M32
    except bpfvm.Halt:
        assume(False)
        return
    got = emitted_u32(shared().observe(lower(blobs)))
    assert got is not None, "the lowered program rejected; these generate no " \
                            "memory access, so nothing should overrun"
    assert got == want, (
        "lowered program returned 0x%08x, bytecode returned 0x%08x"
        % (got, want))


@given(descriptors())
@SETTINGS
def test_every_transformer_ends_with_a_default_rule(descs):
    """CrDslProperties.transformer_has_default: the LAST rule must have an
    empty match pattern, so a state whose pc names no block always has a rule
    to fall through to.  Its ops are unconstrained -- which is why the
    preamble transformer, whose single unconditional rule does the seeding, is
    legal without a separate no-op rule after it."""
    blobs, _ = assemble(descs)
    n = parse(lower(blobs))
    net = {f[0]: f[1] for f in n[3]}
    for m in coq_list(net["net_modules"]):
        if m[0] != "TransformerModule":
            continue
        rules = coq_list(m[4])
        assert rules, "a transformer with no rules"
        last = rules[-1][1]                       # (SeqCtr <matches> <ops>)
        assert last[1] == "Coq_nil", \
            "the last rule of module %s has a match pattern, so a pc that " \
            "names no block would fall through it" % m[1]


@given(descriptors())
@SETTINGS
def test_the_module_chain_is_a_linear_path(descs):
    """The semantics assume a linear chain: one parser source, one deparser
    sink, no fan-in or fan-out.  Following the edges must visit every module
    exactly once."""
    blobs, _ = assemble(descs)
    n = parse(lower(blobs))
    net = {f[0]: f[1] for f in n[3]}
    mods = [int(m[1]) for m in coq_list(net["net_modules"])]
    edges = [(int(e[0]), int(e[1])) for e in net["net_edges"]]
    srcs = [a for a, _ in edges]
    dsts = [b for _, b in edges]
    assert len(set(srcs)) == len(srcs), "a module with two outgoing edges"
    assert len(set(dsts)) == len(dsts), "a module with two incoming edges"
    walked, cur = [], int(net["start_module"])
    nxt = dict(edges)
    while cur is not None:
        walked.append(cur)
        cur = nxt.get(cur)
    assert sorted(walked) == sorted(mods), "the chain does not cover every module"


@given(descriptors())
@SETTINGS
def test_only_allocated_headers_are_named(descs):
    """Every header the output names must be one the allocation scheme owns:
    the pc, a register, a scratch slot, or a stack slot.  A scratch id outside
    30..37 would mean fresh_tmp wrapped, which silently aliases two live
    values."""
    import re
    blobs, _ = assemble(descs)
    text = lower(blobs)
    for m in re.findall(r"OpHeader (\d+)|\(Coq_pair \(Coq_pair (\d+) Cmp", text):
        h = int(m[0] or m[1])
        assert h == 1 or 10 <= h <= 20 or 30 <= h <= 37 or h >= 100, \
            "header %d is outside every allocated range" % h


@given(descriptors())
@SETTINGS
def test_lowering_is_deterministic(descs):
    """Two lowerings of one object must be byte-identical.  Region ids come
    from a sort and stack-slot header ids from allocation order, so a stray
    dependence on dict or set iteration order would show up here."""
    blobs, _ = assemble(descs)
    assert lower(blobs) == lower(blobs)


@given(descriptors())
@SETTINGS
def test_declares_exactly_the_ctx_and_packet_regions(descs):
    """These programs touch no map, so the declarations must be exactly the
    two unconditional regions -- the checker refuses to compare two programs
    whose declarations differ, so a spurious one would make every comparison
    against a real program fail as NotEquivalentVariablesDiffer."""
    blobs, _ = assemble(descs)
    n = parse(lower(blobs))
    decls = {int(d[0][1]): int(d[1][1]) for d in coq_list(n[2])}
    assert decls == {1: CTX_XDP_MD.length, 2: 64}, decls
