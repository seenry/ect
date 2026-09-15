"""The synthesized operators: run what they emit and check the result.

These are the paths with no natural coverage in the example programs -- the
compiler canonicalises most of them away -- and the ones where a subtle
arithmetic slip would produce a plausible program that silently means
something else.
"""

import os
import random
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mkobj import build, insn
from opeval import eval_ops
from pybpf import bpf
from pybpf.ir import Ops
from pybpf.translate import (Translator, H_TMP, join_reg, RegInfo, SCALAR,
                             pointer, map_pointer, ctx_layout_for,
                             ctx_layout_by_name, CTX_XDP_MD, CTX_SK_BUFF,
                             T_CTX, T_PKT, T_MAP, T_MAPVAL, T_SCALAR, T_UNKNOWN)

MASK64 = (1 << 64) - 1
SRC, DST = 60, 61          # headers outside the scratch pool


class TestBswap(unittest.TestCase):
    def run_bswap(self, value, nbytes):
        t = Translator()
        t.ops = Ops()
        t.emit_bswap(0, SRC, nbytes, DST)
        return eval_ops(t.ops.ops, {SRC: value})[DST]

    def test_matches_python_byteswap(self):
        for nbytes in (2, 4, 8):
            for value in [0, 1, 0xff, 0x0102030405060708, MASK64,
                          0xdeadbeefcafebabe] + \
                         [random.getrandbits(64) for _ in range(64)]:
                got = self.run_bswap(value, nbytes)
                want = int.from_bytes(
                    (value & ((1 << (8 * nbytes)) - 1)).to_bytes(nbytes, "little"),
                    "big")
                self.assertEqual(got, want,
                                 "bswap%d(0x%x)" % (nbytes * 8, value))

    def test_one_byte_is_a_move(self):
        self.assertEqual(self.run_bswap(0xab, 1), 0xab)

    def test_swapping_in_place_reads_the_source_once(self):
        # The caller is allowed to pass the same header as src and target;
        # emit_bswap copies to scratch first, so this must not feed partial
        # results back into itself.
        t = Translator()
        t.ops = Ops()
        t.emit_bswap(0, SRC, 4, SRC)
        self.assertEqual(eval_ops(t.ops.ops, {SRC: 0x01020304})[SRC],
                         0x04030201)

    def test_uses_no_more_scratch_than_the_pool(self):
        t = Translator()
        t.ops = Ops()
        t.emit_bswap(0, SRC, 8, DST)
        self.assertFalse(t.had_error)


class TestArsh(unittest.TestCase):
    def run_arsh(self, value, k, width):
        t = Translator()
        t.ops = Ops()
        t.emit_arsh_const(0, DST, k, width)
        return eval_ops(t.ops.ops, {DST: value})[DST]

    def test_matches_a_signed_shift(self):
        for width in (32, 64):
            m = (1 << width) - 1
            for value in [0, 1, m, m >> 1, (1 << (width - 1)),
                          (1 << (width - 1)) | 12345] + \
                         [random.getrandbits(width) for _ in range(48)]:
                for k in range(1, width):
                    signed = value - (1 << width) if value >> (width - 1) else value
                    want = (signed >> k) & m
                    self.assertEqual(self.run_arsh(value, k, width), want,
                                     "arsh(0x%x, %d) at %d" % (value, k, width))

    def test_shift_of_zero_is_a_noop(self):
        t = Translator()
        t.ops = Ops()
        t.emit_arsh_const(0, DST, 0, 64)
        self.assertEqual(t.ops.ops, [])
        self.assertFalse(t.had_error)


class TestJoin(unittest.TestCase):
    """The abstract-interpretation lattice.  A wrong join gives a register the
    wrong region tag, and the consequence surfaces far away as a mis-regioned
    load."""

    def test_same_tag_same_offset_is_preserved(self):
        a = pointer(T_CTX, 8)
        self.assertEqual(join_reg(a, a), a)

    def test_same_tag_different_offset_loses_the_offset(self):
        j = join_reg(pointer(T_CTX, 8), pointer(T_CTX, 12))
        self.assertEqual(j.tag, T_CTX)
        self.assertFalse(j.off_known)

    def test_different_tags_are_unknown(self):
        j = join_reg(pointer(T_CTX, 0), pointer(T_PKT, 0))
        self.assertEqual(j.tag, T_UNKNOWN)
        self.assertFalse(j.off_known)

    def test_two_different_maps_do_not_merge(self):
        # Merging them would let a dereference name the wrong region.
        j = join_reg(map_pointer(T_MAPVAL, 0, 0), map_pointer(T_MAPVAL, 0, 1))
        self.assertEqual(j.tag, T_UNKNOWN)

    def test_same_map_merges(self):
        j = join_reg(map_pointer(T_MAPVAL, 0, 3), map_pointer(T_MAPVAL, 0, 3))
        self.assertEqual((j.tag, j.mapidx), (T_MAPVAL, 3))

    def test_join_is_commutative_and_idempotent(self):
        vals = [SCALAR, pointer(T_CTX, 0), pointer(T_CTX, 4),
                pointer(T_PKT, 0), map_pointer(T_MAP, 0, 1),
                map_pointer(T_MAPVAL, 0, 1)]
        for a in vals:
            self.assertEqual(join_reg(a, a), a)
            for b in vals:
                self.assertEqual(join_reg(a, b), join_reg(b, a))


class TestCtxLayout(unittest.TestCase):
    def test_known_program_types(self):
        for sec in ("xdp", "xdp.frags", "xdp_devmap"):
            self.assertIs(ctx_layout_for(sec), CTX_XDP_MD)
        for sec in ("socket", "filter", "tc", "tcx/ingress", "classifier",
                    "action", "cgroup_skb/ingress", "sk_skb", "lwt_in",
                    "flow_dissector"):
            self.assertIs(ctx_layout_for(sec), CTX_SK_BUFF)

    def test_other_contexts_are_refused_not_guessed(self):
        # Each of these has its OWN context struct.  Reaching them through
        # __sk_buff would model a different program while still translating
        # cleanly, so the only safe answer is None.
        for sec in ("sk_reuseport", "sk_msg", "sockops", "sk_lookup",
                    "cgroup/connect4", "cgroup/getsockopt", "netfilter",
                    "kprobe/vfs_read", "tp_btf/sys_enter", "loadbalancer"):
            self.assertIsNone(ctx_layout_for(sec), sec)

    def test_field_offsets(self):
        self.assertEqual((CTX_SK_BUFF.data_off, CTX_SK_BUFF.data_end_off), (76, 80))
        self.assertEqual((CTX_XDP_MD.data_off, CTX_XDP_MD.data_end_off), (0, 4))

    def test_names_accepted_by_the_ctx_flag(self):
        self.assertIs(ctx_layout_by_name("__sk_buff"), CTX_SK_BUFF)
        self.assertIs(ctx_layout_by_name("skb"), CTX_SK_BUFF)
        self.assertIs(ctx_layout_by_name("xdp_md"), CTX_XDP_MD)
        self.assertIsNone(ctx_layout_by_name("pt_regs"))


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestProvenance(unittest.TestCase):
    """Pointer provenance decides which region a dereference names, and a
    wrong tag produces a program that still translates and still runs -- it
    just reads the wrong memory.  The property tests in test_lowering.py
    generate no memory operations, so this tier needs direct coverage."""

    def deref_after(self, mov_class):
        """MOV r2, r1 (at the given ALU class) and then load through r2."""
        import io
        blob = build([
            insn(mov_class | bpf.MOV | bpf.X, dst=2, src=1),
            insn(bpf.LDX | bpf.W | bpf.MEM, dst=3, src=2, off=0),
            insn(bpf.JMP | bpf.EXIT),
        ])
        t = Translator()
        t.run(blob, CTX_XDP_MD, io.StringIO())
        return t.had_error

    def test_64_bit_move_carries_the_pointer(self):
        self.assertFalse(self.deref_after(bpf.ALU64),
                         "a 64-bit MOV should keep r1's ctx tag, so the load "
                         "names region 1")

    def test_32_bit_move_destroys_the_pointer(self):
        # A 32-bit MOV zero-extends through 32 bits, which cannot preserve a
        # pointer.  The load through it has no region, and guessing one would
        # silently read the wrong memory.
        self.assertTrue(self.deref_after(bpf.ALU),
                        "a load through a 32-bit-truncated pointer must be "
                        "refused, not attributed to a region")
