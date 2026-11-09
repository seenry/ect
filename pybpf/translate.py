"""BPF bytecode -> a Caracara GeneralCaracaraProgram s-expression.

See README.md for the program shape, the memory model, the control-flow
scheme and the map model.  The short version:

  T_0 -> T_1 -> ... -> deparser (module 2)

The network has no parser module: eBPF reaches its packet through a computed
pointer, which a P4-style parser cannot express, so nothing a parser would do
(extract headers from packet bytes) applies here, and the well-formedness of
a ModuleNetwork places no constraint on the start module -- see the comment
on `wf_module_network` in CrModule.v.  T_0 is the network's source instead.

Each basic block becomes one transformer guarded on a program-counter header;
sequencing comes from the module chain, because a transformer runs only the
FIRST rule whose match pattern holds.  A block ending in a conditional jump --
or in a map lookup, which chooses between a value pointer and NULL -- needs a
second transformer, since a match pattern is evaluated on entry and the
condition is computed by the block itself.
"""

import io
import sys
from dataclasses import dataclass, replace

from . import bpf
from .btf import Btf, BtfError
from .elf import Elf, SHF_EXECINSTR, STT_SECTION, R_BPF_64_64
from .ir import (MASK64, Ops, coq_list, konst, hdr, match_const, match_header,
                 cmp_entry, rule, default_rule, set_pc_op, assign_op, zero_op,
                 const_op)

# ── Identifier allocation ───────────────────────────────────────────────
H_PC = 1                        # program counter
def H_REG(n): return 10 + n     # r0..r10  -> 10..20
def H_TMP(k): return 30 + k     # scratch, reused per instruction
H_STACK_BASE = 100              # one header per touched slot
# A hash map's scan needs one header per slot for the presence byte and one
# for the tag, both live until the decide transformer reads them, so the
# budget is 2*nslots plus a handful for the key, the copy and the pointer.
# H_TMP runs 30..99 before H_STACK_BASE, so 64 is the most that fits.
NUM_TMPS = 64
MAP_SLOTS_MAX = (NUM_TMPS - 8) // 2

REGION_CTX = 1
REGION_PKT = 2
def REGION_MAP(i): return 10 + i
REGION_NONE = 99                # undeclared: loads read ErrorVal

# Bytes of packet modelled.  It has to reach past the headers a filter
# actually parses, or the reads past it overrun, the run rejects, and the tail
# of the program is silently dead -- suricata's filter.c reads the IPv4 daddr
# at packet offset 30..33, so 32 made half of it unreachable.  64 covers
# ethernet + IPv4 + the start of a TCP header.
PKT_LEN = 64

MAX_MAPS = 16
# Slots modelled per map, overridable with --map-slots.
#
# For a TAGGED map this bounds how many ENTRIES the model can hold, and has
# nothing to do with the values the keys take: `check_map_budget` turns it
# into "a map may be accessed at nslots/2 sites", which every program in ex/
# meets at 4.  (It used to bound the key values instead, because the slot was
# `key % nslots`; ex/ebpf-se/map_access.c needed 24 slots for its constant key
# 23 and was impractical.  It fits in 2 now.)
#
# For an ARRAY map the key IS the index, so it still bounds key values, and
# check_array_key refuses what would alias.
#
# Raising it is not free -- every slot adds cells to the region and two more
# rules to every scan, and the equivalence check grows superlinearly in region
# size once a program writes into the map.  Measured on
# ex/ebpf-se/xdp_pktcntr.c with the old key-indexed model: 4 slots 2.7s,
# 8 slots 11s, 16 slots 47s, 32 slots over two minutes with a symbolic slot.
MAP_MAX_SLOTS = 4
MAP_MAX_VALUE_COPY = 64         # bytes an update will copy one at a time

# The helpers that are translated rather than rejected.
BPF_FUNC_map_lookup_elem = 1
BPF_FUNC_map_update_elem = 2    # BPF_ANY only; see emit_map_update

# What the kernel returns from bpf_map_update_elem when the write does not
# happen: a hash map that is at max_entries and is asked for a NEW key, or an
# array map indexed past its end.  The helper returns it in r0 and nothing
# traps, so a program that ignores the result carries on.
E2BIG = 7

MOD_DEPARSER = 2
MOD_FIRST_XFRM = 10

PC_HALT = 0                     # no block guards on 0
def BLOCK_PC(leader): return 2 * leader + 1
def DECIDE_PC(leader): return 2 * leader + 2

NUM_BPF_REGS = 11
BPF_STACK_SIZE = 512
MAX_INSNS = 8192


# ── Maps ────────────────────────────────────────────────────────────────

# The two map families differ in what a KEY MEANS, and they need different
# models.  Getting this wrong is not a detail: for an array map the key IS the
# index and an in-range lookup can never fail, while for a hash map the key is
# an opaque blob and presence is whatever was inserted.
ARRAY_TYPES = {
    2,   # BPF_MAP_TYPE_ARRAY
    6,   # BPF_MAP_TYPE_PERCPU_ARRAY
}
HASH_TYPES = {
    1,   # BPF_MAP_TYPE_HASH
    5,   # BPF_MAP_TYPE_PERCPU_HASH
}
# An LRU map is a hash map that never fails an insert: when it is full it
# EVICTS the least-recently-used entry, so the insert succeeds and some OTHER
# key -- one the program never named -- silently disappears.  Nothing here
# models that, and the gap is in the direction that matters: a transition the
# model lacks is a difference the checker cannot find, which is a wrong
# Equivalent rather than a loud one.  So these are refused rather than folded
# into FAMILY_HASH, where they sat until now.
LRU_TYPES = {
    9,   # BPF_MAP_TYPE_LRU_HASH
    10,  # BPF_MAP_TYPE_LRU_PERCPU_HASH
}

FAMILY_ARRAY, FAMILY_HASH, FAMILY_LRU = "array", "hash", "lru"


@dataclass
class MapInfo:
    """A BPF map becomes one declared IR memory region.  How it is laid out,
    and how a lookup decides between the value pointer and NULL, depend on the
    map FAMILY, because the two families disagree about what a key is:

      * an ARRAY map is fully pre-allocated and zero-filled when it is
        created, so `key < max_entries` is present -- always, a lookup can
        never return NULL for an in-range key -- and `key >= max_entries` is
        NULL.  The key is the index.  So presence is decided by the key alone
        and the presence bytes are not read at all; modelling it with a free
        presence byte would invent a miss path that cannot occur.

      * a HASH map's key is an opaque blob and `max_entries` is a capacity,
        not a key range.  Whether a key is present depends on what was
        inserted, which is unknown on entry -- so the presence byte is a free
        region cell and the solver explores both arms.

    So an ARRAY map indexes the region BY the key:

        [0, nslots)                          presence bytes (never read)
        [nslots, nslots + nslots*value_size) the values, slot i at
                                             nslots + i*value_size

    while a HASH map stores the key IN the region as a tag and finds it by
    scanning:

        [0, nslots)                          presence bytes, 1 = slot filled
        [tag_base, + nslots*key_size)        the key each slot holds
        [value_base, + nslots*value_size)    the values
        [full_off]                           1 = the real map is at capacity

    The tag is the whole point.  Deriving the slot from the key -- `key %
    nslots`, which is what this did until now -- forces distinct keys that
    collide modulo nslots to share one entry, and that DELETES reachable map
    states: "k1 present, k2 absent" has no representative once the two
    collide.  A deleted state is a difference the checker cannot find, so it
    is a wrong Equivalent rather than a loud failure.  With the key stored,
    the slot is a function of the region rather than of the key, and no two
    keys are forced together.

    What makes a bounded region enough is that the translator refuses
    backward jumps: with no loops a run performs at most one map operation per
    call site, so it observes at most that many distinct keys.  See
    `check_map_budget` for the side condition that turns that into a number.

    An ARRAY map keeps the old key-indexed layout, because there the key IS
    the index and there is nothing to look up; `check_array_key` refuses the
    accesses where the modulus could still alias.
    """
    name: str
    type: int
    key_size: int
    value_size: int
    max_entries: int
    slots_budget: int = MAP_MAX_SLOTS

    @property
    def family(self):
        if self.type in ARRAY_TYPES:
            return FAMILY_ARRAY
        if self.type in HASH_TYPES:
            return FAMILY_HASH
        if self.type in LRU_TYPES:
            return FAMILY_LRU
        return None

    @property
    def is_array(self):
        return self.family == FAMILY_ARRAY

    @property
    def exact(self):
        """True when no two keys share a slot, so the model is not abstracting
        at all.  Only reachable for a small array map."""
        return self.is_array and self.max_entries <= self.slots_budget

    @property
    def nslots(self):
        me = self.max_entries
        b = self.slots_budget
        return b if (me == 0 or me > b) else me

    @property
    def tagged(self):
        """True when the region carries the key of each slot, so a lookup
        scans for it instead of computing an index from it."""
        return self.family == FAMILY_HASH

    @property
    def tag_base(self):
        return self.nslots

    def tag_off(self, i):
        return self.tag_base + i * self.key_size

    @property
    def value_base(self):
        return self.nslots + (self.nslots * self.key_size if self.tagged else 0)

    def value_off(self, i):
        return self.value_base + i * self.value_size

    @property
    def full_off(self):
        """The capacity byte: 1 when the map is at max_entries, so an insert
        of a NEW key fails.  A tagged map only; an array map's entries all
        exist from creation and it can never be full.

        It is a free region cell rather than anything derived from the
        presence bytes, because model fullness and real fullness are not the
        same event -- nslots is 4 and max_entries is 64, 256 or 32768 in every
        map under ex/.  Deriving it would tie E2BIG to the model's own size
        and fire it thousands of entries early.
        """
        return self.value_base + self.nslots * self.value_size

    @property
    def length(self):
        return self.full_off + (1 if self.tagged else 0)


# ── Context layouts ─────────────────────────────────────────────────────

@dataclass(frozen=True)
class CtxLayout:
    """The context a program is called with -- the one piece of program-type
    knowledge in the translator.  Two things depend on it: how big the ctx
    region is, and which fields hold pointers into the packet.

    Getting the length wrong is not a small error.  `struct __sk_buff` puts
    vlan_tci at offset 24 and data at 76, so modelling an __sk_buff program
    with xdp_md's 20 bytes makes every field access an out-of-bounds read.
    Those are total, but they record an overrun, and an overrun rejects the
    run at the sink -- so the program is modelled as one that always rejects,
    and two such programs are "equivalent" whatever they compute.  Hence
    `ctx_access_ok`, which refuses the translation rather than emitting that
    silently.
    """
    name: str
    length: int
    data_off: int
    data_end_off: int


CTX_XDP_MD = CtxLayout("xdp_md", 20, 0, 4)
CTX_SK_BUFF = CtxLayout("__sk_buff", 192, 76, 80)

# Program types whose context is struct __sk_buff.  Only these -- a name that
# is merely network-ish is NOT enough: sk_reuseport, sk_msg, sockops,
# sk_lookup and the cgroup/sock* hooks each have their own context struct, and
# reaching them through this one would model a different program while still
# translating cleanly.
_SKB_PREFIXES = ("socket", "filter", "tc", "classifier", "action",
                 "cgroup_skb", "cgroup/skb", "sk_skb", "lwt_", "flow_dissector")


def ctx_layout_by_name(n):
    if n in ("xdp_md", "xdp"):
        return CTX_XDP_MD
    if n in ("__sk_buff", "skb"):
        return CTX_SK_BUFF
    return None


def ctx_layout_for(sec):
    """Which context a program section gets.  An unrecognised name yields
    None -- guessing wrong is the silent failure described on CtxLayout."""
    if sec.startswith("xdp"):
        return CTX_XDP_MD
    if sec.startswith(_SKB_PREFIXES):
        return CTX_SK_BUFF
    return None


# ── Pointer provenance ──────────────────────────────────────────────────

# Each register carries an abstract region tag.  A load or store needs one to
# know which declared region to name, and the stack needs a constant offset on
# top of that to pick a slot header.
#
# SCALAR is a plain integer; UNKNOWN is the join of two disagreeing tags, and
# using it as a memory base is an error rather than a guess.  MAP is the map
# object itself, only ever a helper argument; MAPVAL is what a successful
# lookup returns.  Both carry the map's index, since which map it is decides
# which region a dereference names.
T_SCALAR, T_CTX, T_PKT, T_STACK, T_MAP, T_MAPVAL, T_UNKNOWN = range(7)


@dataclass(frozen=True)
class RegInfo:
    tag: int = T_SCALAR
    off: int = 0
    off_known: bool = True
    mapidx: int = -1
    # A scalar whose value is statically known.  Only MOV of an immediate and
    # LD_IMM64 set this; anything computed clears it.  It exists so that a
    # helper argument that must be a particular constant -- bpf_map_update_elem's
    # flags -- can be CHECKED rather than assumed.
    const: int = None


SCALAR = RegInfo()


def scalar_const(v):
    return RegInfo(T_SCALAR, 0, True, -1, v & MASK64)


def pointer(tag, off=0):
    return RegInfo(tag, off, True, -1)


def map_pointer(tag, off, mapidx):
    return RegInfo(tag, off, True, mapidx)


def join_reg(a, b):
    if a.tag != b.tag or a.mapidx != b.mapidx:
        return RegInfo(T_UNKNOWN, 0, False, -1)
    known = a.off_known and b.off_known and a.off == b.off
    const = a.const if a.const == b.const else None
    return RegInfo(a.tag, a.off if known else 0, known, a.mapidx, const)


class AbsState:
    """Abstract state on entry to a block: a tag per register and per stack
    slot, plus whether the block has been reached at all."""

    def __init__(self):
        self.reg = [SCALAR] * NUM_BPF_REGS
        self.slot = [SCALAR] * (BPF_STACK_SIZE + 1)
        self.live = False

    def copy(self):
        s = AbsState()
        s.reg = list(self.reg)
        s.slot = list(self.slot)
        s.live = self.live
        return s

    def join_from(self, src):
        if not src.live:
            return
        if not self.live:
            self.reg = list(src.reg)
            self.slot = list(src.slot)
            self.live = True
            return
        self.reg = [join_reg(a, b) for a, b in zip(self.reg, src.reg)]
        self.slot = [join_reg(a, b) for a, b in zip(self.slot, src.slot)]


class Unsupported(Exception):
    """Raised only for conditions that abort the whole run; per-instruction
    problems are reported and translation continues, so that one diagnostic
    does not hide the rest."""


class Translator:
    """One object file -> one s-expression.

    All the state the C version kept in file-scope globals lives here, which
    is what makes the pieces unit-testable: `emit_bswap`, `join_reg` and
    `emit_condition` can be exercised without an ELF file.
    """

    def __init__(self, ctx_layout=CTX_XDP_MD, map_slots=None):
        self.had_error = False
        # None means "size each map from how often the program uses it"; see
        # probe_map_sites.  An explicit number forces it, for every map.
        self.map_slots = map_slots
        self.site_hint = None
        self.quiet = False
        self.ctx = ctx_layout
        self.maps = []                     # sorted by name before use
        self.insn_map_idx = {}             # insn index -> map index
        self.modules = []
        self.next_mod = MOD_FIRST_XFRM
        self.stack_hdr_of = {}             # slot -> header id
        self.next_stack_hdr = H_STACK_BASE
        self.reg_used = [False] * NUM_BPF_REGS
        self.ops = Ops()                   # ops of the block being translated
        self.tmp_next = 0                  # scratch pool cursor
        self.map_const_keys = {}           # map index -> {slot: key} seen
        self.map_sites = {}                # map index -> helper calls on it

    # ── diagnostics ─────────────────────────────────────────────────────
    def unsupported(self, idx, msg):
        if not self.quiet:
            print("bpf_to_ir: insn %d: unsupported: %s" % (idx, msg),
                  file=sys.stderr)
        self.had_error = True

    def error(self, msg):
        if not self.quiet:
            print("bpf_to_ir: %s" % msg, file=sys.stderr)
        self.had_error = True

    # ── maps ────────────────────────────────────────────────────────────
    def find_map(self, name):
        for i, m in enumerate(self.maps):
            if m.name == name:
                return i
        return -1

    def add_map(self, name, type_, ks, vs, me):
        if self.find_map(name) >= 0:
            return
        if len(self.maps) >= MAX_MAPS:
            self.error("more than %d maps" % MAX_MAPS)
            return
        self.maps.append(MapInfo(name, type_, ks, vs, me,
                                 self.map_slots or MAP_MAX_SLOTS))

    def map_region(self, m):
        return REGION_MAP(m)

    def discover_legacy_maps(self, elf, sec):
        """`struct bpf_map_def SEC("maps")`, whose five u32 fields sit in the
        section data, so no BTF is needed."""
        import struct as _s
        for sym in elf.symbols:
            if sym.shndx != sec.index or sym.type == STT_SECTION:
                continue
            off = sym.value
            if off + 20 > len(sec.data):
                continue
            f = _s.unpack_from("<IIIII", sec.data, off)
            self.add_map(sym.name, f[0], f[1], f[2], f[3])

    def discover_btf_maps(self, blob):
        try:
            b = Btf(blob)
        except BtfError as e:
            self.error(".BTF %s" % e)
            return
        for name, struct_id in b.datasec_vars(".maps"):
            members = b.struct_members(struct_id)
            if members is None:
                self.error("map %s: BTF entry is not a struct" % name)
                continue
            type_ = ks = vs = me = 0
            for mn, mtid in members:
                if mn == "type":
                    type_ = b.uint_value(mtid)
                elif mn == "max_entries":
                    me = b.uint_value(mtid)
                elif mn == "key_size":
                    ks = b.uint_value(mtid)
                elif mn == "value_size":
                    vs = b.uint_value(mtid)
                elif mn == "key":
                    ks = b.type_size(mtid)
                elif mn == "value":
                    vs = b.type_size(mtid)
            if ks == 0 or vs == 0:
                self.error("map %s: BTF gives key_size=%d value_size=%d; "
                           "the map cannot be sized" % (name, ks, vs))
                continue
            self.add_map(name, type_, ks, vs, me)

    # ── scratch and stack headers ───────────────────────────────────────
    def fresh_tmp(self, idx):
        if self.tmp_next >= NUM_TMPS:
            self.unsupported(idx, "ran out of scratch headers")
            self.tmp_next = 0
        t = H_TMP(self.tmp_next)
        self.tmp_next += 1
        return t

    def stack_header(self, slot):
        """Allocated on first use, in source order -- so header ids depend on
        the order slots are touched, and the two objects being compared touch
        them in the same order because they come from one source."""
        if slot < 0 or slot > BPF_STACK_SIZE:
            return 0
        if slot not in self.stack_hdr_of:
            self.stack_hdr_of[slot] = self.next_stack_hdr
            self.next_stack_hdr += 1
        return self.stack_hdr_of[slot]

    # ── regions ─────────────────────────────────────────────────────────
    def region_of(self, r):
        if r.tag == T_CTX:
            return REGION_CTX
        if r.tag == T_PKT:
            return REGION_PKT
        if r.tag == T_MAPVAL:
            return (self.map_region(r.mapidx)
                    if 0 <= r.mapidx < len(self.maps) else REGION_NONE)
        return REGION_NONE

    def ctx_field_is_pkt_ptr(self, off):
        return off in (self.ctx.data_off, self.ctx.data_end_off)

    def ctx_access_ok(self, idx, base, insn_off, nbytes, what):
        """A ctx access at a statically known offset must land inside the
        region.  The offset is known for essentially every real ctx access --
        the verifier requires it -- so this catches a wrong or missing layout
        at translation time instead of at the both-rejected disjunct of the
        equivalence checker."""
        if base.tag != T_CTX or not base.off_known:
            return True
        lo = base.off + insn_off
        if lo >= 0 and lo + nbytes <= self.ctx.length:
            return True
        self.unsupported(idx, "%s at ctx offset %d..%d, outside the %d bytes "
                              "of struct %s that are modelled"
                         % (what, lo, lo + nbytes, self.ctx.length,
                            self.ctx.name))
        return False

    # ── synthesized operators ───────────────────────────────────────────
    def emit_arsh_const(self, idx, reg, k, width_bits):
        """An arithmetic right shift by a constant, built out of the operators
        the IR does have:

            logical = x / 2^k                      (unsigned divide)
            sign    = x / 2^(width-1)              (0 or 1)
            result  = logical | sign * (2^k - 1) * 2^(width-k)

        The two summands occupy disjoint bits, so the combine is an or.
        """
        if k <= 0 or k >= width_bits:
            if k != 0:
                self.unsupported(idx, "arithmetic shift by %d at %d bits"
                                 % (k, width_bits))
            return
        w = "W32" if width_bits == 32 else "W64"
        t_sign = self.fresh_tmp(idx)
        t_mask = self.fresh_tmp(idx)
        sign_div = 1 << (31 if width_bits == 32 else 63)
        mask = ((1 << k) - 1) << (width_bits - k)
        if width_bits == 32:
            mask &= 0xffffffff
        o = self.ops
        o.binop("DivOp", w, hdr(reg), konst(sign_div), t_sign)
        o.binop("MulOp", w, hdr(t_sign), konst(mask), t_mask)
        o.binop("DivOp", w, hdr(reg), konst(1 << k), reg)
        o.binop("OrOp", w, hdr(reg), hdr(t_mask), reg)

    def emit_bswap(self, idx, src, nbytes, target):
        """A byte swap, built out of the operators the IR does have.  Same
        trick as emit_arsh_const: there is no shift, but a shift by a constant
        is a multiply or divide by a power of two, so byte i of the source

            (src / 2^(8i)) & 0xff

        lands at byte (n-1-i) of the result by multiplying it back up.  The
        partial results occupy disjoint bits, so the accumulate is an or.

        Everything is done at W64 with explicit masks rather than at the
        operand's own width, so the source is read once and the caller may
        pass the same header as `src` and `target`.  Four ops per byte.
        """
        o = self.ops
        if nbytes <= 1:
            if src != target:
                o.move(target, src)
            return
        t_src = self.fresh_tmp(idx)
        t_acc = self.fresh_tmp(idx)
        t_b = self.fresh_tmp(idx)
        o.move(t_src, src)
        o.set_(t_acc, 0)
        for i in range(nbytes):
            up = 8 * (nbytes - 1 - i)
            if i == 0:
                o.move(t_b, t_src)
            else:
                o.binop("DivOp", "W64", hdr(t_src), konst(1 << (8 * i)), t_b)
            o.binop("AndOp", "W64", hdr(t_b), konst(0xff), t_b)
            if up:
                o.binop("MulOp", "W64", hdr(t_b), konst(1 << up), t_b)
            o.binop("OrOp", "W64", hdr(t_acc), hdr(t_b), t_acc)
        o.move(target, t_acc)

    # ── ALU ─────────────────────────────────────────────────────────────
    def translate_alu(self, idx, in_, is64, st):
        """ALU at 64 bits operates on the register headers directly.  At 32
        bits it narrows both operands, operates at W32 and widens back --
        which is also the zero-extension BPF's 32-bit ALU performs on the
        upper half."""
        o = self.ops
        op = in_.op
        is_imm = in_.is_imm
        dst, src = in_.dst, in_.src
        hd, hs = H_REG(dst), H_REG(src)
        imm = in_.imm & MASK64                  # sign-extended, then unsigned
        w = "W64" if is64 else "W32"
        width_bits = 64 if is64 else 32

        if dst >= NUM_BPF_REGS or src >= NUM_BPF_REGS:
            self.unsupported(idx, "register out of range")
            return

        # Abstract effect first; the concrete ops follow.
        if op == bpf.MOV:
            if is_imm:
                st.reg[dst] = scalar_const(imm if is64 else in_.imm & 0xffffffff)
            else:
                st.reg[dst] = st.reg[src]
            if not is64 and not is_imm:
                st.reg[dst] = SCALAR        # truncation destroys a pointer
        elif op == bpf.ADD and is64:
            d, s = st.reg[dst], st.reg[src]
            if is_imm:
                if d.tag != T_SCALAR and d.off_known:
                    st.reg[dst] = replace(d, off=d.off + in_.imm)
                elif d.tag != T_SCALAR:
                    st.reg[dst] = replace(d, off_known=False)
            elif d.tag != T_SCALAR and s.tag == T_SCALAR:
                st.reg[dst] = replace(d, off_known=False)   # ptr + variable
            elif d.tag == T_SCALAR and s.tag != T_SCALAR:
                st.reg[dst] = replace(s, off_known=False)
            else:
                st.reg[dst] = SCALAR
        else:
            st.reg[dst] = SCALAR

        if op == bpf.MOV:
            if is64:
                if is_imm:
                    o.set_(hd, imm)
                else:
                    o.move(hd, hs)
            else:
                if is_imm:
                    o.set_(hd, in_.imm & 0xffffffff)
                else:
                    t = self.fresh_tmp(idx)
                    o.cast("W64", "W32", hdr(hs), t)
                    o.cast("W32", "W64", hdr(t), hd)
            return

        if op == bpf.NEG:
            if is64:
                o.binop("SubOp", "W64", konst(0), hdr(hd), hd)
            else:
                t = self.fresh_tmp(idx)
                o.cast("W64", "W32", hdr(hd), t)
                o.binop("SubOp", "W32", konst(0), hdr(t), t)
                o.cast("W32", "W64", hdr(t), hd)
            return

        if op in (bpf.LSH, bpf.RSH, bpf.ARSH):
            if not is_imm:
                self.unsupported(idx, "shift by a register (the IR has no "
                                      "shift operator; only constant shifts "
                                      "lower to multiply/divide)")
                return
            k = in_.imm & (width_bits - 1)
            t = hd if is64 else self.fresh_tmp(idx)
            if not is64:
                o.cast("W64", "W32", hdr(hd), t)
            if op == bpf.ARSH:
                self.emit_arsh_const(idx, t, k, width_bits)
            elif k != 0:
                o.binop("MulOp" if op == bpf.LSH else "DivOp", w,
                        hdr(t), konst(1 << k), t)
            if not is64:
                o.cast("W32", "W64", hdr(t), hd)
            return

        if op == bpf.END:
            # `imm` is the width in BITS, and the result is written back at
            # that width -- the kernel assigns through a u16/u32, so the
            # register's upper bits are zeroed whichever direction the
            # conversion goes.
            bits = in_.imm
            if bits not in (16, 32, 64):
                self.unsupported(idx, "BPF_END with a width of %d bits" % bits)
                return
            if bits != 64:
                o.binop("AndOp", "W64", hdr(hd), konst((1 << bits) - 1), hd)
            # BPF_END is defined against the HOST's byte order, and this
            # translator models a little-endian host: BPF_TO_BE (the BPF_X
            # source bit) is a real swap and BPF_TO_LE is the truncation
            # alone.  The ALU64 spelling is BPF v4's unconditional `bswap`,
            # which swaps regardless.
            if is64 or bpf.src(in_.code) == bpf.X:
                self.emit_bswap(idx, hd, bits // 8, hd)
            return

        binop = bpf.ALU_BINOP.get(op)
        if binop is None:
            self.unsupported(idx, "ALU op 0x%x" % op)
            return
        if is64:
            o.binop(binop, "W64", hdr(hd), konst(imm) if is_imm else hdr(hs), hd)
        else:
            t1 = self.fresh_tmp(idx)
            o.cast("W64", "W32", hdr(hd), t1)
            if is_imm:
                o.binop(binop, "W32", hdr(t1), konst(in_.imm & 0xffffffff), t1)
            else:
                t2 = self.fresh_tmp(idx)
                o.cast("W64", "W32", hdr(hs), t2)
                o.binop(binop, "W32", hdr(t1), hdr(t2), t1)
            o.cast("W32", "W64", hdr(t1), hd)

    # ── memory ──────────────────────────────────────────────────────────
    def emit_address(self, idx, base_hdr, off):
        """Materialise `base + off` into a scratch header."""
        t = self.fresh_tmp(idx)
        self.ops.binop("AddOp", "W64", hdr(base_hdr), konst(off), t)
        return t

    def translate_ldx(self, idx, in_, st):
        o = self.ops
        dst, src = in_.dst, in_.src
        nbytes = bpf.size_bytes(in_.code)
        w = bpf.width_name(nbytes)
        base = st.reg[src]

        if base.tag == T_STACK:
            if not base.off_known:
                self.unsupported(idx, "stack load at a non-constant offset")
                st.reg[dst] = SCALAR
                return
            slot = -(base.off + in_.off)
            sh = self.stack_header(slot)
            if not sh:
                self.unsupported(idx, "stack load outside the %d-byte frame "
                                      "(slot %d)" % (BPF_STACK_SIZE, slot))
                st.reg[dst] = SCALAR
                return
            # The slot header holds the value at the width it was stored; the
            # cast both zero-extends and checks that width, exactly as a load
            # from a region checks the cell's type.
            o.cast(w, "W64", hdr(sh), H_REG(dst))
            st.reg[dst] = st.slot[slot]
            return

        region = self.region_of(base)
        if region == REGION_NONE:
            self.unsupported(idx, "load through r%d, whose region is unknown" % src)
        self.ctx_access_ok(idx, base, in_.off, nbytes, "load")

        t_addr = self.emit_address(idx, H_REG(src), in_.off)
        t_val = self.fresh_tmp(idx)
        o.load(w, region, hdr(t_addr), t_val)
        o.cast(w, "W64", hdr(t_val), H_REG(dst))

        if (base.tag == T_CTX and base.off_known
                and self.ctx_field_is_pkt_ptr(base.off + in_.off)):
            # A pointer read out of memory has no statically known offset of
            # its own; what the program computes from it is compared, not
            # assumed.
            st.reg[dst] = RegInfo(T_PKT, 0, False, -1)
        else:
            st.reg[dst] = SCALAR

    def translate_store(self, idx, in_, st, from_reg):
        """[dst + off] := <val header or immediate>, at width nbytes."""
        o = self.ops
        dst, src = in_.dst, in_.src
        nbytes = bpf.size_bytes(in_.code)
        w = bpf.width_name(nbytes)
        base = st.reg[dst]
        imm = in_.imm & MASK64

        if base.tag == T_STACK:
            if not base.off_known:
                self.unsupported(idx, "stack store at a non-constant offset")
                return
            slot = -(base.off + in_.off)
            sh = self.stack_header(slot)
            if not sh:
                self.unsupported(idx, "stack store outside the %d-byte frame "
                                      "(slot %d)" % (BPF_STACK_SIZE, slot))
                return
            if from_reg:
                o.cast("W64", w, hdr(H_REG(src)), sh)
                st.slot[slot] = st.reg[src]
            else:
                o.binop("AddOp", w, konst(imm), konst(0), sh)
                # A stored immediate makes the slot a known constant, which is
                # how a map key written as `key.field = 23` stays constant.
                st.slot[slot] = scalar_const(imm)
            return

        region = self.region_of(base)
        if region == REGION_NONE:
            self.unsupported(idx, "store through r%d, whose region is unknown" % dst)
        self.ctx_access_ok(idx, base, in_.off, nbytes, "store")

        t_addr = self.emit_address(idx, H_REG(dst), in_.off)
        if from_reg:
            t_val = self.fresh_tmp(idx)
            o.cast("W64", w, hdr(H_REG(src)), t_val)
            o.store(w, region, hdr(t_addr), hdr(t_val))
        else:
            # A constant operand adopts the op's type, so no cast is needed.
            o.store(w, region, hdr(t_addr), konst(imm))

    # ── map lookup ──────────────────────────────────────────────────────
    def emit_map_lookup(self, idx, st):
        """Translate `r0 = bpf_map_lookup_elem(r1, r2)`.

        Everything a decision reads -- the key, and for a tagged map every
        slot's presence byte and tag -- is emitted into the current block,
        because a match pattern is evaluated on ENTRY to its transformer.  The
        decision itself comes back as a list of ARMS, `(match entries, ops)`
        in first-match order with an unconditional one last, and the caller
        turns them into the rules of a second transformer.

        An ARRAY map yields two arms: the key alone decides, exactly.  A HASH
        map yields nslots + 1 -- one per slot, matching "this slot is filled
        AND its tag is the key we were given", then a miss.  The scan is what
        removes the modulus: the value pointer in arm i is the LITERAL offset
        of slot i, and which slot a key lands in is a fact about the region
        rather than about the key.

        Returns None (having reported why) if the call cannot be translated.
        """
        o = self.ops
        mp, kp = st.reg[1], st.reg[2]

        if mp.tag != T_MAP or mp.mapidx < 0:
            self.unsupported(idx, "bpf_map_lookup_elem: r1 is not a known map "
                                  "pointer")
            return None
        m = mp.mapidx
        mi = self.maps[m]
        if not self.check_map_modelled(idx, mi):
            return None
        if mi.key_size not in (1, 2, 4, 8):
            self.unsupported(idx, "map %s has a %d-byte key (only 1, 2, 4 and "
                                  "8 are modelled)" % (mi.name, mi.key_size))
            return None
        kw = bpf.width_name(mi.key_size)
        self.tmp_next = 0
        self.count_map_site(m)

        if mi.is_array:
            arms = self.emit_array_lookup(idx, m, mi, kp, st, kw)
        else:
            arms = self.emit_tagged_lookup(idx, m, mi, kp, kw)
        if arms is None:
            return None

        # r0 is the value pointer on a hit arm and 0 on the miss arm; the tag
        # is what a later dereference reads, and the program has to NULL-check
        # before dereferencing or the verifier would have rejected it.
        st.reg[0] = map_pointer(T_MAPVAL, 0, m)
        for r in range(1, 6):
            st.reg[r] = SCALAR              # clobbered by the call
        return arms

    def emit_array_lookup(self, idx, m, mi, kp, st, kw):
        """An array map is pre-allocated and zero-filled at creation, so an
        in-range lookup ALWAYS succeeds and an out-of-range one is always
        NULL.  The key alone decides it, exactly -- reading a free presence
        byte here would invent a miss path that cannot occur.

        The key is still the index, so `check_array_key` has to rule out the
        accesses the modulus would alias.
        """
        o = self.ops
        if not self.check_array_key(idx, m, self.const_key(kp, st)):
            return None
        t_slot, const = self.emit_slot(idx, m, kp, st, kw)
        if t_slot is None:
            return None
        t_vp = self.fresh_tmp(idx)
        o.binop("MulOp", "W64", hdr(t_slot), konst(mi.value_size), t_vp)
        o.binop("AddOp", "W64", hdr(t_vp), konst(mi.value_base), t_vp)

        # A constant key settles it at translation time.  The guard has
        # already established const < nslots <= max_entries, so the lookup
        # cannot fail: test the slot against itself, which is always true.
        if const is not None:
            cond = cmp_entry(t_slot, "CmpEq",
                             match_const(const % mi.nslots, "W64"))
        else:
            t_key = self.fresh_tmp(idx)
            o.cast("W64", "W64", hdr(t_slot), t_key)       # slot == key here
            cond = cmp_entry(t_key, "CmpLt",
                             match_const(mi.max_entries, "W64"))
        return [([cond], [assign_op(H_REG(0), t_vp)]),
                ([], [zero_op(H_REG(0))])]

    def emit_tagged_lookup(self, idx, m, mi, kp, kw):
        """One arm per slot: filled, and holding the key we were given."""
        t_key = self.read_map_key(idx, kp, kw)
        if t_key is None:
            return None
        pres, tags = self.emit_slot_headers(idx, m, mi, kw)
        arms = [([cmp_entry(pres[i], "CmpEq", match_const(1, "W64")),
                  cmp_entry(tags[i], "CmpEq", match_header(t_key))],
                 [const_op(H_REG(0), mi.value_off(i))])
                for i in range(mi.nslots)]
        arms.append(([], [zero_op(H_REG(0))]))
        return arms

    def emit_slot_headers(self, idx, m, mi, kw):
        """Every slot's presence byte and tag, widened to W64 in headers of
        their own, because a match pattern compares headers and is evaluated
        before the transformer it guards runs any ops.

        The raw load target is reused across slots -- it is dead the moment
        the cast has read it -- but the widened values are not, since all of
        them are live until the scan picks one.
        """
        o = self.ops
        region = self.map_region(m)
        t_raw = self.fresh_tmp(idx)
        pres, tags = [], []
        for i in range(mi.nslots):
            t = self.fresh_tmp(idx)
            o.load("W8", region, konst(i), t_raw)
            o.cast("W8", "W64", hdr(t_raw), t)
            pres.append(t)
        for i in range(mi.nslots):
            t = self.fresh_tmp(idx)
            o.load(kw, region, konst(mi.tag_off(i)), t_raw)
            o.cast(kw, "W64", hdr(t_raw), t)
            tags.append(t)
        return pres, tags

    def check_map_modelled(self, idx, mi):
        """Refuse a map whose family decides what a key MEANS and which this
        does not model.  Guessing would be the silent kind of wrong: a
        prog-array or a ringbuf is not an associative store at all."""
        if mi.family is None:
            self.unsupported(idx, "map %s has type %d, which is neither an "
                                  "array nor a hash; what a key means there "
                                  "is not modelled" % (mi.name, mi.type))
            return False
        if mi.family == FAMILY_LRU:
            self.unsupported(idx, "map %s is an LRU map (type %d): a full LRU "
                                  "map EVICTS the least-recently-used entry "
                                  "instead of failing the insert, which "
                                  "mutates an entry the program never named "
                                  "and is not modelled" % (mi.name, mi.type))
            return False
        return True

    def const_key(self, kp, st):
        """The key's value, when it is statically known.

        The usual shape is a constant written to a stack slot and passed by
        address, which the scalar-constant tracking follows.  Returns None
        when the key is computed, which is the case this cannot police."""
        if kp.tag != T_STACK or not kp.off_known:
            return None
        slot = -kp.off
        return st.slot[slot].const if 0 <= slot <= BPF_STACK_SIZE else None

    def check_array_key(self, idx, m, key):
        """Refuse an ARRAY access the slot mapping would ALIAS.

        A tagged map has no such problem -- the key is stored, not folded --
        but an array map still indexes the region by `key % nslots`, which
        puts distinct keys in one entry whenever the key reaches nslots.  That
        is unsound in the dangerous direction: two programs reading DIFFERENT
        entries get reported equivalent.  Checking for a collision within one
        program is not enough either, because the two programs a comparison is
        about are translated separately and neither sees the other's keys -- a
        program reading key 3 and one reading key 7 each alias nothing on
        their own, and compare equal.

        So the condition is stricter: a constant key must be BELOW nslots, at
        which point the slot is the key and no aliasing is possible with any
        other program.  A computed key cannot be placed at all, so it is
        allowed only when every key fits, i.e. max_entries <= nslots.
        """
        mi = self.maps[m]
        if key is None:
            if mi.max_entries > mi.nslots:
                self.unsupported(idx, "array map %s is accessed with a "
                                      "computed key, but only %d of its %d "
                                      "entries are modelled, so distinct keys "
                                      "would be folded onto one slot.  Raise "
                                      "--map-slots to %d"
                                 % (mi.name, mi.nslots, mi.max_entries,
                                    mi.max_entries))
                return False
            return True
        if key >= mi.nslots:
            self.unsupported(idx, "array map %s is accessed with the constant "
                                  "key %d, but only %d slots are modelled, so "
                                  "it would be folded onto slot %d and share "
                                  "an entry with other keys.  Raise "
                                  "--map-slots above %d"
                             % (mi.name, key, mi.nslots, key % mi.nslots, key))
            return False
        self.map_const_keys.setdefault(m, {})[key % mi.nslots] = key
        return True

    def count_map_site(self, m):
        self.map_sites[m] = self.map_sites.get(m, 0) + 1

    def size_maps(self):
        """Give each TAGGED map the slots its use actually needs.

        `check_map_budget` says a map accessed at k sites needs 2k slots, so
        that is what it gets.  Every slot is region cells the solver pins and
        two more rules on every scan, and a default of 4 over-provisions any
        map used once -- which is most of them.  Measured on ex/map/map_ref.c
        against map_spill.c: 4 slots is a 53-byte region and 85ms, 2 slots is
        27 bytes and 54ms.

        An ARRAY map is left alone.  There the budget bounds the KEY VALUES
        the model can represent rather than the number of live entries (see
        `check_array_key`), so sizing it from a call count would refuse
        perfectly good programs.

        The two objects being compared have to declare the same region, which
        holds when they use a map the same number of times -- true of two
        lowerings of one source.  When it does not hold the checker refuses
        the pair rather than answering, so this cannot become a wrong verdict.
        """
        if self.site_hint is None:
            return
        for mi in self.maps:
            if not mi.tagged:
                continue
            sites = self.site_hint.get(mi.name, 0)
            mi.slots_budget = min(max(2 * sites, 1), MAP_SLOTS_MAX)

    def check_map_budget(self):
        """The side condition that makes a bounded region enough.

        With no loops a run performs at most one map operation per call site,
        so it observes at most that many distinct keys.  But the two programs
        in a comparison are given the SAME region, and their keys need not be
        the same ones -- so in the worst case the region has to hold both
        programs' keys at once, and each program's translation only ever sees
        its own.  Halving the budget is what composes: if each side is within
        nslots/2 then the sum is within nslots, whatever the other side is.

        Exceeding it is not a precision loss, it is the unsound direction
        again -- a map state neither program can represent is one where a real
        difference can hide -- so it is refused rather than warned about.
        """
        for m, n in sorted(self.map_sites.items()):
            mi = self.maps[m]
            if not mi.tagged:
                continue
            budget = mi.nslots // 2
            if n > budget:
                self.error("map %s is accessed at %d sites but only %d slots "
                           "are modelled, and half of those have to be left "
                           "for the keys of the program it is compared "
                           "against.  Raise --map-slots to %d"
                           % (mi.name, n, mi.nslots, 2 * n))

    def emit_slot(self, idx, m, kp, st, kw):
        """The slot a key selects, in a scratch header.

        When the key is a known constant the slot is a literal: the guard in
        `check_array_key` has already established it is below nslots, so
        the modulus is the identity.  That matters for more than tidiness --
        a symbolic slot makes every store into the region a store at an
        unknown index, and the solver then has to reason about all of it.
        Measured on ex/ebpf-se/xdp_pktcntr.c, which writes through a returned
        value pointer: with a symbolic slot the comparison goes from seconds to
        minutes as the region grows.
        """
        o = self.ops
        mi = self.maps[m]
        key = self.const_key(kp, st)
        t_slot = self.fresh_tmp(idx)
        if key is not None:
            o.set_(t_slot, key % mi.nslots)
            return t_slot, key
        t_key = self.read_map_key(idx, kp, kw)
        if t_key is None:
            return None, None
        o.binop("ModOp", "W64", hdr(t_key), konst(mi.nslots), t_slot)
        return t_slot, None

    def read_map_key(self, idx, kp, kw):
        """The key a lookup or an update is given, widened to W64 in a scratch
        header.  Shared by both helpers, which read it identically.

        Returns None (having reported why) if r2 does not point anywhere the
        translator can name.
        """
        o = self.ops
        t_key = self.fresh_tmp(idx)
        if kp.tag == T_STACK:
            # The usual shape: the key was written to a stack slot, which is a
            # header rather than a region cell.
            if not kp.off_known:
                self.unsupported(idx, "map key at a non-constant stack offset")
                return None
            slot = -kp.off
            sh = self.stack_header(slot)
            if not sh:
                self.unsupported(idx, "map key outside the %d-byte frame "
                                      "(slot %d)" % (BPF_STACK_SIZE, slot))
                return None
            o.cast(kw, "W64", hdr(sh), t_key)
        else:
            region = self.region_of(kp)
            if region == REGION_NONE:
                self.unsupported(idx, "map key through r2, whose region is "
                                      "unknown")
                return None
            t_raw = self.fresh_tmp(idx)
            o.load(kw, region, hdr(H_REG(2)), t_raw)
            o.cast(kw, "W64", hdr(t_raw), t_key)
        return t_key

    def copy_map_value(self, idx, vp, mi, m, dst, o):
        """Copy the value r3 points at into the map region at `dst`.

        `dst` is an OPERAND, not a header: a tagged map's arms each write at
        the literal offset of their own slot, which is what keeps the store
        concrete.  `o` is the op list to emit into, which for a tagged map is
        the arm rather than the block -- a failed insert must write nothing.

        The source is usually a stack slot, which is a HEADER holding the whole
        value at the width it was stored -- so it is written out in one store
        rather than copied byte by byte.  A region source of one of the four
        access widths is one load and one store; anything wider is copied a
        byte at a time, which is what the IR's byte-addressed regions make
        natural.
        """
        vs = mi.value_size
        dst_region = self.map_region(m)

        if vp.tag == T_STACK:
            if vs not in (1, 2, 4, 8):
                self.unsupported(idx, "bpf_map_update_elem: a %d-byte value "
                                      "from the stack (a stack slot holds one "
                                      "value, so only 1, 2, 4 and 8 fit)" % vs)
                return False
            if not vp.off_known:
                self.unsupported(idx, "map value at a non-constant stack offset")
                return False
            sh = self.stack_header(-vp.off)
            if not sh:
                self.unsupported(idx, "map value outside the %d-byte frame"
                                 % BPF_STACK_SIZE)
                return False
            o.store(bpf.width_name(vs), dst_region, dst, hdr(sh))
            return True

        src_region = self.region_of(vp)
        if src_region == REGION_NONE:
            self.unsupported(idx, "map value through r3, whose region is unknown")
            return False

        if vs in (1, 2, 4, 8):
            vw = bpf.width_name(vs)
            t_val = self.fresh_tmp(idx)
            o.load(vw, src_region, hdr(H_REG(3)), t_val)
            o.store(vw, dst_region, dst, hdr(t_val))
            return True

        if vs > MAP_MAX_VALUE_COPY:
            self.unsupported(idx, "bpf_map_update_elem: a %d-byte value (the "
                                  "byte-wise copy is capped at %d)"
                             % (vs, MAP_MAX_VALUE_COPY))
            return False
        t_sa, t_da, t_b = (self.fresh_tmp(idx), self.fresh_tmp(idx),
                           self.fresh_tmp(idx))
        for i in range(vs):
            o.binop("AddOp", "W64", hdr(H_REG(3)), konst(i), t_sa)
            o.binop("AddOp", "W64", dst, konst(i), t_da)
            o.load("W8", src_region, hdr(t_sa), t_b)
            o.store("W8", dst_region, hdr(t_da), hdr(t_b))
        return True

    def emit_map_update(self, idx, st):
        """Translate `r0 = bpf_map_update_elem(r1, r2, r3, r4)`.

        An ARRAY map write is straight-line: every entry exists from creation,
        so with BPF_ANY and an in-range key it cannot fail -- pick the slot,
        copy the value in, return 0.

        A HASH map write scans, like a lookup, and can fail.  Its arms, in
        first-match order:

          slot i is filled and its tag is the key -> overwrite it.  Capacity
              is never consulted: the kernel reuses an existing element.
          the map is full                         -> -E2BIG, writing nothing.
              This is the real thing the kernel does when it holds
              max_entries entries and is asked for a NEW key.
          slot i is empty                         -> insert there: tag, then
              presence, then the value.  First-match makes that the LOWEST
              free slot, which matters -- the choice has to be a function of
              the REGION, not of the program, or two programs inserting the
              same key could put it in different slots and be reported
              different on the final contents.
          nothing matched                         -> -E2BIG.  Not the kernel's
              behaviour but the model running out of slots, which
              `check_map_budget` is what keeps improbable.  Of the available
              fallbacks it is the safe one: it invents a behaviour reality
              lacks (a false difference at worst), where rejecting the run
              would DELETE a state reality has, which is how a real
              difference goes missing.

        Fullness is a free region cell (MapInfo.full_off), not something
        derived from the presence bytes: the model holds nslots entries and
        the real map holds max_entries, and tying E2BIG to the former would
        fire it thousands of entries early.

        The flags are CHECKED, not assumed.  BPF_NOEXIST and BPF_EXIST make the
        write conditional on what is already in the slot, which is a branch this
        does not emit; translating them as BPF_ANY would silently model a
        different program, so they are refused.

        Returns the arms when the write needs a branch, and None when it does
        not -- either because it is straight-line, or because it could not be
        translated, which has already been reported.
        """
        o = self.ops
        mp, kp, vp, fl = st.reg[1], st.reg[2], st.reg[3], st.reg[4]

        if mp.tag != T_MAP or mp.mapidx < 0:
            self.unsupported(idx, "bpf_map_update_elem: r1 is not a known map "
                                  "pointer")
            return None
        m = mp.mapidx
        mi = self.maps[m]
        if not self.check_map_modelled(idx, mi):
            return None
        if mi.key_size not in (1, 2, 4, 8):
            self.unsupported(idx, "map %s has a %d-byte key (only 1, 2, 4 and "
                                  "8 are modelled)" % (mi.name, mi.key_size))
            return None
        key = self.const_key(kp, st)
        if mi.is_array and not self.check_array_key(idx, m, key):
            return None
        if mi.is_array and key is None:
            # An update to an array map writes only when key < max_entries and
            # returns -E2BIG otherwise, which is a branch this does not emit.
            # With a constant key the test is decided here; without one it is
            # not.
            self.unsupported(idx, "bpf_map_update_elem on the array map %s "
                                  "with a key that is not a known constant "
                                  "(whether it is in range decides whether "
                                  "anything is written)" % mi.name)
            return None
        if mi.is_array and key >= mi.max_entries:
            # Out of range: the kernel writes nothing and returns -E2BIG.
            o.set_(H_REG(0), (-E2BIG) & MASK64)
            st.reg[0] = SCALAR
            for r in range(1, 6):
                st.reg[r] = SCALAR
            return None
        if fl.tag != T_SCALAR or fl.const is None:
            self.unsupported(idx, "bpf_map_update_elem with flags that are not "
                                  "a known constant")
            return None
        if fl.const != 0:
            self.unsupported(idx, "bpf_map_update_elem with flags=%d; only "
                                  "BPF_ANY (0) is modelled, because BPF_NOEXIST "
                                  "and BPF_EXIST make the write conditional on "
                                  "what is already in the slot" % fl.const)
            return None

        kw = bpf.width_name(mi.key_size)
        self.tmp_next = 0
        self.count_map_site(m)

        for r in range(1, 6):
            st.reg[r] = SCALAR              # clobbered by the call

        if mi.is_array:
            # An array entry exists whether or not anything has been written
            # to it, so there is no presence byte to set and no capacity to
            # run out of.  The write cannot fail.
            t_slot, _const = self.emit_slot(idx, m, kp, st, kw)
            if t_slot is None:
                return None
            t_dst = self.fresh_tmp(idx)
            o.binop("MulOp", "W64", hdr(t_slot), konst(mi.value_size), t_dst)
            o.binop("AddOp", "W64", hdr(t_dst), konst(mi.value_base), t_dst)
            if not self.copy_map_value(idx, vp, mi, m, hdr(t_dst), o):
                return None
            o.set_(H_REG(0), 0)
            st.reg[0] = scalar_const(0)
            return None

        arms = self.emit_tagged_update(idx, m, mi, kp, vp, kw)
        if arms is None:
            return None
        # r0 is 0 or -E2BIG depending on region cells, so it is no longer the
        # known constant it used to be -- which matters, because a later
        # helper's flags argument is only accepted when it IS one.
        st.reg[0] = SCALAR
        return arms

    def emit_tagged_update(self, idx, m, mi, kp, vp, kw):
        """The scan and its arms; see emit_map_update for what each one is."""
        o = self.ops
        region = self.map_region(m)
        t_key = self.read_map_key(idx, kp, kw)
        if t_key is None:
            return None
        pres, tags = self.emit_slot_headers(idx, m, mi, kw)
        # A store takes the value from a header of the STORE's width -- a
        # CrVal carries its type, and a W64 one stored as W32 is ErrorVal --
        # so an insert needs the key narrowed back to the tag's width.  The
        # comparison still uses the widened copy, against widened tags.
        t_tag = self.fresh_tmp(idx)
        o.cast("W64", kw, hdr(t_key), t_tag)
        t_full_raw, t_full = self.fresh_tmp(idx), self.fresh_tmp(idx)
        o.load("W8", region, konst(mi.full_off), t_full_raw)
        o.cast("W8", "W64", hdr(t_full_raw), t_full)

        # Each arm does its own writing, at the LITERAL offsets of its own
        # slot.  Hoisting the stores into a third transformer, so that one
        # store at a selected offset replaced 2*nslots at fixed ones, was
        # tried and reverted: it cut the formula (40259 smt nodes to 34181)
        # and made an Equivalent verdict 1.6x faster, but a NotEquivalent one
        # 11.7x SLOWER -- 667ms to 7794ms on map_update vs map_update_differs.
        # A smaller formula is not an easier one.  With literal offsets the
        # solver can pick an arm and read a counterexample off one cell; with
        # a selected offset every cell depends on the selector, and finding a
        # model means considering all of them at once.  Half the suite is
        # NotEquivalent, so that trade is a loss.
        #
        # Only one arm ever runs, so they can share scratch headers -- which
        # they have to, since a byte-wise copy in each of 2*nslots arms would
        # otherwise exhaust them.
        mark = self.tmp_next

        def arm_ops(i, insert):
            """What the arm for slot i does.  An insert claims the slot first;
            an overwrite finds it already claimed."""
            self.tmp_next = mark
            ops = Ops()
            if insert:
                ops.store(kw, region, konst(mi.tag_off(i)), hdr(t_tag))
                ops.store("W8", region, konst(i), konst(1))
            if not self.copy_map_value(idx, vp, mi, m, konst(mi.value_off(i)),
                                       ops):
                return None
            ops.set_(H_REG(0), 0)
            return ops.ops

        arms = []
        for i in range(mi.nslots):           # the key is already here
            ops = arm_ops(i, insert=False)
            if ops is None:
                return None
            arms.append(([cmp_entry(pres[i], "CmpEq", match_const(1, "W64")),
                          cmp_entry(tags[i], "CmpEq", match_header(t_key))],
                         ops))

        arms.append(([cmp_entry(t_full, "CmpEq", match_const(1, "W64"))],
                     [const_op(H_REG(0), -E2BIG)]))

        for i in range(mi.nslots):           # the lowest free slot takes it
            ops = arm_ops(i, insert=True)
            if ops is None:
                return None
            arms.append(([cmp_entry(pres[i], "CmpEq", match_const(0, "W64"))],
                         ops))

        arms.append(([], [const_op(H_REG(0), -E2BIG)]))
        return arms

    # ── classic-BPF packet loads ────────────────────────────────────────
    def translate_ld_pkt(self, idx, in_, st):
        """LD_ABS reads the packet at the constant in `imm`; LD_IND at
        `src_reg + imm`.  Three things are implicit in the instruction rather
        than encoded, because these lower to a call into the kernel rather
        than to a real load:

          - the destination is always R0, and R1..R5 are clobbered;
          - the value arrives converted from network to host byte order;
          - an access past the end of the packet ABORTS the program,
            returning 0.

        The first two are emitted.  The third is not, and the difference is
        worth being precise about.  An access outside the packet region yields
        ErrorVal and records an overrun, and an overrun rejects the run at the
        sink -- a different terminal state from "returns 0", but a
        conservative one.  Two programs that both run off the packet both
        reject and still compare equal; one that runs off and one that does
        not are reported different, which is right unless the other happened
        to return 0 as well.  So the approximation can raise a false
        difference, never hide a real one.

        Note these index the packet region from 0 directly, rather than
        through ctx->data as an ordinary packet access does -- which is what
        the instruction means, and it makes the offset concrete where a
        ctx->data-based one stays symbolic.
        """
        o = self.ops
        nbytes = bpf.size_bytes(in_.code)
        if nbytes == 8:
            # Classic BPF had no 64-bit packet load; the verifier rejects one.
            self.unsupported(idx, "LD_ABS/LD_IND at 64 bits")
            return
        w = bpf.width_name(nbytes)

        t_addr = self.fresh_tmp(idx)
        if in_.mode == bpf.IND:
            o.binop("AddOp", "W64", hdr(H_REG(in_.src)), konst(in_.imm), t_addr)
        else:
            o.set_(t_addr, in_.imm & MASK64)

        t_val = self.fresh_tmp(idx)
        o.load(w, REGION_PKT, hdr(t_addr), t_val)
        o.cast(w, "W64", hdr(t_val), t_val)
        self.emit_bswap(idx, t_val, nbytes, H_REG(0))

        st.reg[0] = SCALAR
        for r in range(1, 6):
            st.reg[r] = SCALAR

    # ── straight-line translation ───────────────────────────────────────
    def translate_one(self, idx, insns, st):
        """Returns the number of instruction slots consumed (2 for
        LD_IMM64)."""
        in_ = insns[idx]
        self.tmp_next = 0

        if in_.is_nop_jump:
            return 1

        if in_.code == bpf.LD_IMM64:
            if idx + 1 >= len(insns):
                self.unsupported(idx, "truncated LD_IMM64")
                return 1
            # A map address.  The object file's src_reg is still 0 -- libbpf
            # sets it to BPF_PSEUDO_MAP_FD when it applies the relocation --
            # so the relocation is the only marker there is.  The register's
            # value is never read; its tag is what names the region.
            m = self.insn_map_idx.get(idx, -1)
            if m >= 0:
                self.ops.set_(H_REG(in_.dst), 0)
                st.reg[in_.dst] = map_pointer(T_MAP, 0, m)
                return 2
            if in_.src != 0:
                self.unsupported(idx, "LD_IMM64 with src_reg=%d (map/pseudo "
                                      "immediate)" % in_.src)
            v = ((insns[idx + 1].imm & 0xffffffff) << 32) | (in_.imm & 0xffffffff)
            self.ops.set_(H_REG(in_.dst), v)
            st.reg[in_.dst] = scalar_const(v)
            return 2

        c = in_.cls
        if c == bpf.ALU64:
            self.translate_alu(idx, in_, True, st)
        elif c == bpf.ALU:
            self.translate_alu(idx, in_, False, st)
        elif c == bpf.LDX:
            self.translate_ldx(idx, in_, st)
        elif c == bpf.STX:
            if in_.mode == bpf.ATOMIC:
                self.unsupported(idx, "atomic memory op")
            else:
                self.translate_store(idx, in_, st, True)
        elif c == bpf.ST:
            self.translate_store(idx, in_, st, False)
        elif c == bpf.LD:
            if in_.mode in (bpf.ABS, bpf.IND):
                self.translate_ld_pkt(idx, in_, st)
            else:
                self.unsupported(idx, "BPF_LD in mode 0x%x" % in_.mode)
        else:
            self.unsupported(idx, "instruction class 0x%x" % c)
        return 1

    # ── registers the program mentions ──────────────────────────────────
    def scan_used_regs(self, insns):
        """Which registers the program mentions at all.  Used to decide what
        the preamble initialises: seeding a register nothing touches would
        only add a header for every transformer's merge to carry."""
        self.reg_used = [False] * NUM_BPF_REGS

        def mark(r):
            if 0 <= r < NUM_BPF_REGS:
                self.reg_used[r] = True

        i = 0
        while i < len(insns):
            in_ = insns[i]
            if in_.code == bpf.LD_IMM64:
                mark(in_.dst)
                i += 2
                continue
            c = in_.cls
            if c in (bpf.ALU64, bpf.ALU):
                mark(in_.dst)
                if bpf.src(in_.code) == bpf.X:
                    mark(in_.src)
            elif c in (bpf.LDX, bpf.STX):
                mark(in_.dst)
                mark(in_.src)
            elif c == bpf.ST:
                mark(in_.dst)
            elif c == bpf.LD:
                # LD_ABS/LD_IND always write r0 (which the encoding's dst_reg
                # already says) and LD_IND reads src_reg as the offset.
                mark(in_.dst)
                if in_.mode == bpf.IND:
                    mark(in_.src)
            elif in_.is_jmp:
                op = in_.op
                if op == bpf.EXIT:
                    mark(0)                     # EXIT reads r0
                elif op == bpf.CALL:
                    mark(0); mark(1); mark(2)
                elif op != bpf.JA:
                    mark(in_.dst)
                    if bpf.src(in_.code) == bpf.X:
                        mark(in_.src)
            i += 1
        mark(1)     # r1 carries the context pointer whether mentioned or not

    # ── blocks ──────────────────────────────────────────────────────────
    def find_leaders(self, insns):
        """Split into basic blocks.  Returns (block_start, block_of).

        Blocks are emitted in instruction order, which is a topological order
        iff every jump goes forward; backward jumps are rejected.
        """
        n = len(insns)
        is_leader = [False] * (n + 1)
        if n:
            is_leader[0] = True
        i = 0
        while i < n:
            in_ = insns[i]
            if in_.code == bpf.LD_IMM64:
                i += 2
                continue
            if not in_.is_jmp:
                i += 1
                continue
            op = in_.op
            # `JA +0` is a jump to the next instruction.  clang emits a lot of
            # them; splitting a block at each one would double the length of
            # the module chain for nothing.
            if op == bpf.JA and in_.off == 0:
                i += 1
                continue
            if i + 1 < n:
                is_leader[i + 1] = True
            # A CALL ends its block: a map lookup decides between a pointer
            # and NULL, and a decision is a match pattern, which is only read
            # on entry to a transformer.
            if op in (bpf.EXIT, bpf.CALL):
                i += 1
                continue
            target = i + 1 + in_.off
            if target < 0 or target > n:
                self.unsupported(i, "jump target %d is out of range" % target)
                i += 1
                continue
            if target <= i:
                self.unsupported(i, "backward jump to %d (loops are not "
                                    "modelled)" % target)
            is_leader[target] = True
            i += 1

        block_start, block_of = [], [0] * n
        for k in range(n):
            if is_leader[k]:
                block_start.append(k)
            block_of[k] = len(block_start) - 1
        return block_start, block_of

    @staticmethod
    def jmp_is_conditional(in_):
        return in_.is_jmp and in_.op not in (bpf.JA, bpf.EXIT, bpf.CALL)

    def emit_condition(self, idx, in_):
        """The condition of a conditional jump, as one match-pattern entry,
        plus which arm it selects.

        A match pattern is a conjunction of positive comparisons over
        CmpEq/CmpGt/CmpLt with no negation, so the four "or equal" and "not
        equal" forms are expressed by testing the complementary condition and
        swapping the arms; first-match ordering supplies the else.  `swap` is
        set when the entry selects the fallthrough rather than the jump
        target.

        Signed comparisons are biased into unsigned ones by flipping the sign
        bit of both operands (CrVal.ltb is Integers.ltu), which needs scratch
        ops in the block; those are emitted here.

        Returns (entry, swap), or (None, False) if the op is unsupported.
        """
        o = self.ops
        op = in_.op
        is_imm = in_.is_imm
        is32 = in_.cls == bpf.JMP32
        w = "W32" if is32 else "W64"
        imm = (in_.imm & 0xffffffff) if is32 else (in_.imm & MASK64)
        lhs = H_REG(in_.dst)
        is_signed = op in (bpf.JSGT, bpf.JSGE, bpf.JSLT, bpf.JSLE)
        self.tmp_next = 0

        # JSET has no comparison form at all: compute the masked value and
        # test it against zero.
        if op == bpf.JSET:
            t = self.fresh_tmp(idx)
            if is32:
                t2 = self.fresh_tmp(idx)
                o.cast("W64", "W32", hdr(lhs), t2)
                if is_imm:
                    o.binop("AndOp", "W32", hdr(t2), konst(imm), t)
                else:
                    t3 = self.fresh_tmp(idx)
                    o.cast("W64", "W32", hdr(H_REG(in_.src)), t3)
                    o.binop("AndOp", "W32", hdr(t2), hdr(t3), t)
                return cmp_entry(t, "CmpEq", match_const(0, "W32")), True
            if is_imm:
                o.binop("AndOp", "W64", hdr(lhs), konst(imm), t)
            else:
                o.binop("AndOp", "W64", hdr(lhs), hdr(H_REG(in_.src)), t)
            return cmp_entry(t, "CmpEq", match_const(0, "W64")), True

        # Narrow to 32 bits and/or bias by the sign bit, as needed.  Either
        # rewrites both sides into scratch headers.
        if is32 or is_signed:
            bias = 0x80000000 if is32 else 0x8000000000000000
            tl = self.fresh_tmp(idx)
            if is32:
                o.cast("W64", "W32", hdr(lhs), tl)
            else:
                o.move(tl, lhs)
            if is_signed:
                o.binop("XorOp", w, hdr(tl), konst(bias), tl)
            lhs = tl
            if is_imm:
                k = (in_.imm & 0xffffffff) if is32 else imm
                if is_signed:
                    k ^= bias
                rhs = match_const(k, w)
            else:
                tr = self.fresh_tmp(idx)
                if is32:
                    o.cast("W64", "W32", hdr(H_REG(in_.src)), tr)
                else:
                    o.move(tr, H_REG(in_.src))
                if is_signed:
                    o.binop("XorOp", w, hdr(tr), konst(bias), tr)
                rhs = match_header(tr)
        else:
            rhs = match_const(imm, "W64") if is_imm else match_header(H_REG(in_.src))

        table = {
            bpf.JEQ:  ("CmpEq", False), bpf.JNE:  ("CmpEq", True),
            bpf.JGT:  ("CmpGt", False), bpf.JSGT: ("CmpGt", False),
            bpf.JLT:  ("CmpLt", False), bpf.JSLT: ("CmpLt", False),
            bpf.JGE:  ("CmpLt", True),  bpf.JSGE: ("CmpLt", True),
            bpf.JLE:  ("CmpGt", True),  bpf.JSLE: ("CmpGt", True),
        }
        if op not in table:
            self.unsupported(idx, "jump op 0x%x" % op)
            return None, False
        cmp, swap = table[op]
        return cmp_entry(lhs, cmp, rhs), swap

    # ── module emission ─────────────────────────────────────────────────
    def pc_entry(self, pc):
        return cmp_entry(H_PC, "CmpEq", match_const(pc, "W64"))

    def push_transformer(self, rules):
        rules = rules + [default_rule()]
        self.modules.append("(TransformerModule %d Coq_nil Coq_nil %s)"
                            % (self.next_mod, coq_list(rules)))
        self.next_mod += 1

    # ── top level ───────────────────────────────────────────────────────
    def translate_program(self, insns):
        n = len(insns)
        block_start, block_of = self.find_leaders(insns)
        self.scan_used_regs(insns)
        nblocks = len(block_start)

        block_in = [AbsState() for _ in range(nblocks)]

        # Entry state: r1 is the context pointer, r10 the frame pointer.
        # Every other register is undefined on entry (the verifier rejects
        # reading one), so it is left scalar and reads UninitVal if anything
        # does.
        if nblocks:
            entry = block_in[0]
            entry.reg[1] = pointer(T_CTX, 0)
            entry.reg[10] = pointer(T_STACK, 0)
            entry.live = True

        # The preamble seeds pc and gives every register the program mentions
        # a defined u64 value.
        #
        # That last part is not cosmetic.  The symbolic header map starts
        # seeded with SmtUninit, and a transformer's merge keeps the old value
        # on the path where its guard did not match -- so without this, every
        # register's symbolic expression has an SmtUninit leaf and the solver
        # has to carry "this might not be an integer" through the whole
        # program.  Initialising them roughly halves the solve time on a
        # several-hundred-instruction program (measurements in
        # <ir>/memo-memo.txt).
        #
        # It costs nothing in fidelity for any program the BPF verifier
        # accepts: everything but r1 and r10 is undefined at entry and the
        # verifier rejects reading an uninitialised register, so a valid
        # program always writes before it reads.
        self.ops = Ops()
        for r in range(NUM_BPF_REGS):
            if self.reg_used[r]:
                self.ops.set_(H_REG(r), 0)
        self.ops.raw(set_pc_op(BLOCK_PC(0), H_PC))
        # Already unconditional; no default rule needed beyond this one.
        self.modules.append(
            "(TransformerModule %d Coq_nil Coq_nil %s)"
            % (self.next_mod, coq_list([rule([], self.ops.ops)])))
        self.next_mod += 1

        for b in range(nblocks):
            start = block_start[b]
            end = block_start[b + 1] if b + 1 < nblocks else n
            st = block_in[b].copy()
            if not st.live:
                # Unreachable in the abstract sense only; still translated,
                # with everything unknown, so the emitted program stays total.
                st = AbsState()

            term = insns[end - 1]
            has_term = term.is_jmp and not term.is_nop_jump
            body_end = end - 1 if has_term else end

            self.ops = Ops()
            i = start
            while i < body_end:
                i += self.translate_one(i, insns, st)

            # A conditional jump has exactly two arms going to two different
            # blocks, so it keeps its own shape.  A map helper has as many as
            # it has slots, all rejoining at the next block; `map_arms` is
            # (match entries, ops) in first-match order.
            cond, cond_swap = None, False
            map_arms = None
            if has_term and self.jmp_is_conditional(term):
                entry, cond_swap = self.emit_condition(end - 1, term)
                cond = [entry] if entry else None

            # Where control goes, and the abstract state each successor sees.
            fall_pc = take_pc = PC_HALT
            fall_blk = take_blk = -1
            if not has_term:
                if end < n:
                    fall_blk, fall_pc = block_of[end], BLOCK_PC(end)
            else:
                op = term.op
                if op == bpf.EXIT:
                    pass                    # pc := 0; nothing guards on it
                elif op == bpf.CALL:
                    if term.src != 0:
                        self.unsupported(end - 1, "subprogram call")
                    elif term.imm == BPF_FUNC_map_lookup_elem:
                        # A lookup chooses between a value pointer and NULL, so
                        # it hands back a condition and the caller emits the
                        # two-transformer split below.
                        map_arms = self.emit_map_lookup(end - 1, st)
                    elif term.imm == BPF_FUNC_map_update_elem:
                        # A tagged write scans and can fail, so it branches
                        # like a lookup.  An array write cannot, and hands
                        # back None so this block falls through as before.
                        map_arms = self.emit_map_update(end - 1, st)
                    else:
                        self.unsupported(end - 1, "helper call %d (only "
                                                  "bpf_map_lookup_elem and "
                                                  "bpf_map_update_elem are "
                                                  "modelled)" % term.imm)
                    if end < n:
                        fall_blk, fall_pc = block_of[end], BLOCK_PC(end)
                    take_pc = fall_pc       # both arms rejoin at the next block
                elif op == bpf.JA:
                    t = end + term.off
                    if 0 <= t < n:
                        take_blk, take_pc = block_of[t], BLOCK_PC(t)
                else:
                    t = end + term.off
                    if 0 <= t < n:
                        take_blk, take_pc = block_of[t], BLOCK_PC(t)
                    if end < n:
                        fall_blk, fall_pc = block_of[end], BLOCK_PC(end)

            for succ in (fall_blk, take_blk):
                if succ >= 0:
                    st.live = True
                    block_in[succ].join_from(st)

            if cond or map_arms:
                # Ops first, then a second transformer that reads what they
                # computed.  A match pattern is evaluated on entry to its
                # transformer, so the decision cannot live in this one.
                self.ops.raw(set_pc_op(DECIDE_PC(start), H_PC))
                self.push_transformer(
                    [rule([self.pc_entry(BLOCK_PC(start))], self.ops.ops)])

                if map_arms:
                    # Every arm rejoins at the next block, so they differ only
                    # in what they leave in r0 and the region.
                    arms = [(e, ops, fall_pc) for e, ops in map_arms]
                else:
                    first_pc = fall_pc if cond_swap else take_pc
                    second_pc = take_pc if cond_swap else fall_pc
                    arms = [(cond, [], first_pc), ([], [], second_pc)]

                self.push_transformer([
                    rule([self.pc_entry(DECIDE_PC(start))] + entries,
                         list(ops) + [set_pc_op(pc, H_PC)])
                    for entries, ops, pc in arms
                ])
            else:
                next_pc = take_pc if take_blk >= 0 else fall_pc
                self.ops.raw(set_pc_op(next_pc, H_PC))
                self.push_transformer(
                    [rule([self.pc_entry(BLOCK_PC(start))], self.ops.ops)])

    def emit_program(self, out):
        # No parser module: T_0 (module MOD_FIRST_XFRM) is the network's
        # source directly.  See the module docstring.
        # Deparser: emit r0, which is what an eBPF program returns -- 32 bits
        # of it, since a BPF return value is a u32.
        deparser = ("(DeparserModule %d (Coq_cons (EmitOpConstructor %d 32) "
                    "Coq_nil))" % (MOD_DEPARSER, H_REG(0)))

        all_mods = self.modules + [deparser]

        edges = ["(%d %d)" % (m, m + 1)
                 for m in range(MOD_FIRST_XFRM, self.next_mod - 1)]
        edges.append("(%d %d)" % (self.next_mod - 1, MOD_DEPARSER))

        # Regions: ctx, the packet, and one per declared map.  The checker
        # refuses to compare two programs whose declarations differ, and the
        # two objects declare the same maps because they come from one source.
        regions = ["((mr_id %d) (mr_len %d))" % (REGION_CTX, self.ctx.length),
                   "((mr_id %d) (mr_len %d))" % (REGION_PKT, PKT_LEN)]
        regions += ["((mr_id %d) (mr_len %d))" % (self.map_region(i), m.length)
                    for i, m in enumerate(self.maps)]

        out.write("(GeneralCaracaraProgramDef 0\n")
        for i, m in enumerate(self.maps):
            out.write("  ; region %d = map %s (key %d, value %d, %d of %d slots)\n"
                      % (self.map_region(i), m.name, m.key_size, m.value_size,
                         m.nslots, m.max_entries))
        out.write("  %s\n" % coq_list(regions))
        out.write("  ((net_modules %s)\n" % coq_list(all_mods))
        out.write("   (net_edges (%s))\n" % " ".join(edges))
        out.write("   (start_module %d)))\n" % MOD_FIRST_XFRM)

    # ── driving it from an object file ──────────────────────────────────
    def load_map_relocs(self, elf, sec_index, ninsns):
        """Fill in insn_map_idx from the relocations that apply to a section.
        A map reference is an R_BPF_64_64 against a symbol that names a map,
        sitting on the LD_IMM64 that loads the map address."""
        for r_offset, sym_idx, r_type in elf.relocations(sec_index):
            if r_type != R_BPF_64_64 or sym_idx >= len(elf.symbols):
                continue
            m = self.find_map(elf.symbols[sym_idx].name)
            if m < 0:
                continue
            idx = r_offset // bpf.INSN_SIZE
            if idx < ninsns:
                self.insn_map_idx[idx] = m

    def probe_map_sites(self, blob, ctx_override):
        """How many times the program uses each map.

        Which map a helper call names comes from the abstract state of r1, so
        translating is the only way to find out -- hence a throwaway pass
        whose output is discarded and whose diagnostics are silenced.  The
        real pass makes the same discoveries and reports them.
        """
        probe = Translator(self.ctx, map_slots=MAP_MAX_SLOTS)
        probe.quiet = True
        probe.run(blob, ctx_override, io.StringIO())
        return dict((probe.maps[m].name, n)
                    for m, n in probe.map_sites.items())

    def run(self, blob, ctx_override=None, out=sys.stdout):
        """Returns 0 on success, non-zero if the object could not be read at
        all.  `had_error` separately records a translation that ran but is
        incomplete."""
        if self.map_slots is None and self.site_hint is None:
            self.site_hint = self.probe_map_sites(blob, ctx_override)
        try:
            elf = Elf(blob)
        except ValueError as e:
            print("bpf_to_ir: %s" % e, file=sys.stderr)
            return 1

        # Maps, from whichever declaration style the object uses.
        for s in elf.sections:
            if not s.size:
                continue
            if s.name == "maps" and elf.symbols:
                self.discover_legacy_maps(elf, s)
            elif s.name == ".BTF":
                self.discover_btf_maps(s.data)
        # Region ids have to agree between the two objects being compared, and
        # section and symbol order do not.  Names do.
        self.maps.sort(key=lambda m: m.name.encode())
        self.size_maps()

        for s in elf.sections:
            if not s.size:
                continue
            if not (s.flags & SHF_EXECINSTR) and "text" not in s.name \
                    and "xdp" not in s.name:
                continue

            self.ctx = ctx_override or ctx_layout_for(s.name)
            if self.ctx is None:
                print("bpf_to_ir: section %s: no context layout is known for "
                      "this program type; the ctx region would be the wrong "
                      "size and every field access an overrun.  Pass "
                      "--ctx=xdp_md or --ctx=__sk_buff to say which it is."
                      % s.name, file=sys.stderr)
                return 1

            insns = bpf.decode(s.data[:len(s.data) // bpf.INSN_SIZE * bpf.INSN_SIZE])
            if len(insns) > MAX_INSNS:
                print("bpf_to_ir: section %s has %d instructions (max %d)"
                      % (s.name, len(insns), MAX_INSNS), file=sys.stderr)
                return 1

            self.insn_map_idx = {}
            if elf.symbols:
                self.load_map_relocs(elf, s.index, len(insns))

            self.translate_program(insns)
            self.check_map_budget()
            self.emit_program(out)
            return 0

        print("bpf_to_ir: no executable section found", file=sys.stderr)
        return 1
