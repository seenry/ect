"""Building the Caracara s-expression.

This is the layer the C version spent ~300 lines on (StrVec, xsprintf, manual
Coq-list construction with hand-computed buffer sizes).  Here a list of ops is
a list of strings.
"""

MASK64 = (1 << 64) - 1


def coq_list(items):
    """`[a, b]` -> `(Coq_cons a (Coq_cons b Coq_nil))`."""
    out = "Coq_nil"
    for it in reversed(items):
        out = "(Coq_cons %s %s)" % (it, out)
    return out


def konst(v):
    """Coq's uint64 is a Z; emit values already reduced mod 2^64."""
    return "(OpConst %d)" % (v & MASK64)


def hdr(h):
    return "(OpHeader %d)" % h


def match_const(k, w):
    return "(MatchConst %d %s)" % (k & MASK64, w)


def match_header(h):
    return "(MatchHeader %d)" % h


def cmp_entry(lhs_hdr, cmp, rhs):
    """One entry of a match pattern: header `cmp` value."""
    return "(Coq_pair (Coq_pair %d %s) %s)" % (lhs_hdr, cmp, rhs)


def rule(match_entries, ops):
    return "(Seq (SeqCtr %s %s))" % (coq_list(match_entries), coq_list(ops))


def default_rule():
    """Every transformer ends with an empty-pattern default rule, which
    CrDslProperties.transformer_has_default requires; it does nothing, so a
    state whose pc names no block passes through untouched."""
    return "(Seq (SeqCtr Coq_nil Coq_nil))"


class Ops:
    """The op list of the block being translated."""

    def __init__(self):
        self.ops = []

    def __len__(self):
        return len(self.ops)

    def raw(self, s):
        self.ops.append(s)

    def binop(self, op, w, a1, a2, target):
        self.ops.append("(StatelessOp %s %s %s %s %d)" % (op, w, a1, a2, target))

    def cast(self, frm, to, arg, target):
        self.ops.append("(CastHeaderOp %s %s %s %d)" % (frm, to, arg, target))

    def load(self, w, region, off, target):
        self.ops.append("(LoadOp %s %d %s %d)" % (w, region, off, target))

    def store(self, w, region, off, val):
        self.ops.append("(StoreOp %s %d %s %s)" % (w, region, off, val))

    def set_(self, target, v):
        """dst := imm, at u64"""
        self.binop("AddOp", "W64", konst(v), konst(0), target)

    def move(self, target, src):
        """dst := src, at u64"""
        self.binop("AddOp", "W64", hdr(src), konst(0), target)


def set_pc_op(pc, h_pc):
    return "(StatelessOp AddOp W64 (OpConst %d) (OpConst 0) %d)" % (pc, h_pc)


def assign_op(target, src_hdr):
    return "(StatelessOp AddOp W64 (OpHeader %d) (OpConst 0) %d)" % (src_hdr, target)


def const_op(target, v):
    """dst := v, at u64.  The arms of a map scan assign a literal value
    pointer, which is what keeps the offset of a later load concrete."""
    return ("(StatelessOp AddOp W64 (OpConst %d) (OpConst 0) %d)"
            % (v & MASK64, target))


def zero_op(target):
    return const_op(target, 0)
