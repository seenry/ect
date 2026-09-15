"""A tiny evaluator for the arithmetic ops the translator emits.

Enough of the IR to check that a *synthesized* operator computes what it
claims: emit_bswap and emit_arsh_const build a byte swap and an arithmetic
shift out of multiply, divide, and/or, and the only way to know they are right
is to run them.  Comparing emitted strings would only pin the current output,
not its meaning.

Division and remainder follow BPF and the IR: x/0 = 0 and x%0 = x.
"""

import re

_TOK = re.compile(r"\(|\)|[^\s()]+")


def _parse(s):
    toks = _TOK.findall(s)
    pos = 0

    def node():
        nonlocal pos
        if toks[pos] == "(":
            pos += 1
            out = []
            while toks[pos] != ")":
                out.append(node())
            pos += 1
            return out
        t = toks[pos]
        pos += 1
        return t

    return node()


_BITS = {"W8": 8, "W16": 16, "W32": 32, "W64": 64}


def _mask(v, w):
    return v & ((1 << _BITS[w]) - 1)


def _operand(node, regs):
    if node[0] == "OpConst":
        return int(node[1])
    if node[0] == "OpHeader":
        return regs.get(int(node[1]), 0)
    raise AssertionError("unhandled operand %r" % (node,))


def eval_ops(ops, regs=None):
    """Run a list of emitted op strings over a header -> value mapping."""
    regs = dict(regs or {})
    for op in ops:
        n = _parse(op)
        if n[0] == "StatelessOp":
            _, f, w, a1, a2, target = n
            x, y = _operand(a1, regs), _operand(a2, regs)
            x, y = _mask(x, w), _mask(y, w)
            if f == "AddOp":   r = x + y
            elif f == "SubOp": r = x - y
            elif f == "AndOp": r = x & y
            elif f == "OrOp":  r = x | y
            elif f == "XorOp": r = x ^ y
            elif f == "MulOp": r = x * y
            elif f == "DivOp": r = 0 if y == 0 else x // y
            elif f == "ModOp": r = x if y == 0 else x % y
            else: raise AssertionError("unhandled op %s" % f)
            regs[int(target)] = _mask(r, w)
        elif n[0] == "CastHeaderOp":
            _, frm, to, arg, target = n
            regs[int(target)] = _mask(_mask(_operand(arg, regs), frm), to)
        elif n[0] in ("LoadOp", "StoreOp"):
            continue        # memory is not modelled here
        else:
            raise AssertionError("unhandled op %r" % (n[0],))
    return regs
