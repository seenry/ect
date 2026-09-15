"""Reading the s-expressions bpf_to_ir emits.

Only enough to walk the structure: the CONTENTS are interpreted by the
extracted evaluator (EqCheck --serve), not here.
"""

import re

_TOK = re.compile(r"\(|\)|[^\s()]+")


def parse(text):
    """s-expression -> nested lists.  `;` starts a line comment."""
    text = "\n".join(l.split(";", 1)[0] for l in text.splitlines())
    toks = _TOK.findall(text)
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


def coq_list(n):
    """`(Coq_cons a (Coq_cons b Coq_nil))` -> [a, b]."""
    out = []
    while isinstance(n, list) and n and n[0] == "Coq_cons":
        out.append(n[1])
        n = n[2]
    return out


