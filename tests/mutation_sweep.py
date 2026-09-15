"""Sweep: mutate a program, decide by execution whether the mutation changed
it, and check the OCaml equivalence checker's verdict against that.

Usage:  .venv/bin/python tests/mutation_sweep.py <object> [<object> ...]
"""

import io
import os
import random
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

from irrunner import shared
from mutate import mutations, observable, regions_of
from pybpf.translate import Translator, ctx_layout_for
from pybpf.elf import Elf, SHF_EXECINSTR

EQCHECK = os.path.expanduser(
    "~/proj/ir/_build/default/extracted_code/EqCheck.exe")


def lower(blob):
    """Returns the IR text, or None if the translator refused//reported."""
    e = Elf(blob)
    sec = next((s for s in e.sections if s.size and (s.flags & SHF_EXECINSTR)), None)
    ctx = ctx_layout_for(sec.name) if sec else None
    if ctx is None:
        return None
    t = Translator()
    buf = io.StringIO()
    err = io.StringIO()
    old, sys.stderr = sys.stderr, err
    try:
        rc = t.run(blob, ctx, buf)
    finally:
        sys.stderr = old
    return None if (rc != 0 or t.had_error) else buf.getvalue()


def seeds(regions, rng, n):
    """Random contents for every declared region, as runner seed tuples."""
    return [[(r, off, 1, rng.getrandbits(8))
             for r, length in sorted(regions.items())
             for off in range(length)]
            for _ in range(n)]


def classify(ir_a, ir_b, rng, n=60):
    """('differs', index) if some seed separates them, else ('same', None)."""
    ra, rb = regions_of(ir_a), regions_of(ir_b)
    if ra != rb:
        return "regions-differ", None
    run = shared()
    for i, s in enumerate(seeds(ra, rng, n)):
        if observable(run, ir_a, s) != observable(run, ir_b, s):
            return "differs", i
    return "same", None


def verdict(ir_a, ir_b):
    with tempfile.NamedTemporaryFile("w", suffix=".ir", delete=False) as fa, \
         tempfile.NamedTemporaryFile("w", suffix=".ir", delete=False) as fb:
        fa.write(ir_a); fb.write(ir_b)
        pa, pb = fa.name, fb.name
    try:
        r = subprocess.run([EQCHECK, "--net", pa, pb], capture_output=True, text=True)
        last = [l for l in r.stdout.strip().splitlines() if l.strip()]
        return last[-1].strip() if last else "?"
    finally:
        os.unlink(pa); os.unlink(pb)


def sweep(path, rng, limit=None):
    blob = open(path, "rb").read()
    base = lower(blob)
    if base is None:
        print("  (the unmutated program does not translate cleanly; skipping)")
        return []
    rows = []
    for k, (name, mblob) in enumerate(mutations(blob, rng)):
        if limit and k >= limit:
            break
        mir = lower(mblob)
        if mir is None:
            rows.append((name, "rejected", "-", True))
            continue
        if mir == base:
            rows.append((name, "identical-ir", "-", True))
            continue
        kind, _ = classify(base, mir, rng)
        v = verdict(base, mir)
        if kind == "differs":
            ok = v.replace(" ", "") == "NotEquivalent"       # a witness exists: SOUND
        elif kind == "same":
            ok = v == "Equivalent"                            # heuristic
        else:
            ok = v.startswith("NotEquivalentVariablesDiffer")
        rows.append((name, kind, v, ok))
    return rows


if __name__ == "__main__":
    rng = random.Random(20260902)
    total = bad = 0
    for path in sys.argv[1:]:
        print("=== %s" % path)
        rows = sweep(path, rng)
        for name, kind, v, ok in rows:
            total += 1
            if not ok:
                bad += 1
                print("   MISMATCH  %-28s execution=%-9s checker=%s"
                      % (name, kind, v))
        agree = sum(1 for _, k, _, o in rows if o and k in ("differs", "same"))
        diff = sum(1 for _, k, _, _ in rows if k == "differs")
        same = sum(1 for _, k, _, _ in rows if k == "same")
        skip = sum(1 for _, k, _, _ in rows if k in ("rejected", "identical-ir"))
        print("   %d mutations: %d differ, %d indistinguishable, %d not comparable"
              % (len(rows), diff, same, skip))
    print("\n%d checked, %d mismatches" % (total, bad))


def eqcheck_output(ir_a, ir_b):
    """Raw EqCheck stdout, including the SAT valuation on NotEquivalent."""
    with tempfile.NamedTemporaryFile("w", suffix=".ir", delete=False) as fa, \
         tempfile.NamedTemporaryFile("w", suffix=".ir", delete=False) as fb:
        fa.write(ir_a); fb.write(ir_b)
        pa, pb = fa.name, fb.name
    try:
        return subprocess.run([EQCHECK, "--net", pa, pb],
                              capture_output=True, text=True).stdout
    finally:
        os.unlink(pa); os.unlink(pb)
