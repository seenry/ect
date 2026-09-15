"""Replay every NotEquivalent verdict's counterexample and confirm it is real.

For each single-instruction mutation of a program, ask the checker; when it
answers NotEquivalent, take the SAT valuation it printed, seed both lowered
programs with it, and run them.  The two must produce different observable
output -- if they do not, the checker produced a counterexample that does not
witness anything, which would be a soundness bug.

This is the direction that actually pins the checker down.  Random seeding is
far too weak to find these inputs on its own (vlan_filter needs
vlan_tci & 0xfff in {2,4}), so the solver's own answer is the only practical
source of them.

Usage:  .venv/bin/python tests/witness_check.py <object> [<object> ...]
"""

import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

from irrunner import shared
from mutate import mutations, observable, parse_witness
from mutation_sweep import lower, eqcheck_output, EQCHECK


def check(path, out=sys.stdout, limit=None):
    blob = open(path, "rb").read()
    base = lower(blob)
    if base is None:
        print("  %-32s (does not translate cleanly; skipped)" % path,
              file=out, flush=True)
        return (0, 0, 0, 0, [])
    tot = confirmed = poisoned = 0
    bad = []
    equivalent = 0
    for k, (name, mblob) in enumerate(mutations(blob)):
        if limit and k >= limit:
            break
        mir = lower(mblob)
        if mir is None or mir == base:
            continue
        stdout = eqcheck_output(base, mir)
        if "Not Equivalent" not in stdout:
            equivalent += 1
            continue
        tot += 1
        seed, poison = parse_witness(stdout)
        if poison or not seed:
            poisoned += 1
            continue
        run = shared()
        if observable(run, base, seed) != observable(run, mir, seed):
            confirmed += 1
        else:
            bad.append(name)
    print("  %-32s %3d NotEquivalent, %3d confirmed, %2d unusable witness, "
          "%2d Equivalent%s"
          % (os.path.basename(path), tot, confirmed, poisoned, equivalent,
             "   *** %d UNCONFIRMED: %s" % (len(bad), bad) if bad else ""),
          file=out, flush=True)
    return (tot, confirmed, poisoned, equivalent, bad)


if __name__ == "__main__":
    # Fail loudly rather than raising once per mutation: a missing checker
    # otherwise produces a traceback per pair and zero results, which is how a
    # whole sweep once came back empty.
    if not os.path.exists(EQCHECK):
        sys.exit("witness_check: %s does not exist.  Build it with\n"
                 "  cd ~/proj/ir && dune build --profile release" % EQCHECK)
    args = [a for a in sys.argv[1:] if not a.startswith("--limit=")]
    LIMIT = next((int(a.split("=")[1]) for a in sys.argv[1:]
                  if a.startswith("--limit=")), None)
    T = C = P = E = 0
    BAD = []
    for p in args:
        t, c, pz, e, b = check(p, limit=LIMIT)
        T += t; C += c; P += pz; E += e; BAD += b
    print("\nTOTAL  %d NotEquivalent verdicts | %d confirmed by execution | "
          "%d unusable witness | %d Equivalent | %d UNCONFIRMED"
          % (T, C, P, E, len(BAD)), flush=True)
    sys.exit(1 if BAD else 0)
