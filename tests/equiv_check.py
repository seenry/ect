"""The other direction: try to refute every Equivalent verdict.

For each mutation the checker calls Equivalent, search for an input on which
the two lowered programs behave differently.  Finding one would mean the
checker missed a real difference.

This direction is inherently weaker than witness_check.py: absence of a
separating input after N random seeds is evidence, not proof.  Report it as
"no contradiction found", never as "verified".

Usage:  .venv/bin/python tests/equiv_check.py [--seeds=N] <object> ...
"""

import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

from irrunner import shared
from mutate import mutations, observable, regions_of
from mutation_sweep import lower, seeds, eqcheck_output, EQCHECK


def check(path, rng, n):
    blob = open(path, "rb").read()
    base = lower(blob)
    if base is None:
        return 0, []
    tot, bad = 0, []
    for name, mblob in mutations(blob):
        mir = lower(mblob)
        if mir is None or mir == base:
            continue
        if "Not Equivalent" in eqcheck_output(base, mir):
            continue
        tot += 1
        run = shared()
        for s in seeds(regions_of(base), rng, n):
            if observable(run, base, s) != observable(run, mir, s):
                bad.append(name)
                break
    print("  %-30s %2d Equivalent verdicts, %d contradicted"
          % (os.path.basename(path), tot, len(bad)),
          flush=True)
    if bad:
        print("     contradicted: %s" % bad, flush=True)
    return tot, bad


if __name__ == "__main__":
    if not os.path.exists(EQCHECK):
        sys.exit("equiv_check: %s does not exist; build it first" % EQCHECK)
    n = next((int(a.split("=")[1]) for a in sys.argv[1:]
              if a.startswith("--seeds=")), 200)
    paths = [a for a in sys.argv[1:] if not a.startswith("--")]
    T, BAD = 0, []
    rng = random.Random(4242)
    for p in paths:
        t, b = check(p, rng, n)
        T += t; BAD += b
    print("\n%d Equivalent verdicts, %d contradicted by %d random inputs each.\n"
          "(No contradiction is evidence, not proof.)" % (T, len(BAD), n))
    sys.exit(1 if BAD else 0)
