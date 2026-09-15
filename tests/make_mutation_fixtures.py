"""Generate bytecode-mutation fixtures for the IR's equivalence tests.

Every pair here is a single in-place instruction edit to a real program, with
an expected verdict established two ways:

  * NotEquivalent pairs come with a concrete input, found by running both
    lowered programs, on which their observable behaviour differs.  A witness
    is a PROOF of inequivalence, so `Equivalent` from the checker would be a
    soundness bug.
  * Equivalent pairs are ones no input we tried separates, and which the
    solver independently proves equal.

The point of mutating BYTECODE rather than source is that these are
differences a compiler would never produce -- the existing pairs in the suite
are all source-level variants, which exercise the checker only on the shapes
clang happens to emit.

Usage:  .venv/bin/python tests/make_mutation_fixtures.py [--check]
"""

import os
import random
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

from irrunner import shared
from mutate import mutations, observable, parse_witness, regions_of
from mutation_sweep import lower, seeds, eqcheck_output

ECT = os.path.dirname(HERE)
IR_TEST = os.path.expanduser("~/proj/ir/test")

# (fixture name, object, mutation label, expected verdict, why)
FIXTURES = [
    ("bpf_vlan_filter_narrowed", "ex/suricata/vlan_filter.o", "aluwidth@1",
     "Equivalent",
     "the mask of vlan_tci done at 32 bits instead of 64.  vlan_tci is a u32 "
     "and the mask keeps 12 bits, so nothing can reach the upper half and the "
     "narrower operation computes the same thing."),
    ("bpf_vlan_filter_mask", "ex/suricata/vlan_filter.o", "imm@1 4095->4096",
     "NotEquivalent",
     "the VLAN id mask changed from 0x0fff to 0x1000, so the filter selects "
     "on a different bit entirely."),
    ("bpf_vlan_filter_cmp", "ex/suricata/vlan_filter.o", "jmpop@5 JEQ->JNE",
     "NotEquivalent",
     "the accept test inverted: JEQ becomes JNE, so the filter accepts exactly "
     "the VLAN ids it used to drop."),
    ("bpf_ref_nop", "ex/basic/ex0.o", "nop@0", "Equivalent",
     "an instruction deleted (NOPped out).  It is dead -- the value it "
     "computes is overwritten before any use -- which is the kind of "
     "difference an optimiser makes and a compiler would never emit as a "
     "source variant."),
]


def apply_named(blob, label, rng):
    for name, mutated in mutations(blob, rng):
        if name == label:
            return mutated
    raise SystemExit("no mutation named %r (the generator is seeded, so the "
                     "labels are stable; re-derive them if mutate.py changes)"
                     % label)


def main(check_only):
    rng = random.Random(0)
    ok = True
    for fixture, obj, label, expected, why in FIXTURES:
        blob = open(os.path.join(ECT, obj), "rb").read()
        base = lower(blob)
        assert base is not None, obj
        mir = lower(apply_named(blob, label, random.Random(0)))
        assert mir is not None, "%s: the mutant does not translate" % label
        assert mir != base, "%s: the mutation did not change the IR" % label

        # Re-establish the expectation by execution rather than trusting the
        # table.  For a NotEquivalent pair the separating input is taken from
        # the CHECKER's own counterexample: random seeding almost never finds
        # one (vlan_filter needs vlan_tci & 0xfff in {2,4}, about 1 in 2048),
        # whereas the solver constructs it.  Replaying it here is what turns
        # "the checker says they differ" into "they demonstrably differ".
        run = shared()
        sep = None
        for s in seeds(regions_of(base), rng, 200):
            if observable(run, base, s) != observable(run, mir, s):
                sep = "random input"
                break
        if sep is None:
            out = eqcheck_output(base, mir)
            seed, poison = parse_witness(out)
            if seed and not poison and \
                    observable(run, base, seed) != observable(run, mir, seed):
                sep = "the checker's own counterexample, replayed"
        if expected == "NotEquivalent" and sep is None:
            print("  %-30s ERROR: nothing separates them, so NotEquivalent is "
                  "unjustified" % fixture)
            ok = False
            continue
        if expected == "Equivalent" and sep is not None:
            print("  %-30s ERROR: expected Equivalent but %s separates them"
                  % (fixture, sep))
            ok = False
            continue

        path = os.path.join(IR_TEST, fixture + ".ir")
        if check_only:
            cur = open(path).read() if os.path.exists(path) else None
            state = "ok" if cur == mir else "STALE"
            print("  %-30s %-14s %s" % (fixture, expected, state))
            ok = ok and cur == mir
        else:
            with open(path, "w") as f:
                f.write(mir)
            print("  %-30s %-14s written  %s" % (fixture, expected,
                  "separated by %s" % sep if sep else "no input separates them"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main("--check" in sys.argv))
