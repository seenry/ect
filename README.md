# ect — eBPF → Caracara IR

Tools for getting compiled eBPF bytecode into the Caracara IR, which this is a
submodule of (`../..`), so
that two lowerings of one program can be proved equivalent.

- `bpf_to_ir` — translate an object into a `GeneralCaracaraProgram`
  s-expression for the unified IR.
- `bpf_dump` — decode and print the BPF instructions in an ELF object.

Both are Python and need no build step; the work lives in `pybpf/`:

| | |
|---|---|
| `pybpf/bpf.py` | instruction encoding and decoding |
| `pybpf/elf.py` | ELF sections, symbols, relocations |
| `pybpf/btf.py` | BTF, for sizing modern maps |
| `pybpf/ir.py` | building the Caracara s-expression |
| `pybpf/disasm.py` | rendering an instruction as text |
| `pybpf/translate.py` | the translator |

## Building

Nothing needs compiling to run the tools. `make` builds the *examples*, for
which the BPF backend is needed — it is not in the stock macOS toolchain, so
put an LLVM that has it on `PATH`, or point the Makefile at one:

```bash
source ~/llvm-project/set_env
make

make CLANG=/opt/homebrew/opt/llvm/bin/clang LLC=/opt/homebrew/opt/llvm/bin/llc
```

A **stock** LLVM is enough. There used to be an `%.ast` rule running
`-Xclang -ast-dump`, which needed a locally patched clang; nothing consumed
its output, so both are gone.

Only the `.c` sources are checked in. `make` produces, and `.gitignore`
ignores, everything else:

| | |
|---|---|
| `ex/**/NAME.O1.o`, `NAME.O2.o` | every program compiled at two optimization levels |
| `ex/**/NAME.O1.ir`, `NAME.O2.ir` | each of those translated |
| `ex/basic/ex0.O0.ir` | the one source that also translates at `-O0` — see below |

So `make` on its own produces 19 pairs of the kind the equivalence checker is
for: one program against the same program after LLVM has optimized it. `make
clean` removes all of it, `make objs` and `make ir` build half each.

**-O0 is not one of the two levels, and cannot be.** The eBPF-SE and Suricata
shims declare each helper as a function *pointer* initialized to its helper
number, and only `-O1` and up fold that to an immediate; at `-O0` clang emits
an indirect `call rN`, which `bpf_to_ir` does not model, and every map access
downstream then loses its provenance. The REF pair is the exception because
`ex/basic/ex0.c` calls no helper.

```bash
make test        # unit tests; see "Tests" below
```

(`llc -march=bpf` was the old spelling and current LLVM rejects it; the
Makefile uses `-mtriple=bpf`.)

## The end-to-end check

```bash
source ~/llvm-project/set_env
make ex/basic/ex0.O0.ir ex/basic/ex0.O2.ir
(cd ../.. && dune build --profile release)
../../_build/default/extracted_code/EqCheck.exe --net \
    ex/basic/ex0.O0.ir ex/basic/ex0.O2.ir
# Equivalent
```

`EqCheck --net` runs `modnet_equivalence_checker`, which compares the emitted
return value, the number of input bits read, and the final contents and access
extents of every declared memory region. The same pair is checked in the IR's
test suite (`TestEquality`, "e2e bpf test: O0 ≡ O2, unified IR") against the
checked-in copies at `../../test/bpf_O{0,2}.ir`, alongside concrete runs of both
programs in `TestModuleSemantics` — the checker on its own would also be
satisfied by two programs that are equally broken.

The map programs in `ex/map/` are checked the same way, as three pairs against
`map_ref` -- one Equivalent and two NotEquivalent, since a verdict in only one
direction says nothing.  So are the two Suricata filters in `ex/suricata/`,
which are production sources carried verbatim.

Regenerate those fixtures after changing `bpf_to_ir`. `make` already produces
every one of them, so this is a copy rather than a second pipeline — and the
fixtures are the `-O2` translations, which is what `.O2.ir` means:

```bash
make
cp ex/basic/ex0.O0.ir ../../test/bpf_O0.ir
cp ex/basic/ex0.O2.ir ../../test/bpf_O2.ir
for f in map_ref map_spill map_miss_differs map_hit_differs \
         map_update map_update_differs map_update_spill; do
  cp ex/map/$f.O2.ir ../../test/bpf_$f.ir
done
for f in vlan_filter vlan_filter_alt pkt_load; do
  cp ex/suricata/$f.O2.ir ../../test/bpf_$f.ir
done
# filter.c keeps its upstream name in ex/ but is bpf_sur_filter.ir in the IR
cp ex/suricata/filter.O2.ir     ../../test/bpf_sur_filter.ir
cp ex/suricata/filter_alt.O2.ir ../../test/bpf_sur_filter_alt.ir
for f in xdp_pktcntr xdp_pktcntr_alt cls_pktcntr cls_pktcntr_alt; do
  cp ex/ebpf-se/$f.O2.ir ../../test/bpf_$f.ir
done
```

Three fixtures have no source here and are not regenerated this way:
`bpf_vlan_filter_narrowed.ir`, `_mask.ir` and `_cmp.ir` are single in-place
edits to `vlan_filter`'s BYTECODE — one behaviour-preserving, two not — which
exist because a source-level variant only exercises the differences clang
happens to emit.

`ex/suricata/offsets.c` and `ex/ebpf-se/offsets.c` are not programs: they
static-assert every field offset the programs in their directory read, so a
wrong one in the shim header breaks `make` instead of silently modelling a
different field.

## The example programs

`ex/` holds the sources the fixtures are generated from, grouped by upstream.
Everything outside `ex/basic/` is production code carried verbatim apart from
its `#include`s, which are replaced by a per-directory shim so it builds
without a kernel tree.

| | |
|---|---|
| `ex/basic/` | small hand-written programs, plus `opcodes.c`, a codegen fixture |
| `ex/map/` | map lookup and update, with variants |
| `ex/suricata/` | `vlan_filter.c` and `filter.c` from [Suricata](https://github.com/OISF/suricata) |
| `ex/ebpf-se/` | katran's two packet counters and the `fw` map example, from [ebpf-se](https://github.com/dslab-epfl/ebpf-se) |

Each production program is paired with an `_alt` variant differing in exactly
one way, because a verdict in only one direction says nothing — an
`Equivalent` that comes from both programs *rejecting* looks identical to one
that comes from both computing the same answer.

All three `ex/ebpf-se/` programs return a **constant** on every path, so a
checker comparing only the emitted packet would call two of the three pairs
equivalent. What separates them is the map region: `xdp_pktcntr` differs from
its variant only in the counter it leaves behind, and `map_access` only in what
`bpf_map_update_elem` writes.

## Usage

```bash
./bpf_to_ir <path_to_bpf_object_file>   # s-expression on stdout
./bpf_dump  <path_to_bpf_object_file>
```

`bpf_dump` prints one line per instruction:

```
[index] code=0xXX dst=N src=N off=N imm=N | DECODED_INSTRUCTION

[   0] code=0xb7 dst=0 src=0 off=0 imm=0 | ALU64_MOV r0, 0x0
[   1] code=0x95 dst=0 src=0 off=0 imm=0 | JMP_EXIT
```

## How the translation works

The long version is the module docstring of `pybpf/translate.py`. In brief:

- **Registers are headers.** Each of `r0`–`r10` is one `u64` header, and the
  preamble gives every register the program mentions a defined `u64` value at
  entry — without that, each register's symbolic expression carries an
  "uninitialised" leaf that the solver drags through the whole program (~1.25x
  on a several-hundred-instruction pair). Costs nothing in fidelity: the BPF
  verifier rejects reading an uninitialised register, so a valid program always
  writes before it reads. (The previous
  translator, which targeted a standalone memory IR since deleted, had to split
  every register into eight `u8` bytes with a hand-rolled ripple-carry chain
  because that IR had no wide integer type; a 64-bit add cost ~24 instructions
  and now costs one. `ex0`'s `-O0` translation went from 62 kB to 5 kB.)
- **Memory is declared regions**: `ctx` (1), `pkt` (2), and one per BPF map
  (10 and up). A load or store names its region statically and takes the
  offset as a runtime operand, so pointer arithmetic is just arithmetic on the
  register header. Which region a register points into is tracked by a small
  abstract interpretation over the basic blocks.
- **A map is a region too**, and `bpf_map_lookup_elem` is the one helper that
  is translated rather than rejected — see "The map model" below.
- **The BPF stack is not a region**: the verifier requires constant offsets
  from `r10`, so each slot becomes its own header. This matters — the checker
  compares the final contents of every declared region, and `-O0` spills where
  `-O2` does not, so modelling the stack as memory would report a difference
  nothing can observe.
- **Control flow is a chain of transformer modules** driven by a program
  counter header, since a transformer runs only the first rule that matches.
  First-match ordering is also what supplies negation: `JNE` compiles to "if
  equal, fall through; otherwise jump".
- **The IR packet is unused.** eBPF reaches its packet through a computed
  pointer, which a P4-style parser cannot express, so the packet is a memory
  region and the parser is a single accepting state that extracts nothing. The
  deparser emits `r0`, which is what makes the return value observable.

### Not supported

Reported on stderr with a non-zero exit status, so a build cannot silently
produce a program that means something else: `CALL` other than
`bpf_map_lookup_elem` and `bpf_map_update_elem`, shifts by a register,
atomics, backward jumps (loops), memory accesses through a register whose
region could not be determined, ctx accesses outside the modelled context
struct, and accesses to an LRU map (see "The map model").

Constant shifts, `BPF_END` (byte swap) and the byte swap implied by
`LD_ABS`/`LD_IND` are all *synthesized* rather than rejected: the IR has no
shift operator, but a shift by a constant is a multiply or divide by a power
of two, so a byte swap is four ops per byte — 8 for a `u16`, 32 for a `u64`.

`ex/basic/ex0.c` uses none of these. `ex/basic/1.c` does, which makes it a useful check
that the diagnostics fire.

### Classic-BPF packet loads

`LD_ABS` reads the packet at a constant offset and `LD_IND` at `src_reg + imm`
— the `load_byte`/`load_half`/`load_word` of socket filters. Three things are
implicit in the instruction rather than encoded, because these lower to a call
into the kernel rather than to a real load:

- the destination is always `r0`, and `r1`–`r5` are clobbered;
- the value arrives converted from network to host byte order;
- **an access past the end of the packet aborts the program, returning 0.**

The first two are emitted. The third is not: an access outside the packet
region yields `ErrorVal` and records an overrun, and an overrun rejects the run
at the sink — a different terminal state from "returns 0", but a conservative
one. Two programs that both run off the packet both reject and still compare
equal; one that runs off and one that does not are reported different, which is
right unless the other also returned 0. So the approximation can raise a false
difference, never hide a real one.

These index the packet region from 0 directly rather than through `ctx->data`,
which is what the instruction means — and it makes the offset concrete where a
`ctx->data`-based one stays symbolic.

### The map model

Each map declared in the object becomes one IR memory region, and how it is
laid out depends on the family, because the two disagree about what a key is.

An **array** map indexes the region *by* the key — there is nothing to look
up, the key is the index:

```
[0, nslots)                              presence bytes, never read
[nslots, nslots + nslots*value_size)     the values, slot i at nslots + i*value_size
```

A **hash** map stores the key *in* the region as a tag, and finds it by
scanning:

```
[0, nslots)                              presence bytes, 1 = the slot is filled
[tag_base,   + nslots*key_size)          the key each slot holds
[value_base, + nslots*value_size)        the values
[full_off]                               1 = the real map is at capacity
```

`bpf_map_lookup_elem(map, key)` on a hash map compiles to: read the key, read
every slot's presence byte and tag into headers, and then choose. The choice
is a branch, so a `CALL` ends its block and a second transformer decides, with
one rule per slot in first-match order and a miss last:

```
[pc, pres_0 == 1, tag_0 == key]  ->  r0 := value_base + 0*value_size
...
[pc, pres_n == 1, tag_n == key]  ->  r0 := value_base + n*value_size
[pc]                             ->  r0 := 0
```

No new IR was needed for this: a match pattern is already a conjunction, and
`match_header` already compares one header against another — it is what a
register-to-register jump uses. An array lookup keeps the old two-arm shape,
where `key < max_entries` decides it exactly.

**The tag is the point.** Deriving the slot from the key — `slot = key %
nslots`, which is what this did until now — forces distinct keys that collide
modulo `nslots` to share one entry, and that *deletes reachable map states*:
once two keys collide, "k1 present, k2 absent" has no representative. A
deleted state is a difference the checker cannot find, so it is a wrong
`Equivalent` rather than a loud failure. With the key stored, which slot it
lands in is a fact about the region rather than about the key, and nothing is
forced together. The value pointer in each arm is also a *literal*, where the
modulus produced a computed one.

`bpf_map_update_elem(map, key, value, flags)` scans the same way, and has
`2*nslots + 2` arms:

| | |
|---|---|
| slot *i* filled, tag is the key | overwrite it — capacity is never consulted, because the kernel reuses an existing element |
| the map is full | `-E2BIG`, writing nothing |
| slot *i* empty | insert: tag, then presence, then the value |
| nothing matched | `-E2BIG` |

First-match makes the insert take the **lowest free slot**, which matters: the
choice has to be a function of the *region*, not of the program, or two
programs inserting the same key could put it in different slots and be
reported different on the final contents.

The value source is usually a stack slot, which is a *header* holding the
whole value at the width it was stored, so it is written out in one store; a
region source of one of the four access widths is one load and one store, and
anything wider is copied a byte at a time. A store takes its value from a
header of the store's own width — a `CrVal` carries its type, and a `u64` one
stored as `u32` is `ErrorVal` — so an insert narrows the key back to the tag's
width, while the comparison uses the widened copy.

The last arm is the model running out of slots, not the kernel running out of
entries, and `-E2BIG` is the safe way to spend it: it invents a behaviour
reality lacks, which is a false difference at worst, where rejecting the run
would *delete* a state reality has — which is how a real difference goes
missing. Real fullness is the separate capacity byte, a free cell rather than
anything derived from the presence bytes, because model fullness and real
fullness are different events: `nslots` is 4 and `max_entries` is 64, 256 or
32768 in every map under `ex/`.

An array write needs none of this — every entry exists from creation — and
stays straight-line.

**The flags are checked, not assumed.** Only `BPF_ANY` is modelled.
`BPF_NOEXIST` and `BPF_EXIST` make the write conditional on what is already in
the slot — a branch this does not emit — so translating them as `BPF_ANY`
would silently model a different program, and they are refused instead. That
check needs the flags to be a *statically known* constant, which is why
`RegInfo` now carries one for scalars written by `MOV imm` and `LD_IMM64`; a
computed flags value is refused too.

Both pieces are ordinary region cells, so both are free symbolic input: a
lookup can hit or miss and the solver explores both, which is what keeps a
program's `if (!v)` arm live rather than pruning it. The region's final
contents and access extent are compared like any other region, so a program
that writes through the value pointer is distinguished from one that does not.

Map sizes are read from the object: from the section data for legacy
`struct bpf_map_def SEC("maps")`, and from `.BTF` for the modern
`struct { __uint(...); __type(...); } SEC(".maps")` style. Region ids are
assigned by sorted map name, because two lowerings of one source declare the
same maps but not necessarily in the same order, and the checker refuses to
compare programs whose declarations differ.

What makes a bounded region enough is that backward jumps are refused: with no
loops a run performs at most one map operation per call site, so it observes
at most that many distinct keys, whatever the key space is.

That turns into a checkable side condition. The two programs in a comparison
are given the *same* region and their keys need not be the same ones, so in
the worst case it has to hold both programs' keys at once — and each
translation only ever sees its own. Halving composes: **a map may be accessed
at `nslots/2` sites**, and if each side is within that the sum is within
`nslots` whatever the other side does. `check_map_budget` refuses the rest,
because a map state neither program can represent is one where a real
difference can hide.

**So each hash map is sized to its own use**: `2 * sites`, worked out by a
throwaway translation pass that exists only to count them (`probe_map_sites`
— which map a call names comes from the abstract state of `r1`, so translating
is the only way to know). A map used once gets 2 slots rather than a blanket
4, which is worth having: `map_ref` against `map_spill` goes from a 53-byte
region and 85ms to 27 bytes and 55ms. `--map-slots=N` forces it, to at most
28, where the per-slot scratch headers run out. Array maps are not sized this
way — there the budget bounds key *values*, not live entries.

The two objects compared must declare the same region, which holds when they
use a map the same number of times; two lowerings of one source do. When they
do not, the checker refuses the pair rather than answering, so this cannot
become a wrong verdict.

An **array** map still indexes by the key, so `check_array_key` has to rule
out what the modulus would alias: a constant key must be below `nslots`, and a
computed one is allowed only when `max_entries <= nslots`. No array map in
`ex/` is accessed with a computed key.

Note also that the model says nothing about *where* a key lives — a lookup is
a function of the map region and the key, and that is all the equivalence
check needs. It is not a model of the kernel's hash table.

**LRU maps are refused.** `BPF_MAP_TYPE_LRU_HASH` and `LRU_PERCPU_HASH` used
to be folded into the hash family, which is wrong in the direction that
matters: a full LRU map does not fail an insert, it *evicts* the
least-recently-used entry, so the write succeeds and some other key — one the
program never named — silently disappears. Nothing here models that
transition, and a transition the model lacks is a difference the checker
cannot find. They now get their own family and are refused at the access.

### Known approximations

Memory is byte-addressed — a region is an array of `u8` cells and a width-*w*
access covers *w* consecutive cells little-endian — so store coalescing across
optimization levels and type punning both work. That is the IR's doing; the
transpiler just emits width-typed `LoadOp`/`StoreOp`.

- **The ctx layout is chosen from the program's section name**: `xdp*` gets
  `struct xdp_md` (20 bytes, packet pointers at offsets 0 and 4), and
  `socket`/`filter`/`tc`/`classifier`/`action`/`cgroup_skb`/`sk_skb`/`lwt_*`
  get `struct __sk_buff` (192 bytes, packet pointers at 76 and 80). An
  unrecognised section is refused rather than guessed. This is the one piece
  of program-type knowledge in the translator; the values loaded are still
  whatever the region holds, and what the program computes from them is
  compared between the two versions, not assumed.

  Getting this wrong is a *silent* failure, which is why a ctx access at a
  known offset outside the layout is now rejected outright. An out-of-bounds
  access is total but records an overrun, an overrun rejects the run at the
  sink, and two rejecting programs are "equivalent" whatever they compute — so
  modelling an `__sk_buff` filter with `xdp_md`'s 20 bytes made every field
  access an overrun and reported two *different* filters equivalent, with the
  translator exiting 0. `ex/suricata/vlan_filter.c` against `ex/suricata/vlan_filter_alt.c` is
  the regression test.
- `PKT_LEN` is fixed. It must match between the two programs being compared,
  so it deliberately does not depend on what a program happens to use.
- A region's cells are free symbolic input, and the IR's `CrVal` cells carry a
  type tag, so a model may give a cell a tag that no real byte has — including
  `ErrorVal`. `CrVal`'s comparisons are false on `ErrorVal` in *both*
  directions, so `x > 100` and `101 > x` are both false there. Two programs
  that compare in opposite directions are therefore reported inequivalent on
  an input no real machine produces. This predates the map work and is
  independent of it (`if (x > 100) return 2; return 0;` against
  `if (x < 101) return 0; return 2;`, reading `x` from `ctx`, reproduces it
  with no map in sight). Closing it means constraining a declared region's
  cells to be well-formed bytes in the checker's query, not in the solver.

## Tests

```bash
make test        # creates .venv on first run (hypothesis, pytest)
```

Five layers, because they catch different things.

- **`make test`** — unit tests over the pieces with no natural coverage in the
  example programs. `emit_bswap` and `emit_arsh_const` are *synthesized* out
  of multiply/divide/and/or, so `tests/opeval.py` runs the ops they emit and
  compares against Python's own arithmetic; comparing emitted strings would
  pin the current output without saying anything about its meaning. Also the
  provenance lattice (`join_reg`) and the section-name → context mapping,
  including the program types that must be *refused* rather than guessed.
- **`ex/basic/opcodes.c`** — a fixture, not a program: it exists to make clang
  emit every instruction form the translator synthesizes, since the real
  programs in `ex/` between them exercise about half. Built at `-Os -mcpu=v3`,
  because `-O2` turns its switch into a jump table (a backward jump) and `v3`
  is what produces the 32-bit compare class.
- **`tests/mkobj.py`** — builds a minimal BPF object from hand-written
  instructions, for the forms clang will not emit at all: it canonicalises
  `JSLE` into `JSGT` with swapped arms, turns division by a constant into a
  multiply-high, and never produces `JSET` from ordinary C. Those go through
  `emit_condition`'s swap logic, which is exactly where a wrong entry would be
  invisible.

- **Property tests** (`tests/test_lowering.py`) — Hypothesis generates a random
  BPF program, and the property is *semantic*: running the lowered IR must
  return what running the bytecode returns. That needs two independent
  interpreters — `tests/bpfvm.py` for the ISA, written from the ISA, and for
  the IR **the extracted evaluator itself**. It exercises on every example the
  tier with no other oracle: the 32-bit narrow/widen dance, the synthesized
  shifts and byte swaps, `emit_condition`'s arm swapping, block splitting, and
  the program-counter threading.

  The IR side is not a reimplementation. `run_net --serve` (in `../..`)
  runs a network program concretely and prints what it did — the emitted
  packet, then every region's final contents and access extent — and
  `tests/irrunner.py` drives it as a co-process, spawned once and kept alive
  because the spawn costs far more than the run. So the oracle is the same evaluator the Coq development is
  about and the same one the IR's own expect tests exercise, rather than a
  second model of the semantics that could be wrong in the same places the
  translator is.

  This needs `dune build --profile release` to have been run in `../..`.

  Two things about the generator are deliberate and worth keeping. It draws
  immediates from a small pool and emits explicit *tie* comparisons, because
  with random 32-bit immediates two compared values are essentially never
  equal — and the "or equal" jump forms differ from their strict counterparts
  only at equality. And it ends with an epilogue folding every register's high
  half into `r0`, because only `r0`'s low 32 bits are emitted and
  add/sub/xor/mul propagate low bits from low bits, so a difference confined
  to a register's high half — exactly what a wrong 32-bit zero-extension
  produces — would otherwise never reach the output. Both were added after
  mutation testing showed the suite blind to those cases.

- **Bytecode mutation** (`tests/mutate.py`, `tests/make_mutation_fixtures.py`)
  — single in-place instruction edits to a real program, turned into
  equivalence-test pairs in `<ir>`'s suite. The expectation for each pair is
  established *independently of the checker*: a NotEquivalent pair comes with
  a concrete input on which the two lowered programs demonstrably behave
  differently, replayed through the extracted evaluator. A separating input
  is a **proof** of
  inequivalence, so `Equivalent` there would be a soundness bug rather than a
  surprising verdict.

  Note the asymmetry, which is the opposite of the usual metamorphic-testing
  intuition. "This rewrite preserves semantics, so expect Equivalent" is the
  *weak* direction here, because the both-rejected disjunct makes Equivalent
  cheap and because random inputs rarely reach the interesting states —
  `vlan_filter` needs `vlan_tci & 0xfff` in {2,4}, about one in 2048, which 400
  random seeds never hit. For those, the separating input is taken from the
  checker's own counterexample and *replayed* concretely, which checks the
  counterexample is genuine.

  Three drivers, run per object (each takes a couple of minutes, so pass one
  or two objects at a time rather than the whole tree):

  | | |
  |---|---|
  | `tests/witness_check.py` | replays every NotEquivalent counterexample and confirms it really separates the two programs |
  | `tests/equiv_check.py` | tries to *refute* every Equivalent verdict by searching for a separating input |
  | `tests/mutation_sweep.py` | both directions at once, reporting disagreements |

  Only the first is sound. Failing to refute an Equivalent verdict after N
  random inputs is evidence, not proof, and `equiv_check.py` says so in its
  own output.

  There is no catalogue of semantics-preserving BPF rewrites to borrow, and it
  is worth knowing why: [K2](https://github.com/smartnic/superopt), the eBPF
  superoptimizer, is built the same way round. Its proposal distribution
  (`src/search/proposals.cc`) is deliberately blind — replace an operand,
  replace an instruction, replace k contiguous instructions, NOP one out — and
  the SMT equivalence checker is the filter that decides which proposals were
  valid. Labels come from an oracle, not from the mutation.

The end-to-end checks in `<ir>`'s `dune runtest` are the fourth layer, and the
one that catches modelling errors rather than coding ones.

### What the property tests do not cover

Generation is arithmetic and control flow only: no memory operations, so
pointer provenance never influences the output. That tier is covered directly
instead, by `TestProvenance` in `tests/test_synth.py` — a load through a
32-bit-truncated pointer must be *refused*, since a 32-bit MOV cannot preserve
a pointer and guessing a region would silently read the wrong memory.

Extending generation to memory would mean restricting it to accesses the model
agrees on: a stack slot is a header holding the value at the width it was
stored, so a `u32` spill read back as a `u64` is `ErrorVal` in the IR and a
real value in BPF.

## Clean

```bash
make clean
```
