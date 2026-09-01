# ect — eBPF → Caracara IR

Tools for getting compiled eBPF bytecode into the Caracara IR (`~/proj/ir`) so
that two lowerings of one program can be proved equivalent.

- `bpf_to_ir` — translate an object into a `GeneralCaracaraProgram`
  s-expression for the unified IR.
- `bpf_dump` — decode and print the BPF instructions in an ELF object.

## Building

The BPF backend is not in the stock macOS toolchain, so put a real LLVM on
`PATH` first:

```bash
source ~/llvm-project/set_env
make
```

`make` builds the example objects and ASTs, both tools, and `O0.ir` /
`O2.ir` — the `-O0` and `-O2` lowerings of `ex/basic/ex0.c`, which is the same source
as `<ir>/test/bpf_ref.c`.

(`llc -march=bpf` was the old spelling and current LLVM rejects it; the
Makefile uses `-mtriple=bpf`.)

## The end-to-end check

```bash
source ~/llvm-project/set_env
make O0.ir O2.ir
cd ~/proj/ir && dune build --profile release
./_build/default/extracted_code/EqCheck.exe --net ~/proj/ect/O0.ir ~/proj/ect/O2.ir
# Equivalent
```

`EqCheck --net` runs `modnet_equivalence_checker`, which compares the emitted
return value, the number of input bits read, and the final contents and access
extents of every declared memory region. The same pair is checked in the IR's
test suite (`TestEquality`, "e2e bpf test: O0 ≡ O2, unified IR") against the
checked-in copies at `<ir>/test/bpf_O{0,2}.ir`, alongside concrete runs of both
programs in `TestModuleSemantics` — the checker on its own would also be
satisfied by two programs that are equally broken.

The map programs in `ex/map/` are checked the same way, as three pairs against
`map_ref` -- one Equivalent and two NotEquivalent, since a verdict in only one
direction says nothing.  So are the two Suricata filters in `ex/suricata/`,
which are production sources carried verbatim.

Regenerate those fixtures after changing `bpf_to_ir`:

```bash
make
cp O0.ir ~/proj/ir/test/bpf_O0.ir && cp O2.ir ~/proj/ir/test/bpf_O2.ir
for f in map_ref map_spill map_miss_differs map_hit_differs; do
  ./bpf_to_ir ex/map/$f.o > ~/proj/ir/test/bpf_$f.ir
done
for f in vlan_filter vlan_filter_alt pkt_load; do
  ./bpf_to_ir ex/suricata/$f.o > ~/proj/ir/test/bpf_$f.ir
done
# filter.c keeps its upstream name in ex/ but is bpf_sur_filter.ir in the IR
./bpf_to_ir ex/suricata/filter.o     > ~/proj/ir/test/bpf_sur_filter.ir
./bpf_to_ir ex/suricata/filter_alt.o > ~/proj/ir/test/bpf_sur_filter_alt.ir
```

`ex/suricata/offsets.c` is not a program: it static-asserts every field offset
the programs in that directory read, so a wrong one in `sur_common.h` breaks
`make` instead of silently modelling a different field.

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

The long version is the header comment of `src/bpf_to_ir.c`. In brief:

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
  and now costs one. `O0.ir` went from 62 kB to 5 kB.)
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
`bpf_map_lookup_elem`, shifts by a register, atomics, backward jumps (loops),
memory accesses through a register whose region could not be determined, and
ctx accesses outside the modelled context struct.

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

Each map declared in the object becomes one IR memory region, laid out as

```
[0, nslots)                              presence bytes, 1 = the slot is filled
[nslots, nslots + nslots*value_size)     the values, slot i at nslots + i*value_size
```

and `bpf_map_lookup_elem(map, key)` compiles to: read the key, take
`slot = key % nslots`, read the slot's presence byte, and set `r0` to the
slot's value pointer if that byte is 1 and to 0 otherwise. The choice is a
branch, so a `CALL` ends its block and reuses the same two-transformer shape a
conditional jump uses.

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

The one real abstraction is `nslots = min(max_entries, MAP_MAX_SLOTS)` with
`MAP_MAX_SLOTS = 4`: a full-sized map would need `max_entries * value_size`
region cells, and the solver pins every cell of a free region with a side
constraint, so a 1024-entry map would cost thousands of them. Distinct keys
that fall in the same slot are therefore conflated. Both programs use the same
modulus and compute the key the same way, so this is harmless for comparing
two lowerings of one source; it would not be sound for comparing two programs
that derive their keys differently.

Note also that the model says nothing about which key a slot holds — a lookup
is a function of the map region and the key, and that is all the equivalence
check needs. It is not a model of the kernel's hash table.

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

## Clean

```bash
make clean
```
