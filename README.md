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
`O2.ir` — the `-O0` and `-O2` lowerings of `ex/ex0.c`, which is the same source
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

Regenerate those fixtures after changing `bpf_to_ir`:

```bash
make O0.ir O2.ir
cp O0.ir ~/proj/ir/test/bpf_O0.ir && cp O2.ir ~/proj/ir/test/bpf_O2.ir
```

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
- **Memory is two declared regions**, `ctx` (1) and `pkt` (2). A load or store
  names its region statically and takes the offset as a runtime operand, so
  pointer arithmetic is just arithmetic on the register header. Which region a
  register points into is tracked by a small abstract interpretation over the
  basic blocks.
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
produce a program that means something else: `CALL`, shifts by a register
(constant shifts become multiply/divide by a power of two), `BPF_END`,
atomics, backward jumps (loops), and memory accesses through a register whose
region could not be determined.

`ex/ex0.c` uses none of these. `ex/1.c` does, which makes it a useful check
that the diagnostics fire.

### Known approximations

- Memory is word-addressed: a store of width *w* occupies the single cell at
  its base address, and a load of a different width there reads `ErrorVal`.
  Exact for code that accesses an address at a consistent width, which
  compiled C does.
- `ctx` offsets 0 and 4 are treated as `struct xdp_md`'s `data` and
  `data_end`, i.e. as packet pointers. This is the one piece of program-type
  knowledge in the translator. The values themselves are still whatever the
  region holds — what the program computes from them is compared between the
  two versions, not assumed.
- Region lengths are fixed (`CTX_LEN`, `PKT_LEN` in `bpf_to_ir.c`). They must
  match between the two programs being compared, so they deliberately do not
  depend on what a program happens to use.

## Clean

```bash
make clean
```
