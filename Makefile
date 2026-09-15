# Only the .c sources are checked in.  Everything `make` produces here --
# objects, disassembly, and the IR s-expressions -- is generated and
# gitignored, so a clone plus a toolchain reproduces all of it.
#
# The BPF backend is not in the stock macOS toolchain, so put a real LLVM on
# PATH before building:
#
#     source ~/llvm-project/set_env
#
# or point CLANG and LLC at one:
#
#     make CLANG=/opt/homebrew/opt/llvm/bin/clang LLC=/opt/homebrew/opt/llvm/bin/llc
#
# A STOCK LLVM is enough.  There used to be an `%.ast` rule running
# `-Xclang -ast-dump`, which needed a locally patched clang; nothing ever
# consumed the output, so it is gone and so is that dependency.
#
# (`llc -march=bpf` was the old spelling and newer LLVM rejects it; the rules
# below use `-mtriple=bpf`.)
.DELETE_ON_ERROR:

CLANG ?= clang
LLC   ?= llc

INC := -I./ex

# ---------------------------------------------------------------------------
# What gets built from what.

EX_SRC := $(shell find ex -name '*.c' | sort)
EX_HDR := $(shell find ex -name '*.h')

# A source holds a BPF program iff it declares a section.  Two kinds of source
# do not, and one does but must not be translated:
#
#   ex/*/offsets.c      compile-time assertions that the shim headers
#                       reproduce the kernel's struct layout -- a negative
#                       array size, so a wrong offset breaks `make`.  There is
#                       no executable section to lower.  Compiled, not
#                       translated.
#   ex/basic/[01abcd].c scratch, no SEC() and so no known program type.
#                       Excluded by the grep below, not by name.
#   ex/basic/opcodes.c  a codegen fixture: it exists to make clang emit every
#                       instruction form the translator synthesizes, and its
#                       switch is a BACKWARD JUMP, which the translator
#                       refuses.  Its own rule and its own flags, below.
NO_IR    := $(wildcard ex/*/offsets.c) ex/basic/opcodes.c
# A bare `(` inside $(shell ...) breaks make's paren matching, hence LPAREN.
LPAREN   := (
SEC_SRC  := $(shell grep -l 'SEC$(LPAREN)' $(EX_SRC) 2>/dev/null)
IR_SRC   := $(filter-out $(NO_IR),$(SEC_SRC))
PLAIN_SRC := $(filter-out $(SEC_SRC),$(EX_SRC))

# Each translatable source is built at TWO optimization levels and translated
# at both, so `make` alone produces the pairs the equivalence checker is for:
# one program against the same program after LLVM has optimized it.
#
# -O0 is deliberately not in this list.  The eBPF-SE and Suricata shims
# declare each helper as a function POINTER initialized to its helper number,
# and only -O1 and up fold that to an immediate; at -O0 clang emits an
# indirect `call rN`, which bpf_to_ir does not model, and every map access
# downstream then loses its provenance.  The one -O0 object that does
# translate is the REF pair below, whose source calls no helper.
OPTS := O1 O2

# ... with ONE exception.  ex/basic/ex0.c calls no helper, so it is the one
# source that also translates at -O0, and -O0 against -O2 is a far wider
# optimization gap than O1 against O2: proving that pair equivalent is the
# headline of the whole exercise, and <ir>/test/bpf_O{0,2}.ir are copies of it.
#
#     <ir>/_build/default/extracted_code/EqCheck.exe --net \
#         ex/basic/ex0.O0.ir ex/basic/ex0.O2.ir
REF     := ex/basic/ex0.c
REF_OBJ := $(patsubst %.c,%.O0.o,$(REF))

EX_OBJ  := $(foreach o,$(OPTS),$(patsubst %.c,%.$(o).o,$(IR_SRC))) $(REF_OBJ)
EX_IR   := $(EX_OBJ:.o=.ir)
# Compiled for the diagnostic, never translated.
CHECK_OBJ := $(patsubst %.c,%.O2.o,$(PLAIN_SRC)) ex/basic/opcodes.o

all: $(CHECK_OBJ) $(EX_OBJ) $(EX_IR)

# ---------------------------------------------------------------------------
# Rules.

BPF_TO_IR := ./bpf_to_ir
BPF_DUMP  := ./bpf_dump
PYSRC     := $(wildcard pybpf/*.py)

# The shim headers are prerequisites of every example object.  Without this a
# fix to one of them rebuilds nothing, and the objects keep whatever the old
# header said -- which is how a wrong BPF_MAP_TYPE_* constant survived a
# `make` after being corrected.  Coarse (every object depends on every header)
# but there are only a handful.
$(EX_OBJ) $(CHECK_OBJ): $(EX_HDR)

# -g to get kv sizes of `struct { __uint(...); } SEC(".maps")`.
define compile_at
%.$(1).o: %.c
	$$(CLANG) -target bpf -$(1) -g $$(INC) -emit-llvm -c $$< -o $$@.bc
	$$(LLC) -mtriple=bpf -mcpu=probe -filetype=obj -o $$@ $$@.bc
	@rm -f $$@.bc
endef
$(foreach o,O0 $(OPTS),$(eval $(call compile_at,$(o))))

# cpu v3 is what produces the 32-bit compare class (BPF_JMP32); -Os keeps the
# switch an if-chain, where -O2 makes it a jump table.
ex/basic/opcodes.o: ex/basic/opcodes.c
	$(CLANG) -target bpf -Os -g $(INC) -emit-llvm -c $< -o $@.bc
	$(LLC) -mtriple=bpf -mcpu=v3 -filetype=obj -o $@ $@.bc
	@rm -f $@.bc

# The .O0 / .O1 / .O2 infix is part of the stem, so one rule covers them all.
%.dump: %.o $(BPF_DUMP) $(PYSRC)
	$(BPF_DUMP) $< > $@

%.ir: %.o $(BPF_TO_IR) $(PYSRC)
	$(BPF_TO_IR) $(IRFLAGS) $< > $@

# katran's adapter_integration_test_kern.c is a tc program; its section name
# does not say which context struct it takes, so it has to be told.
$(foreach o,$(OPTS),ex/ebpf-se/cls_pktcntr.$(o).ir ex/ebpf-se/cls_pktcntr_alt.$(o).ir): \
	IRFLAGS := --ctx=__sk_buff

.PHONY: all clean test venv objs ir

objs: $(CHECK_OBJ) $(EX_OBJ)
ir:   $(EX_IR)

VENV   := .venv
PYTEST := $(VENV)/bin/pytest

# The tools need nothing but the standard library; the property tests need
# hypothesis, so they get a venv.
$(VENV):
	python3 -m venv $(VENV)
	$(VENV)/bin/pip install --quiet --upgrade pip
	$(VENV)/bin/pip install --quiet -r requirements-dev.txt

venv: $(VENV)

# Unit tests for the pieces with no natural coverage in the example programs
# (the synthesized operators, the provenance lattice), and property tests that
# run a generated program through both a BPF interpreter and the lowered IR
# and compare.  See README.md, "Tests".
test: $(VENV)
	$(PYTEST) tests -q

clean:
	rm -f $(EX_OBJ) $(EX_IR) $(CHECK_OBJ)
	# Nothing produces .ast any more; sweep any left by an older checkout.
	find . -name '*.ast' -delete
	rm -f ex/*/*.o ex/*/*.ir ex/*/*.dump ex/*/*.o.bc
	rm -rf .hypothesis
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
