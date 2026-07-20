# The BPF backend is not in the stock macOS toolchain.  Put a real LLVM on
# PATH before building the examples:
#
#     source ~/llvm-project/set_env
#
# (`llc -march=bpf` was the old spelling and newer LLVM rejects it; the rules
# below use `-mtriple=bpf`.)
CLANG ?= clang
LLC   ?= llc

EXC := $(shell find ./ex/ -name '*.c')
EXO := $(patsubst ./ex/%.c,./ex/%.o,$(EXC))
EXA := $(patsubst ./ex/%.c,./ex/%.ast,$(EXC))

INC := -I./ex

# O0.o / O2.o are the -O0 and -O2 lowerings of one source; the point of the
# whole exercise is proving them equivalent.  O0.ir / O2.ir are their
# translations into the Caracara IR, checked with
#
#     <ir>/_build/default/extracted_code/EqCheck.exe --net O0.ir O2.ir
REF := ex/ex0.c

all: $(EXO) $(EXA) bpf_dump bpf_to_ir O0.ir O2.ir

bpf_dump: src/bpf_dump.c src/bpf_decode.c include/elf.h include/bpf.h
	gcc -o $@ src/bpf_dump.c src/bpf_decode.c -Iinclude -Wall -Wextra

bpf_to_ir: src/bpf_to_ir.c include/elf.h include/bpf.h
	gcc -o $@ src/bpf_to_ir.c -Iinclude -Wall -Wextra

O0.o: $(REF)
	$(CLANG) -target bpf -O0 $(INC) -emit-llvm -c $< -o - | \
	  $(LLC) -mtriple=bpf -mcpu=probe -filetype=obj -o $@

O2.o: $(REF)
	$(CLANG) -target bpf -O2 $(INC) -emit-llvm -c $< -o - | \
	  $(LLC) -mtriple=bpf -mcpu=probe -filetype=obj -o $@

%.dump: %.o bpf_dump
	./bpf_dump $< > $@

%.ir: %.o bpf_to_ir
	./bpf_to_ir $< > $@

%.o: %.c
	$(CLANG) -target bpf -O2 $(INC) -emit-llvm -c $< -o - | \
	  $(LLC) -mtriple=bpf -mcpu=probe -filetype=obj -o $@

%.ast: %.c
	$(CLANG) -target bpf $(INC) -Wall -O2 -Xclang -ast-dump -c $< > $@

.PHONY: clean

clean:
	rm -rf ex/*.o ex/*.ast bpf_dump bpf_to_ir
