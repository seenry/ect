/*
 * bpf_to_ir.c
 *
 * Translates BPF bytecode from a .o ELF file into a Caracara
 * GeneralCaracaraProgram s-expression, readable by
 * ~/proj/ir/extracted_code/EqCheck.exe --net.
 *
 * This replaces bpf_to_crmem.c, which targeted the standalone memory IR
 * (CrMem).  The unified IR has typed u8/u16/u32/u64 operations and real
 * load/store ops against declared memory regions, which changes the shape of
 * the translation completely:
 *
 *   - A BPF register is ONE u64 header, not eight u8 bytes with a hand-rolled
 *     ripple-carry chain.  A 64-bit add is one StatelessOp instead of ~24
 *     instructions.
 *   - A memory access names its region statically and takes the offset as a
 *     runtime operand, so pointer arithmetic is ordinary arithmetic on the
 *     register header; there is no pointer value and no static-offset
 *     bookkeeping to keep the two compiled versions naming the same cell.
 *   - Control flow is a chain of transformer modules driven by an explicit
 *     program-counter header (see "Control flow" below), rather than nested
 *     BrzOp.
 *
 * ── Program shape ────────────────────────────────────────────────────
 *
 *   parser (module 1)  ->  T_0  ->  T_1  ->  ...  ->  deparser (module 2)
 *
 * The IR packet is not used: eBPF reaches its packet through a pointer, at
 * offsets it computes, which a P4-style parser cannot express.  So the parser
 * is a single accepting state that extracts nothing and the declared input
 * length is 0; the packet is modelled as a memory region instead.  A parser
 * source and a deparser sink are still required by
 * CrModule.wf_module_network, and the deparser is what makes the return value
 * observable: it emits r0, the BPF return value, as 32 bits.
 *
 * ── Memory model ─────────────────────────────────────────────────────
 *
 * Declared regions:
 *   region 1  "ctx"  — the struct the program is called with.  WHICH struct,
 *                      and so how long the region is, comes from the program's
 *                      section name; see [ctx_layout_for].
 *   region 2  "pkt"  — the packet, reached through ctx->data / ctx->data_end.
 *   region 10+       — one per BPF map, ordered by map name.
 *
 * The first two are declared unconditionally and with fixed lengths, because
 * SmtModuleQuery.modnet_equivalence_checker refuses to compare two programs
 * that do not declare identical regions.  Map regions are discovered from the
 * object and named by sorted map name for the same reason: two lowerings of
 * one source declare the same maps, but not necessarily in the same order.
 *
 * The BPF stack is NOT a region.  The verifier requires every stack access to
 * use a compile-time-constant offset from r10, so each distinct slot becomes
 * its own header.  That is not just cheaper, it is necessary: the stack is
 * private scratch, but the checker compares the final contents of every
 * declared region, so modelling it as memory would report -O0 (which spills)
 * and -O2 (which does not) as inequivalent on a difference nothing can
 * observe.
 *
 * Memory is byte-addressed: a region is an array of u8 cells and a width-w
 * access covers w consecutive cells, little-endian, which the IR's
 * LoadOp/StoreOp do for us.  So a u16 store really is the two u8 stores -O2
 * coalesces it from, and type punning reads back what was written.
 *
 * ── Control flow ─────────────────────────────────────────────────────
 *
 * A transformer runs the FIRST rule whose match pattern holds, and only that
 * rule, so one transformer is one if/elif/else -- not a basic block sequence.
 * Sequencing comes from the module chain instead.
 *
 * The BPF program is split into basic blocks and each block becomes one
 * transformer guarded on a program-counter header:
 *
 *   T_b:  [pc == id_b]  ->  <block b's ops> ; pc := <successor>
 *         []            ->  (no-op default)
 *
 * A block ending in a conditional jump needs a second transformer, because a
 * match pattern is evaluated against the state on entry to the transformer
 * and the branch condition is computed by the block itself:
 *
 *   T_b:      [pc == id_b]                -> <ops> ; pc := dec_b
 *   T_b_dec:  [pc == dec_b, <condition>]  -> pc := <taken>
 *             [pc == dec_b]               -> pc := <fallthrough>
 *
 * First-match ordering is also what supplies negation, which a match pattern
 * (a conjunction of positive comparisons) otherwise has no way to express: a
 * JNE is compiled as "if equal go to the fallthrough, otherwise take the
 * jump".  The same trick covers JGE (as not-less-than) and JLE.
 *
 * Blocks are emitted in instruction order, which is a topological order iff
 * every jump goes forward.  Backward jumps (loops) are rejected.
 *
 * A CALL ends its block for the same reason a conditional jump does: a map
 * lookup chooses between a value pointer and NULL, and that choice is a match
 * pattern, which is only read on entry to a transformer.
 *
 * ── Not supported ────────────────────────────────────────────────────
 *
 * Reported on stderr, and the exit status is non-zero so a build does not
 * silently produce a program that means something else:
 *   - CALL, except bpf_map_lookup_elem (see "Maps" above)
 *   - shifts by a register operand (the IR has no shift operator; shifts by a
 *     constant become multiply/divide by a power of two, and so do the byte
 *     swaps in [emit_bswap])
 *   - atomics
 *   - backward jumps
 *   - memory accesses through a register whose region could not be determined
 *   - a ctx access outside the modelled struct (see [ctx_access_ok])
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include "elf.h"
#include "bpf.h"

/* Wide immediate load (BPF_LD | BPF_IMM | BPF_DW), a two-slot instruction. */
#define BPF_LD_IMM64 0x18

/* ── Identifier allocation ──────────────────────────────────────────── */

#define H_PC            1               /* program counter                  */
#define H_REG(n)        (10 + (n))      /* r0..r10  -> 10..20               */
#define H_TMP(k)        (30 + (k))      /* scratch, reused per instruction  */
#define H_STACK_BASE    100             /* one header per touched slot      */
#define NUM_TMPS        8

#define REGION_CTX      1
#define REGION_PKT      2
#define REGION_MAP(i)   (10 + (i))      /* one region per declared BPF map  */
#define REGION_NONE     99              /* undeclared: loads read ErrorVal  */

/* Bytes of packet modelled.  It has to reach past the headers a filter
   actually parses, or the reads past it overrun, the run rejects, and the
   tail of the program is silently dead -- suricata's filter.c reads the IPv4
   daddr at packet offset 30..33, so 32 made half of it unreachable.  64
   covers ethernet + IPv4 + the start of a TCP header. */
#define PKT_LEN         64

#define MAX_MAPS        16
#define MAP_MAX_SLOTS   4               /* slots modelled per map           */

/* The only helper that is translated rather than rejected. */
#define BPF_FUNC_map_lookup_elem  1

#define MOD_PARSER      1
#define MOD_DEPARSER    2
#define MOD_FIRST_XFRM  10

#define PC_HALT         0               /* no block guards on 0             */
#define BLOCK_PC(leader)  (2 * (leader) + 1)
#define DECIDE_PC(leader) (2 * (leader) + 2)

#define NUM_BPF_REGS    11
#define BPF_STACK_SIZE  512
#define MAX_INSNS       8192

static int had_error = 0;

static void unsupported(size_t idx, const char *fmt, ...) {
    va_list ap;
    fprintf(stderr, "bpf_to_ir: insn %zu: unsupported: ", idx);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
    had_error = 1;
}

/* ── Instruction predicates ─────────────────────────────────────────── */

static int is_jmp_class(uint8_t code) {
    return BPF_CLASS(code) == BPF_JMP || BPF_CLASS(code) == BPF_JMP32;
}

/* Which registers the program mentions at all.  Used to decide what the
   preamble initialises: seeding a register nothing touches would only add a
   header for every transformer's merge to carry. */
static int reg_used[NUM_BPF_REGS];

static void mark_reg(int r) { if (r >= 0 && r < NUM_BPF_REGS) reg_used[r] = 1; }

static void scan_used_regs(struct bpf_insn *insns, size_t n) {
    memset(reg_used, 0, sizeof(reg_used));
    for (size_t i = 0; i < n; i++) {
        uint8_t cls = BPF_CLASS(insns[i].code);
        if (insns[i].code == BPF_LD_IMM64) { mark_reg(insns[i].dst_reg); i++; continue; }
        switch (cls) {
        case BPF_ALU64: case BPF_ALU:
            mark_reg(insns[i].dst_reg);
            if (BPF_SRC(insns[i].code) == BPF_X) mark_reg(insns[i].src_reg);
            break;
        case BPF_LDX: case BPF_STX:
            mark_reg(insns[i].dst_reg); mark_reg(insns[i].src_reg); break;
        case BPF_ST:
            mark_reg(insns[i].dst_reg); break;
        case BPF_LD:
            /* LD_ABS/LD_IND always write r0 (which the encoding's dst_reg
               already says) and LD_IND reads src_reg as the offset. */
            mark_reg(insns[i].dst_reg);
            if (BPF_MODE(insns[i].code) == BPF_IND) mark_reg(insns[i].src_reg);
            break;
        default:
            if (is_jmp_class(insns[i].code)) {
                uint8_t op = BPF_OP(insns[i].code);
                if (op == BPF_EXIT) mark_reg(0);          /* EXIT reads r0 */
                else if (op == BPF_CALL) {
                    mark_reg(0); mark_reg(1); mark_reg(2);
                } else if (op != BPF_JA) {
                    mark_reg(insns[i].dst_reg);
                    if (BPF_SRC(insns[i].code) == BPF_X) mark_reg(insns[i].src_reg);
                }
            }
            break;
        }
    }
    /* r1 carries the context pointer whether or not it is mentioned. */
    mark_reg(1);
}

/* A jump to the immediately following instruction: no control flow at all. */
static int is_nop_jump(struct bpf_insn *in) {
    return is_jmp_class(in->code) && BPF_OP(in->code) == BPF_JA && in->off == 0;
}

/* ── Tiny string helpers ────────────────────────────────────────────── */

static char *xsprintf(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0) { perror("vsnprintf"); exit(1); }
    char *s = malloc((size_t)n + 1);
    if (!s) { perror("malloc"); exit(1); }
    va_start(ap, fmt);
    vsnprintf(s, (size_t)n + 1, fmt, ap);
    va_end(ap);
    return s;
}

typedef struct { char **v; int n, cap; } StrVec;

static void sv_init(StrVec *sv) { sv->v = NULL; sv->n = 0; sv->cap = 0; }

static void sv_push(StrVec *sv, char *s) {
    if (sv->n == sv->cap) {
        sv->cap = sv->cap ? sv->cap * 2 : 8;
        sv->v = realloc(sv->v, (size_t)sv->cap * sizeof(char *));
        if (!sv->v) { perror("realloc"); exit(1); }
    }
    sv->v[sv->n++] = s;
}

static void sv_free(StrVec *sv) {
    for (int i = 0; i < sv->n; i++) free(sv->v[i]);
    free(sv->v);
    sv_init(sv);
}

/* Render a StrVec as a Coq list and consume it. */
static char *sv_to_coq_list(StrVec *sv) {
    size_t len = strlen("Coq_nil") + 1;
    for (int i = 0; i < sv->n; i++)
        len += strlen(sv->v[i]) + strlen("(Coq_cons  )") + 2;
    char *out = malloc(len);
    if (!out) { perror("malloc"); exit(1); }
    size_t pos = 0;
    for (int i = 0; i < sv->n; i++)
        pos += (size_t)snprintf(out + pos, len - pos, "(Coq_cons %s ", sv->v[i]);
    pos += (size_t)snprintf(out + pos, len - pos, "Coq_nil");
    for (int i = 0; i < sv->n; i++)
        pos += (size_t)snprintf(out + pos, len - pos, ")");
    sv_free(sv);
    return out;
}

/* ── Maps ───────────────────────────────────────────────────────────── */

/*
 * A BPF map becomes one declared IR memory region.  Its layout is
 *
 *   [0, nslots)                        presence bytes, 1 = the slot is filled
 *   [nslots, nslots + nslots*value_size)   the values, slot i at
 *                                          nslots + i*value_size
 *
 * and `bpf_map_lookup_elem` reads the presence byte to decide between
 * returning the value pointer and returning NULL.  Both pieces are ordinary
 * region cells, so they are free symbolic input: a lookup can hit or miss and
 * the solver explores both, which is what keeps a program's `if (!v)` arm
 * live.
 *
 * `nslots` is min(max_entries, MAP_MAX_SLOTS) and the slot is `key % nslots`.
 * That is the model's one real abstraction -- see README.md, "What the map
 * model does and does not say".
 */
typedef struct {
    char     name[64];
    uint32_t type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    int      nslots;
    int      len;          /* region length in bytes */
} MapInfo;

static MapInfo map_tbl[MAX_MAPS];
static int     nmaps;

static int map_region(int m)     { return REGION_MAP(m); }
static int map_value_base(int m) { return map_tbl[m].nslots; }

static int find_map(const char *name) {
    for (int i = 0; i < nmaps; i++)
        if (strcmp(map_tbl[i].name, name) == 0) return i;
    return -1;
}

static void add_map(const char *name, uint32_t type, uint32_t ks, uint32_t vs,
                    uint32_t me) {
    if (find_map(name) >= 0) return;
    if (nmaps >= MAX_MAPS) {
        fprintf(stderr, "bpf_to_ir: more than %d maps\n", MAX_MAPS);
        had_error = 1;
        return;
    }
    MapInfo *m = &map_tbl[nmaps++];
    snprintf(m->name, sizeof(m->name), "%s", name);
    m->type = type;
    m->key_size = ks;
    m->value_size = vs;
    m->max_entries = me;
    m->nslots = (me == 0 || me > MAP_MAX_SLOTS) ? MAP_MAX_SLOTS : (int)me;
    m->len = m->nslots * (1 + (int)vs);
}

/* Region ids have to agree between the two objects being compared, and
   section and symbol order do not.  Names do. */
static int map_name_cmp(const void *a, const void *b) {
    return strcmp(((const MapInfo *)a)->name, ((const MapInfo *)b)->name);
}

/* ── BTF ────────────────────────────────────────────────────────────── */

/*
 * Modern maps carry their sizes only in BTF: the `.maps` section itself is a
 * block of zeroed pointers.  Enough of BTF is parsed here to answer "how big
 * is the key, how big is the value, how many entries" for each member of the
 * `.maps` data section.
 */
#define BTF_MAGIC 0xeB9F

struct btf_header {
    uint16_t magic;
    uint8_t  version;
    uint8_t  flags;
    uint32_t hdr_len;
    uint32_t type_off, type_len;
    uint32_t str_off,  str_len;
};

struct btf_type {
    uint32_t name_off;
    uint32_t info;      /* vlen:16, unused:8, kind:5, unused:2, kind_flag:1 */
    uint32_t size;      /* or `type`, depending on the kind */
};

#define BTF_KIND(info) (((info) >> 24) & 0x1f)
#define BTF_VLEN(info) ((info) & 0xffff)

enum {
    BTF_KIND_INT = 1, BTF_KIND_PTR, BTF_KIND_ARRAY, BTF_KIND_STRUCT,
    BTF_KIND_UNION, BTF_KIND_ENUM, BTF_KIND_FWD, BTF_KIND_TYPEDEF,
    BTF_KIND_VOLATILE, BTF_KIND_CONST, BTF_KIND_RESTRICT, BTF_KIND_FUNC,
    BTF_KIND_FUNC_PROTO, BTF_KIND_VAR, BTF_KIND_DATASEC, BTF_KIND_FLOAT,
    BTF_KIND_DECL_TAG, BTF_KIND_TYPE_TAG, BTF_KIND_ENUM64
};

struct btf_member    { uint32_t name_off, type, offset; };
struct btf_array     { uint32_t type, index_type, nelems; };
struct btf_var_sec   { uint32_t type, offset, size; };

#define MAX_BTF_TYPES 65536

static const struct btf_type *btf_types[MAX_BTF_TYPES];
static uint32_t btf_ntypes;
static const char *btf_strs;
static uint32_t btf_strs_len;

static const char *btf_name(uint32_t off) {
    return (btf_strs && off < btf_strs_len) ? btf_strs + off : "";
}

static const struct btf_type *btf_get(uint32_t id) {
    return (id > 0 && id < btf_ntypes) ? btf_types[id] : NULL;
}

/* Bytes of kind-specific data following the 12-byte header. */
static size_t btf_extra(const struct btf_type *t) {
    uint32_t vlen = BTF_VLEN(t->info);
    switch (BTF_KIND(t->info)) {
    case BTF_KIND_INT:        return 4;
    case BTF_KIND_ARRAY:      return sizeof(struct btf_array);
    case BTF_KIND_STRUCT:
    case BTF_KIND_UNION:      return (size_t)vlen * sizeof(struct btf_member);
    case BTF_KIND_ENUM:       return (size_t)vlen * 8;
    case BTF_KIND_FUNC_PROTO: return (size_t)vlen * 8;
    case BTF_KIND_VAR:        return 4;
    case BTF_KIND_DATASEC:    return (size_t)vlen * sizeof(struct btf_var_sec);
    case BTF_KIND_DECL_TAG:   return 4;
    case BTF_KIND_ENUM64:     return (size_t)vlen * 12;
    default:                  return 0;
    }
}

/* Strip typedefs and qualifiers. */
static const struct btf_type *btf_strip(uint32_t id, uint32_t *out_id) {
    for (int guard = 0; guard < 32; guard++) {
        const struct btf_type *t = btf_get(id);
        if (!t) return NULL;
        switch (BTF_KIND(t->info)) {
        case BTF_KIND_TYPEDEF: case BTF_KIND_VOLATILE: case BTF_KIND_CONST:
        case BTF_KIND_RESTRICT: case BTF_KIND_TYPE_TAG:
            id = t->size;   /* the union's `type` arm */
            continue;
        default:
            if (out_id) *out_id = id;
            return t;
        }
    }
    return NULL;
}

static uint32_t btf_size_of(uint32_t id) {
    const struct btf_type *t = btf_strip(id, NULL);
    if (!t) return 0;
    switch (BTF_KIND(t->info)) {
    case BTF_KIND_INT: case BTF_KIND_STRUCT: case BTF_KIND_UNION:
    case BTF_KIND_ENUM: case BTF_KIND_ENUM64: case BTF_KIND_FLOAT:
    case BTF_KIND_DATASEC:
        return t->size;
    case BTF_KIND_PTR:
        return 8;
    case BTF_KIND_ARRAY: {
        const struct btf_array *a = (const struct btf_array *)(t + 1);
        return a->nelems * btf_size_of(a->type);
    }
    default:
        return 0;
    }
}

/* `__uint(name, val)` is `int (*name)[val]`: the value is the array length. */
static uint32_t btf_uint_value(uint32_t id) {
    const struct btf_type *p = btf_strip(id, NULL);
    if (!p || BTF_KIND(p->info) != BTF_KIND_PTR) return 0;
    const struct btf_type *a = btf_strip(p->size, NULL);
    if (!a || BTF_KIND(a->info) != BTF_KIND_ARRAY) return 0;
    return ((const struct btf_array *)(a + 1))->nelems;
}

/* `__type(name, val)` is `typeof(val) *name`: the value is the pointee. */
static uint32_t btf_type_size(uint32_t id) {
    const struct btf_type *p = btf_strip(id, NULL);
    if (!p || BTF_KIND(p->info) != BTF_KIND_PTR) return 0;
    return btf_size_of(p->size);
}

static void btf_read_map_struct(const char *name, uint32_t struct_id) {
    uint32_t sid = 0;
    const struct btf_type *st = btf_strip(struct_id, &sid);
    if (!st || BTF_KIND(st->info) != BTF_KIND_STRUCT) {
        fprintf(stderr, "bpf_to_ir: map %s: BTF entry is not a struct\n", name);
        had_error = 1;
        return;
    }
    uint32_t type = 0, ks = 0, vs = 0, me = 0;
    const struct btf_member *mem = (const struct btf_member *)(st + 1);
    for (uint32_t i = 0; i < BTF_VLEN(st->info); i++) {
        const char *mn = btf_name(mem[i].name_off);
        if      (!strcmp(mn, "type"))        type = btf_uint_value(mem[i].type);
        else if (!strcmp(mn, "max_entries")) me   = btf_uint_value(mem[i].type);
        else if (!strcmp(mn, "key_size"))    ks   = btf_uint_value(mem[i].type);
        else if (!strcmp(mn, "value_size"))  vs   = btf_uint_value(mem[i].type);
        else if (!strcmp(mn, "key"))         ks   = btf_type_size(mem[i].type);
        else if (!strcmp(mn, "value"))       vs   = btf_type_size(mem[i].type);
    }
    if (ks == 0 || vs == 0) {
        fprintf(stderr, "bpf_to_ir: map %s: BTF gives key_size=%u value_size=%u; "
                        "the map cannot be sized\n", name, ks, vs);
        had_error = 1;
        return;
    }
    add_map(name, type, ks, vs, me);
}

/* Walk `.BTF` and register every map declared in the `.maps` data section. */
static void discover_btf_maps(const char *btf, size_t btf_len) {
    if (btf_len < sizeof(struct btf_header)) return;
    const struct btf_header *h = (const struct btf_header *)btf;
    if (h->magic != BTF_MAGIC) {
        fprintf(stderr, "bpf_to_ir: .BTF has magic 0x%x, not 0x%x "
                        "(big-endian object?)\n", h->magic, BTF_MAGIC);
        had_error = 1;
        return;
    }
    const char *base = btf + h->hdr_len;
    if (h->hdr_len + (size_t)h->type_off + h->type_len > btf_len ||
        h->hdr_len + (size_t)h->str_off  + h->str_len  > btf_len) {
        fprintf(stderr, "bpf_to_ir: .BTF is truncated\n");
        had_error = 1;
        return;
    }
    btf_strs = base + h->str_off;
    btf_strs_len = h->str_len;

    const char *p   = base + h->type_off;
    const char *end = p + h->type_len;
    btf_ntypes = 1;                     /* id 0 is void */
    while (p + sizeof(struct btf_type) <= end && btf_ntypes < MAX_BTF_TYPES) {
        const struct btf_type *t = (const struct btf_type *)p;
        size_t sz = sizeof(struct btf_type) + btf_extra(t);
        if (p + sz > end) break;
        btf_types[btf_ntypes++] = t;
        p += sz;
    }

    for (uint32_t id = 1; id < btf_ntypes; id++) {
        const struct btf_type *t = btf_types[id];
        if (BTF_KIND(t->info) != BTF_KIND_DATASEC) continue;
        if (strcmp(btf_name(t->name_off), ".maps") != 0) continue;
        const struct btf_var_sec *vs = (const struct btf_var_sec *)(t + 1);
        for (uint32_t i = 0; i < BTF_VLEN(t->info); i++) {
            const struct btf_type *var = btf_get(vs[i].type);
            if (!var || BTF_KIND(var->info) != BTF_KIND_VAR) continue;
            btf_read_map_struct(btf_name(var->name_off), var->size);
        }
    }
}

/*
 * The legacy declaration is `struct bpf_map_def SEC("maps")`, whose five u32
 * fields sit in the section data, so no BTF is needed.
 */
static void discover_legacy_maps(const char *sec, size_t sec_len, int sec_idx,
                                 const Elf64_Sym *syms, size_t nsyms,
                                 const char *strtab) {
    for (size_t i = 0; i < nsyms; i++) {
        if (syms[i].st_shndx != (Elf64_Half)sec_idx) continue;
        if (ELF64_ST_TYPE(syms[i].st_info) == STT_SECTION) continue;
        uint64_t off = syms[i].st_value;
        if (off + 5 * sizeof(uint32_t) > sec_len) continue;
        uint32_t f[5];
        memcpy(f, sec + off, sizeof(f));
        add_map(strtab + syms[i].st_name, f[0], f[1], f[2], f[3]);
    }
}

/* ── Pointer provenance ─────────────────────────────────────────────── */

/*
 * Each register carries an abstract region tag.  A load or store needs one to
 * know which declared region to name, and the stack needs a constant offset
 * on top of that to pick a slot header.
 *
 * T_SCALAR is a plain integer; T_UNKNOWN is the join of two disagreeing tags,
 * and using it as a memory base is an error rather than a guess.
 *
 * T_MAP is the map object itself, which is only ever an argument to a helper;
 * T_MAPVAL is what a successful lookup returns, a pointer into the map's
 * region.  Both carry the map's index in `mapidx`, since which map it is
 * decides which region a dereference names.
 */
typedef enum { T_SCALAR = 0, T_CTX, T_PKT, T_STACK, T_MAP, T_MAPVAL,
               T_UNKNOWN } PtrTag;

typedef struct {
    PtrTag  tag;
    int64_t off;        /* offset from the region base, if known */
    int     off_known;
    int     mapidx;     /* T_MAP / T_MAPVAL only; -1 otherwise */
} RegInfo;

typedef struct {
    RegInfo reg[NUM_BPF_REGS];
    RegInfo slot[BPF_STACK_SIZE + 1];  /* what is spilled at [r10 - k] */
    int     live;                      /* has this state been reached? */
} AbsState;

static RegInfo scalar(void) {
    RegInfo r = { T_SCALAR, 0, 1, -1 };
    return r;
}
static RegInfo pointer(PtrTag t, int64_t off) {
    RegInfo r = { t, off, 1, -1 };
    return r;
}
static RegInfo map_pointer(PtrTag t, int64_t off, int mapidx) {
    RegInfo r = { t, off, 1, mapidx };
    return r;
}

static RegInfo join_reg(RegInfo a, RegInfo b) {
    RegInfo r = { T_UNKNOWN, 0, 0, -1 };
    if (a.tag != b.tag || a.mapidx != b.mapidx) return r;
    r.tag = a.tag;
    r.mapidx = a.mapidx;
    r.off_known = a.off_known && b.off_known && a.off == b.off;
    r.off = r.off_known ? a.off : 0;
    return r;
}

static void join_state(AbsState *dst, const AbsState *src) {
    if (!src->live) return;
    if (!dst->live) { *dst = *src; return; }
    for (int i = 0; i < NUM_BPF_REGS; i++)
        dst->reg[i] = join_reg(dst->reg[i], src->reg[i]);
    for (int i = 0; i <= BPF_STACK_SIZE; i++)
        dst->slot[i] = join_reg(dst->slot[i], src->slot[i]);
}

/*
 * The context a program is called with, which is the one piece of
 * program-type knowledge in the translator.  Two things depend on it: how big
 * the ctx region is, and which of its fields hold pointers into the packet --
 * a load from those two offsets produces a packet pointer, anything else a
 * scalar.  The value loaded is still whatever the (symbolic) ctx region
 * holds; the offsets the program computes from it are compared between the
 * two versions, not assumed.
 *
 * Getting the length wrong is not a small error.  `struct __sk_buff` puts
 * `vlan_tci` at offset 24 and `data` at 76, so modelling an `__sk_buff`
 * program with `struct xdp_md`'s 20 bytes makes every field access an
 * out-of-bounds read.  Those are total, but they record an overrun, and an
 * overrun rejects the run at the sink -- so the program is modelled as one
 * that always rejects, and two such programs are "equivalent" whatever they
 * compute.  Hence [ctx_access_ok] below, which refuses the translation rather
 * than emitting that silently.
 */
typedef struct {
    const char *name;
    int         len;          /* bytes of the struct modelled */
    int64_t     data_off;     /* the packet-pointer fields    */
    int64_t     data_end_off;
} CtxLayout;

static const CtxLayout ctx_xdp_md  = { "xdp_md",   20,  0,  4 };
static const CtxLayout ctx_sk_buff = { "__sk_buff", 192, 76, 80 };

static const CtxLayout *ctx_layout = &ctx_xdp_md;

/* Set by --ctx=NAME, for the programs whose section name is a project's own
   convention rather than a libbpf program type (suricata's "loadbalancer",
   say) and so says nothing about the context. */
static const CtxLayout *ctx_override = NULL;

static const CtxLayout *ctx_layout_by_name(const char *n) {
    if (!strcmp(n, "xdp_md") || !strcmp(n, "xdp"))     return &ctx_xdp_md;
    if (!strcmp(n, "__sk_buff") || !strcmp(n, "skb"))  return &ctx_sk_buff;
    return NULL;
}

/*
 * Which context a program section gets.  The names are the conventional
 * libbpf program-type prefixes; an unrecognised one is XDP only if it says
 * so, because guessing wrong is the silent failure described above.
 */
static const CtxLayout *ctx_layout_for(const char *sec) {
    /* Program types whose context is struct __sk_buff.  Only these -- a name
       that is merely network-ish is NOT enough: sk_reuseport, sk_msg,
       sockops, sk_lookup and the cgroup/sock* hooks each have their own
       context struct, and reaching them through this one would model a
       different program while still translating cleanly. */
    static const char *skb_prefixes[] = {
        "socket", "filter", "tc", "classifier", "action", "cgroup_skb",
        "cgroup/skb", "sk_skb", "lwt_", "flow_dissector", NULL
    };
    if (!strncmp(sec, "xdp", 3)) return &ctx_xdp_md;
    for (int i = 0; skb_prefixes[i]; i++)
        if (!strncmp(sec, skb_prefixes[i], strlen(skb_prefixes[i])))
            return &ctx_sk_buff;
    return NULL;
}

static int ctx_field_is_pkt_ptr(int64_t off) {
    return off == ctx_layout->data_off || off == ctx_layout->data_end_off;
}

/*
 * A ctx access at a statically known offset must land inside the region.  The
 * offset is known for essentially every real ctx access -- the verifier
 * requires it -- so this catches a wrong or missing layout at translation
 * time instead of at the both-rejected disjunct of the equivalence checker.
 */
static int ctx_access_ok(size_t idx, RegInfo base, int64_t insn_off,
                         int nbytes, const char *what) {
    if (base.tag != T_CTX || !base.off_known) return 1;
    int64_t lo = base.off + insn_off;
    if (lo >= 0 && lo + nbytes <= ctx_layout->len) return 1;
    unsupported(idx, "%s at ctx offset %lld..%lld, outside the %d bytes of "
                     "struct %s that are modelled",
                what, (long long)lo, (long long)(lo + nbytes), ctx_layout->len,
                ctx_layout->name);
    return 0;
}

/* ── Stack slot headers ─────────────────────────────────────────────── */

static int stack_hdr_of[BPF_STACK_SIZE + 1];   /* slot k -> header id, 0 = none */
static int next_stack_hdr = H_STACK_BASE;

static int stack_header(int slot) {
    if (slot < 0 || slot > BPF_STACK_SIZE) return 0;
    if (!stack_hdr_of[slot]) stack_hdr_of[slot] = next_stack_hdr++;
    return stack_hdr_of[slot];
}

/* ── Op emission ────────────────────────────────────────────────────── */

static StrVec cur_ops;      /* ops of the block being translated */
static int    tmp_next;     /* scratch pool cursor, reset per instruction */

static int fresh_tmp(size_t idx) {
    if (tmp_next >= NUM_TMPS) {
        unsupported(idx, "ran out of scratch headers");
        tmp_next = 0;
    }
    return H_TMP(tmp_next++);
}

static const char *width_name(int bytes) {
    switch (bytes) {
    case 1: return "W8";
    case 2: return "W16";
    case 4: return "W32";
    default: return "W64";
    }
}

/* Coq's uint64 is a Z; emit values already reduced mod 2^64. */
static char *konst(uint64_t v) { return xsprintf("(OpConst %" PRIu64 ")", v); }
static char *hdr(int h)        { return xsprintf("(OpHeader %d)", h); }

static void emit_binop(const char *op, const char *w, char *a1, char *a2, int target) {
    sv_push(&cur_ops, xsprintf("(StatelessOp %s %s %s %s %d)", op, w, a1, a2, target));
    free(a1);
    free(a2);
}

static void emit_cast(const char *from, const char *to, char *arg, int target) {
    sv_push(&cur_ops, xsprintf("(CastHeaderOp %s %s %s %d)", from, to, arg, target));
    free(arg);
}

static void emit_load(const char *w, int region, char *off, int target) {
    sv_push(&cur_ops, xsprintf("(LoadOp %s %d %s %d)", w, region, off, target));
    free(off);
}

static void emit_store(const char *w, int region, char *off, char *val) {
    sv_push(&cur_ops, xsprintf("(StoreOp %s %d %s %s)", w, region, off, val));
    free(off);
    free(val);
}

/* dst := imm, at u64 */
static void emit_set(int target, uint64_t v) {
    emit_binop("AddOp", "W64", konst(v), konst(0), target);
}

/* dst := src, at u64 */
static void emit_move(int target, int src) {
    emit_binop("AddOp", "W64", hdr(src), konst(0), target);
}

/* ── ALU ────────────────────────────────────────────────────────────── */

static const char *alu_binop_name(uint8_t op) {
    switch (op) {
    case BPF_ADD: return "AddOp";
    case BPF_SUB: return "SubOp";
    case BPF_AND: return "AndOp";
    case BPF_OR:  return "OrOp";
    case BPF_XOR: return "XorOp";
    case BPF_MUL: return "MulOp";
    case BPF_DIV: return "DivOp";   /* unsigned; x/0 = 0, as in BPF */
    case BPF_MOD: return "ModOp";   /* unsigned; x%0 = x, as in BPF */
    default: return NULL;
    }
}

/*
 * An arithmetic right shift by a constant k, built out of the operators the
 * IR does have:
 *
 *   logical = x / 2^k                      (unsigned divide)
 *   sign    = x / 2^63                     (0 or 1)
 *   result  = logical + sign * (2^k - 1) * 2^(64-k)
 *
 * The two summands occupy disjoint bits, so the add is an or.
 */
static void emit_arsh_const(size_t idx, int reg, int k, int width_bits) {
    if (k <= 0 || k >= width_bits) {
        if (k != 0) unsupported(idx, "arithmetic shift by %d at %d bits", k, width_bits);
        return;
    }
    const char *w = width_bits == 32 ? "W32" : "W64";
    int t_sign = fresh_tmp(idx);
    int t_mask = fresh_tmp(idx);
    uint64_t sign_div = width_bits == 32 ? (1ULL << 31) : (1ULL << 63);
    uint64_t mask = ((1ULL << k) - 1ULL) << (width_bits - k);
    if (width_bits == 32) mask &= 0xffffffffULL;

    emit_binop("DivOp", w, hdr(reg), konst(sign_div), t_sign);
    emit_binop("MulOp", w, hdr(t_sign), konst(mask), t_mask);
    emit_binop("DivOp", w, hdr(reg), konst(1ULL << k), reg);
    emit_binop("OrOp",  w, hdr(reg), hdr(t_mask), reg);
}

/*
 * A byte swap, built out of the operators the IR does have.  Same trick as
 * emit_arsh_const: there is no shift, but a shift by a constant is a multiply
 * or divide by a power of two, so byte i of the source
 *
 *   (src / 2^(8i)) & 0xff
 *
 * lands at byte (n-1-i) of the result by multiplying it back up.  The partial
 * results occupy disjoint bits, so the accumulate is an or.
 *
 * Everything is done at W64 with explicit masks rather than at the operand's
 * own width, so the source is read once and the caller may pass the same
 * header as [src] and [target].  Costs 4 ops per byte, so 8 for a u16 and 32
 * for a u64.
 */
static void emit_bswap(size_t idx, int src, int nbytes, int target) {
    if (nbytes <= 1) {
        if (src != target) emit_move(target, src);
        return;
    }
    int t_src = fresh_tmp(idx);
    int t_acc = fresh_tmp(idx);
    int t_b   = fresh_tmp(idx);

    emit_move(t_src, src);
    emit_set(t_acc, 0);
    for (int i = 0; i < nbytes; i++) {
        int up = 8 * (nbytes - 1 - i);
        if (i == 0) emit_move(t_b, t_src);
        else emit_binop("DivOp", "W64", hdr(t_src), konst(1ULL << (8 * i)), t_b);
        emit_binop("AndOp", "W64", hdr(t_b), konst(0xffULL), t_b);
        if (up) emit_binop("MulOp", "W64", hdr(t_b), konst(1ULL << up), t_b);
        emit_binop("OrOp", "W64", hdr(t_acc), hdr(t_b), t_acc);
    }
    emit_move(target, t_acc);
}

/*
 * ALU at 64 bits: operate on the register headers directly.
 * ALU at 32 bits: narrow both operands, operate at W32, widen back -- which
 * is also the zero-extension BPF's 32-bit ALU performs on the upper half.
 */
static void translate_alu(size_t idx, struct bpf_insn *in, int is64, AbsState *st) {
    uint8_t op = BPF_OP(in->code);
    int is_imm = (BPF_SRC(in->code) == BPF_K);
    int dst = in->dst_reg, src = in->src_reg;
    int hd = H_REG(dst), hs = H_REG(src);
    uint64_t imm = (uint64_t)(int64_t)(int32_t)in->imm;
    const char *w = is64 ? "W64" : "W32";
    int width_bits = is64 ? 64 : 32;

    if (dst >= NUM_BPF_REGS || src >= NUM_BPF_REGS) {
        unsupported(idx, "register out of range");
        return;
    }

    /* Abstract effect first; the concrete ops follow. */
    if (op == BPF_MOV) {
        st->reg[dst] = is_imm ? scalar() : st->reg[src];
        if (!is64) st->reg[dst] = scalar();   /* truncation destroys a pointer */
    } else if (op == BPF_ADD && is64) {
        if (is_imm) {
            if (st->reg[dst].tag != T_SCALAR && st->reg[dst].off_known)
                st->reg[dst].off += (int64_t)(int32_t)in->imm;
            else if (st->reg[dst].tag != T_SCALAR)
                st->reg[dst].off_known = 0;
        } else if (st->reg[dst].tag != T_SCALAR && st->reg[src].tag == T_SCALAR) {
            st->reg[dst].off_known = 0;       /* ptr + variable offset */
        } else if (st->reg[dst].tag == T_SCALAR && st->reg[src].tag != T_SCALAR) {
            st->reg[dst] = st->reg[src];
            st->reg[dst].off_known = 0;
        } else {
            st->reg[dst] = scalar();
        }
    } else {
        st->reg[dst] = scalar();
    }

    switch (op) {
    case BPF_MOV:
        if (is64) {
            if (is_imm) emit_set(hd, imm);
            else        emit_move(hd, hs);
        } else {
            if (is_imm) emit_set(hd, (uint32_t)in->imm);
            else {
                int t = fresh_tmp(idx);
                emit_cast("W64", "W32", hdr(hs), t);
                emit_cast("W32", "W64", hdr(t), hd);
            }
        }
        return;

    case BPF_NEG:
        if (is64) {
            emit_binop("SubOp", "W64", konst(0), hdr(hd), hd);
        } else {
            int t = fresh_tmp(idx);
            emit_cast("W64", "W32", hdr(hd), t);
            emit_binop("SubOp", "W32", konst(0), hdr(t), t);
            emit_cast("W32", "W64", hdr(t), hd);
        }
        return;

    case BPF_LSH:
    case BPF_RSH:
    case BPF_ARSH: {
        if (!is_imm) {
            unsupported(idx, "shift by a register (the IR has no shift operator; "
                             "only constant shifts lower to multiply/divide)");
            return;
        }
        int k = in->imm & (width_bits - 1);
        int t = is64 ? hd : fresh_tmp(idx);
        if (!is64) emit_cast("W64", "W32", hdr(hd), t);
        if (op == BPF_ARSH) {
            emit_arsh_const(idx, t, k, width_bits);
        } else if (k != 0) {
            emit_binop(op == BPF_LSH ? "MulOp" : "DivOp", w,
                       hdr(t), konst(1ULL << k), t);
        }
        if (!is64) emit_cast("W32", "W64", hdr(t), hd);
        return;
    }

    case BPF_END: {
        /* [imm] is the width in BITS, and the result is written back at that
           width -- the kernel assigns through a u16/u32, so the register's
           upper bits are zeroed whichever direction the conversion goes. */
        int bits = in->imm;
        if (bits != 16 && bits != 32 && bits != 64) {
            unsupported(idx, "BPF_END with a width of %d bits", bits);
            return;
        }
        if (bits != 64)
            emit_binop("AndOp", "W64", hdr(hd),
                       konst((1ULL << bits) - 1ULL), hd);
        /* BPF_END is defined against the HOST's byte order, and this
           translator models a little-endian host: BPF_TO_BE (the BPF_X source
           bit) is a real swap and BPF_TO_LE is the truncation alone.  The
           ALU64 spelling is BPF v4's unconditional `bswap`, which swaps
           regardless. */
        if (is64 || BPF_SRC(in->code) == BPF_X)
            emit_bswap(idx, hd, bits / 8, hd);
        return;
    }

    default: {
        const char *bin = alu_binop_name(op);
        if (!bin) { unsupported(idx, "ALU op 0x%x", op); return; }
        if (is64) {
            emit_binop(bin, "W64", hdr(hd), is_imm ? konst(imm) : hdr(hs), hd);
        } else {
            int t1 = fresh_tmp(idx);
            emit_cast("W64", "W32", hdr(hd), t1);
            if (is_imm) {
                emit_binop(bin, "W32", hdr(t1), konst((uint32_t)in->imm), t1);
            } else {
                int t2 = fresh_tmp(idx);
                emit_cast("W64", "W32", hdr(hs), t2);
                emit_binop(bin, "W32", hdr(t1), hdr(t2), t1);
            }
            emit_cast("W32", "W64", hdr(t1), hd);
        }
        return;
    }
    }
}

/* ── Memory ─────────────────────────────────────────────────────────── */

static int region_of(RegInfo r) {
    switch (r.tag) {
    case T_CTX: return REGION_CTX;
    case T_PKT: return REGION_PKT;
    case T_MAPVAL:
        return (r.mapidx >= 0 && r.mapidx < nmaps) ? map_region(r.mapidx)
                                                   : REGION_NONE;
    default:    return REGION_NONE;
    }
}

static int size_bytes(uint8_t code) {
    switch (BPF_SIZE(code)) {
    case BPF_B:  return 1;
    case BPF_H:  return 2;
    case BPF_W:  return 4;
    default:     return 8;
    }
}

/* Materialise `base + off` into a scratch header and return it. */
static int emit_address(size_t idx, int base_hdr, int64_t off) {
    int t = fresh_tmp(idx);
    emit_binop("AddOp", "W64", hdr(base_hdr), konst((uint64_t)off), t);
    return t;
}

static void translate_ldx(size_t idx, struct bpf_insn *in, AbsState *st) {
    int dst = in->dst_reg, src = in->src_reg;
    int nbytes = size_bytes(in->code);
    const char *w = width_name(nbytes);
    RegInfo base = st->reg[src];

    if (base.tag == T_STACK) {
        if (!base.off_known) {
            unsupported(idx, "stack load at a non-constant offset");
            st->reg[dst] = scalar();
            return;
        }
        int slot = (int)(-(base.off + in->off));
        int sh = stack_header(slot);
        if (!sh) {
            unsupported(idx, "stack load outside the %d-byte frame (slot %d)",
                        BPF_STACK_SIZE, slot);
            st->reg[dst] = scalar();
            return;
        }
        /* The slot header holds the value at the width it was stored; the
           cast both zero-extends and checks that width, exactly as a load
           from a region checks the cell's type. */
        emit_cast(w, "W64", hdr(sh), H_REG(dst));
        st->reg[dst] = st->slot[slot];
        return;
    }

    int region = region_of(base);
    if (region == REGION_NONE)
        unsupported(idx, "load through r%d, whose region is unknown", src);
    ctx_access_ok(idx, base, in->off, nbytes, "load");

    int t_addr = emit_address(idx, H_REG(src), in->off);
    int t_val = fresh_tmp(idx);
    emit_load(w, region, hdr(t_addr), t_val);
    emit_cast(w, "W64", hdr(t_val), H_REG(dst));

    if (base.tag == T_CTX && base.off_known && ctx_field_is_pkt_ptr(base.off + in->off))
        st->reg[dst] = pointer(T_PKT, 0);
    else
        st->reg[dst] = scalar();
    /* A pointer read out of memory has no statically known offset of its own;
       what the program computes from it is compared, not assumed. */
    if (st->reg[dst].tag == T_PKT) st->reg[dst].off_known = 0;
}

/* [dst + off] := <val_hdr or immediate>, width nbytes. */
static void translate_store(size_t idx, struct bpf_insn *in, AbsState *st,
                            int from_reg) {
    int dst = in->dst_reg, src = in->src_reg;
    int nbytes = size_bytes(in->code);
    const char *w = width_name(nbytes);
    RegInfo base = st->reg[dst];
    uint64_t imm = (uint64_t)(int64_t)(int32_t)in->imm;

    if (base.tag == T_STACK) {
        if (!base.off_known) {
            unsupported(idx, "stack store at a non-constant offset");
            return;
        }
        int slot = (int)(-(base.off + in->off));
        int sh = stack_header(slot);
        if (!sh) {
            unsupported(idx, "stack store outside the %d-byte frame (slot %d)",
                        BPF_STACK_SIZE, slot);
            return;
        }
        if (from_reg) {
            emit_cast("W64", w, hdr(H_REG(src)), sh);
            st->slot[slot] = st->reg[src];
        } else {
            emit_binop("AddOp", w, konst(imm), konst(0), sh);
            st->slot[slot] = scalar();
        }
        return;
    }

    int region = region_of(base);
    if (region == REGION_NONE)
        unsupported(idx, "store through r%d, whose region is unknown", dst);
    ctx_access_ok(idx, base, in->off, nbytes, "store");

    int t_addr = emit_address(idx, H_REG(dst), in->off);
    if (from_reg) {
        int t_val = fresh_tmp(idx);
        emit_cast("W64", w, hdr(H_REG(src)), t_val);
        emit_store(w, region, hdr(t_addr), hdr(t_val));
    } else {
        /* A constant operand adopts the op's type, so no cast is needed. */
        emit_store(w, region, hdr(t_addr), konst(imm));
    }
}

/* ── Map lookup ─────────────────────────────────────────────────────── */

/* Which map each LD_IMM64 loads, from the object's relocations; -1 if none. */
static int insn_map_idx[MAX_INSNS + 1];

/*
 * Translate `r0 = bpf_map_lookup_elem(r1, r2)`.
 *
 * The straight-line part -- read the key, pick the slot, read the slot's
 * presence byte and compute its value pointer -- is emitted into the current
 * block.  Choosing between the pointer and NULL is a branch, so it is handed
 * back as a condition plus the op each arm runs, and the caller emits it with
 * the same two-transformer shape a conditional jump uses.
 *
 * Returns 0 (having reported why) if the call cannot be translated.
 */
static int emit_map_lookup(size_t idx, AbsState *st, char **cond,
                           char **arm_hit, char **arm_miss) {
    RegInfo mp = st->reg[1], kp = st->reg[2];

    if (mp.tag != T_MAP || mp.mapidx < 0) {
        unsupported(idx, "bpf_map_lookup_elem: r1 is not a known map pointer");
        return 0;
    }
    int m = mp.mapidx;
    MapInfo *mi = &map_tbl[m];
    if (mi->key_size != 1 && mi->key_size != 2 &&
        mi->key_size != 4 && mi->key_size != 8) {
        unsupported(idx, "map %s has a %u-byte key (only 1, 2, 4 and 8 are "
                         "modelled)", mi->name, mi->key_size);
        return 0;
    }
    const char *kw = width_name((int)mi->key_size);

    tmp_next = 0;
    int t_key = fresh_tmp(idx);

    if (kp.tag == T_STACK) {
        /* The usual shape: the key was written to a stack slot, which is a
           header rather than a region cell. */
        if (!kp.off_known) {
            unsupported(idx, "map key at a non-constant stack offset");
            return 0;
        }
        int slot = (int)(-kp.off);
        int sh = stack_header(slot);
        if (!sh) {
            unsupported(idx, "map key outside the %d-byte frame (slot %d)",
                        BPF_STACK_SIZE, slot);
            return 0;
        }
        emit_cast(kw, "W64", hdr(sh), t_key);
    } else {
        int region = region_of(kp);
        if (region == REGION_NONE) {
            unsupported(idx, "map key through r2, whose region is unknown");
            return 0;
        }
        int t_raw = fresh_tmp(idx);
        emit_load(kw, region, hdr(H_REG(2)), t_raw);
        emit_cast(kw, "W64", hdr(t_raw), t_key);
    }

    int t_slot = fresh_tmp(idx);
    emit_binop("ModOp", "W64", hdr(t_key), konst((uint64_t)mi->nslots), t_slot);

    int t_pres_raw = fresh_tmp(idx);
    int t_pres     = fresh_tmp(idx);
    emit_load("W8", map_region(m), hdr(t_slot), t_pres_raw);
    emit_cast("W8", "W64", hdr(t_pres_raw), t_pres);

    int t_vp = fresh_tmp(idx);
    emit_binop("MulOp", "W64", hdr(t_slot), konst(mi->value_size), t_vp);
    emit_binop("AddOp", "W64", hdr(t_vp),
               konst((uint64_t)map_value_base(m)), t_vp);

    *cond = xsprintf("(Coq_pair (Coq_pair %d CmpEq) (MatchConst 1 W64))", t_pres);
    *arm_hit  = xsprintf("(StatelessOp AddOp W64 (OpHeader %d) (OpConst 0) %d)",
                         t_vp, H_REG(0));
    *arm_miss = xsprintf("(StatelessOp AddOp W64 (OpConst 0) (OpConst 0) %d)",
                         H_REG(0));

    /* r0 is the value pointer on the hit arm and 0 on the miss arm; the tag
       is what a later dereference reads, and the program has to NULL-check
       before dereferencing or the verifier would have rejected it. */
    st->reg[0] = map_pointer(T_MAPVAL, 0, m);
    for (int r = 1; r <= 5; r++) st->reg[r] = scalar();   /* clobbered */
    return 1;
}

/* ── Classic-BPF packet loads ───────────────────────────────────────── */

/*
 * LD_ABS reads the packet at the constant in [imm]; LD_IND at [src_reg + imm].
 * Three things are implicit in the instruction rather than encoded, because
 * these lower to a call into the kernel rather than to a real load:
 *
 *   - the destination is always R0, and R1..R5 are clobbered;
 *   - the value arrives converted from network to host byte order;
 *   - an access past the end of the packet ABORTS the program, returning 0.
 *
 * The first two are emitted.  The third is not, and the difference is worth
 * being precise about.  An access outside the packet region yields ErrorVal
 * and records an overrun, and an overrun rejects the run at the sink -- a
 * different terminal state from "returns 0", but a conservative one.  Two
 * programs that both run off the packet both reject and still compare equal;
 * one that runs off and one that does not are reported different, which is
 * right unless the other happened to return 0 as well.  So the approximation
 * can raise a false difference, never hide a real one.
 *
 * Note these index the packet region from 0 directly, rather than through
 * ctx->data as an ordinary packet access does -- which is what the
 * instruction means, and it makes the offset concrete where a ctx->data-based
 * one stays symbolic.
 */
static void translate_ld_pkt(size_t idx, struct bpf_insn *in, AbsState *st) {
    int nbytes = size_bytes(in->code);
    if (nbytes == 8) {
        /* Classic BPF had no 64-bit packet load and the verifier rejects one. */
        unsupported(idx, "LD_ABS/LD_IND at 64 bits");
        return;
    }
    const char *w = width_name(nbytes);
    int is_ind = BPF_MODE(in->code) == BPF_IND;

    int t_addr = fresh_tmp(idx);
    if (is_ind)
        emit_binop("AddOp", "W64", hdr(H_REG(in->src_reg)),
                   konst((uint64_t)(int64_t)in->imm), t_addr);
    else
        emit_set(t_addr, (uint64_t)(int64_t)in->imm);

    int t_val = fresh_tmp(idx);
    emit_load(w, REGION_PKT, hdr(t_addr), t_val);
    emit_cast(w, "W64", hdr(t_val), t_val);
    emit_bswap(idx, t_val, nbytes, H_REG(0));

    st->reg[0] = scalar();
    for (int r = 1; r <= 5; r++) st->reg[r] = scalar();
}

/* ── Straight-line translation ──────────────────────────────────────── */

/* Returns the number of instruction slots consumed (2 for LD_IMM64). */
static int translate_one(size_t idx, struct bpf_insn *insns, size_t n,
                         AbsState *st) {
    struct bpf_insn *in = &insns[idx];
    uint8_t cls = BPF_CLASS(in->code);
    tmp_next = 0;

    if (is_nop_jump(in)) return 1;

    if (in->code == BPF_LD_IMM64) {
        if (idx + 1 >= n) { unsupported(idx, "truncated LD_IMM64"); return 1; }
        /* A map address.  The object file's src_reg is still 0 -- libbpf sets
           it to BPF_PSEUDO_MAP_FD when it applies the relocation -- so the
           relocation is the only marker there is.  The register's value is
           never read; its tag is what names the region. */
        if (insn_map_idx[idx] >= 0) {
            emit_set(H_REG(in->dst_reg), 0);
            st->reg[in->dst_reg] = map_pointer(T_MAP, 0, insn_map_idx[idx]);
            return 2;
        }
        if (in->src_reg != 0)
            unsupported(idx, "LD_IMM64 with src_reg=%d (map/pseudo immediate)",
                        in->src_reg);
        uint64_t v = ((uint64_t)(uint32_t)insns[idx + 1].imm << 32)
                     | (uint64_t)(uint32_t)in->imm;
        emit_set(H_REG(in->dst_reg), v);
        st->reg[in->dst_reg] = scalar();
        return 2;
    }

    switch (cls) {
    case BPF_ALU64: translate_alu(idx, in, 1, st); break;
    case BPF_ALU:   translate_alu(idx, in, 0, st); break;
    case BPF_LDX:   translate_ldx(idx, in, st); break;
    case BPF_STX:
        if (BPF_MODE(in->code) == BPF_ATOMIC) unsupported(idx, "atomic memory op");
        else translate_store(idx, in, st, 1);
        break;
    case BPF_ST:    translate_store(idx, in, st, 0); break;
    case BPF_LD:
        if (BPF_MODE(in->code) == BPF_ABS || BPF_MODE(in->code) == BPF_IND)
            translate_ld_pkt(idx, in, st);
        else
            unsupported(idx, "BPF_LD in mode 0x%x", BPF_MODE(in->code));
        break;
    default:        unsupported(idx, "instruction class 0x%x", cls); break;
    }
    return 1;
}

/* ── Blocks ─────────────────────────────────────────────────────────── */

static int is_leader[MAX_INSNS + 1];
static int block_of[MAX_INSNS + 1];   /* insn index -> block index          */
static int block_start[MAX_INSNS + 1];
static int nblocks;

static int jmp_is_conditional(uint8_t code) {
    if (BPF_CLASS(code) != BPF_JMP && BPF_CLASS(code) != BPF_JMP32) return 0;
    uint8_t op = BPF_OP(code);
    return op != BPF_JA && op != BPF_EXIT && op != BPF_CALL;
}

static void find_leaders(struct bpf_insn *insns, size_t n) {
    memset(is_leader, 0, sizeof(is_leader));
    is_leader[0] = 1;
    for (size_t i = 0; i < n; i++) {
        if (insns[i].code == BPF_LD_IMM64) { i++; continue; }
        if (!is_jmp_class(insns[i].code)) continue;
        uint8_t op = BPF_OP(insns[i].code);
        /* `JA +0` is a jump to the next instruction.  clang emits a lot of
           them; splitting a block at each one would double the length of the
           module chain for nothing. */
        if (op == BPF_JA && insns[i].off == 0) continue;
        if (i + 1 < n) is_leader[i + 1] = 1;
        /* A CALL ends its block: a map lookup decides between a pointer and
           NULL, and a decision is a match pattern, which is only read on
           entry to a transformer. */
        if (op == BPF_EXIT || op == BPF_CALL) continue;
        long target = (long)i + 1 + insns[i].off;
        if (target < 0 || (size_t)target > n) {
            unsupported(i, "jump target %ld is out of range", target);
            continue;
        }
        if (target <= (long)i)
            unsupported(i, "backward jump to %ld (loops are not modelled)", target);
        is_leader[target] = 1;
    }

    nblocks = 0;
    for (size_t i = 0; i < n; i++) {
        if (is_leader[i]) block_start[nblocks++] = (int)i;
        block_of[i] = nblocks - 1;
    }
}

/*
 * The condition of a conditional jump, as a single match-pattern entry, plus
 * which arm the entry selects.
 *
 * A match pattern is a conjunction of positive comparisons over CmpEq/CmpGt/
 * CmpLt with no negation, so the four "or equal" and "not equal" forms are
 * expressed by testing the complementary condition and swapping the arms;
 * first-match ordering supplies the else.  *swap is set when the entry
 * selects the fallthrough rather than the jump target.
 *
 * Signed comparisons are biased into unsigned ones by flipping the sign bit
 * of both operands (CrVal.ltb is Integers.ltu), which needs scratch ops in
 * the block; those are emitted here.
 */
static char *emit_condition(size_t idx, struct bpf_insn *in, int *swap) {
    uint8_t op = BPF_OP(in->code);
    int is_imm = (BPF_SRC(in->code) == BPF_K);
    int is32 = BPF_CLASS(in->code) == BPF_JMP32;
    const char *w = is32 ? "W32" : "W64";
    uint64_t imm = is32 ? (uint64_t)(uint32_t)in->imm
                        : (uint64_t)(int64_t)(int32_t)in->imm;
    int lhs = H_REG(in->dst_reg);
    int is_signed = (op == BPF_JSGT || op == BPF_JSGE || op == BPF_JSLT || op == BPF_JSLE);
    tmp_next = 0;
    *swap = 0;

    /* JSET has no comparison form at all: compute the masked value and test
       it against zero. */
    if (op == BPF_JSET) {
        int t = fresh_tmp(idx);
        if (is32) {
            int t2 = fresh_tmp(idx);
            emit_cast("W64", "W32", hdr(lhs), t2);
            if (is_imm) emit_binop("AndOp", "W32", hdr(t2), konst(imm), t);
            else {
                int t3 = fresh_tmp(idx);
                emit_cast("W64", "W32", hdr(H_REG(in->src_reg)), t3);
                emit_binop("AndOp", "W32", hdr(t2), hdr(t3), t);
            }
            *swap = 1;
            return xsprintf("(Coq_pair (Coq_pair %d CmpEq) (MatchConst 0 W32))", t);
        }
        if (is_imm) emit_binop("AndOp", "W64", hdr(lhs), konst(imm), t);
        else        emit_binop("AndOp", "W64", hdr(lhs), hdr(H_REG(in->src_reg)), t);
        *swap = 1;
        return xsprintf("(Coq_pair (Coq_pair %d CmpEq) (MatchConst 0 W64))", t);
    }

    /* Narrow to 32 bits and/or bias by the sign bit, as needed.  Either
       rewrites both sides into scratch headers. */
    char *rhs = NULL;
    if (is32 || is_signed) {
        uint64_t bias = is32 ? 0x80000000ULL : 0x8000000000000000ULL;
        int tl = fresh_tmp(idx);
        if (is32) emit_cast("W64", "W32", hdr(lhs), tl);
        else      emit_move(tl, lhs);
        if (is_signed) emit_binop("XorOp", w, hdr(tl), konst(bias), tl);
        lhs = tl;

        if (is_imm) {
            uint64_t k = is32 ? (uint64_t)(uint32_t)in->imm : imm;
            if (is_signed) k ^= bias;
            rhs = xsprintf("(MatchConst %" PRIu64 " %s)", k, w);
        } else {
            int tr = fresh_tmp(idx);
            if (is32) emit_cast("W64", "W32", hdr(H_REG(in->src_reg)), tr);
            else      emit_move(tr, H_REG(in->src_reg));
            if (is_signed) emit_binop("XorOp", w, hdr(tr), konst(bias), tr);
            rhs = xsprintf("(MatchHeader %d)", tr);
        }
    } else {
        rhs = is_imm ? xsprintf("(MatchConst %" PRIu64 " W64)", imm)
                     : xsprintf("(MatchHeader %d)", H_REG(in->src_reg));
    }

    const char *cmp;
    switch (op) {
    case BPF_JEQ:  cmp = "CmpEq"; *swap = 0; break;
    case BPF_JNE:  cmp = "CmpEq"; *swap = 1; break;
    case BPF_JGT:  case BPF_JSGT: cmp = "CmpGt"; *swap = 0; break;
    case BPF_JLT:  case BPF_JSLT: cmp = "CmpLt"; *swap = 0; break;
    case BPF_JGE:  case BPF_JSGE: cmp = "CmpLt"; *swap = 1; break;
    case BPF_JLE:  case BPF_JSLE: cmp = "CmpGt"; *swap = 1; break;
    default:
        unsupported(idx, "jump op 0x%x", op);
        free(rhs);
        return NULL;
    }
    char *entry = xsprintf("(Coq_pair (Coq_pair %d %s) %s)", lhs, cmp, rhs);
    free(rhs);
    return entry;
}

/* ── Module emission ────────────────────────────────────────────────── */

static StrVec modules;
static int next_mod = MOD_FIRST_XFRM;

static char *rule(char *match_list, char *op_list) {
    char *r = xsprintf("(Seq (SeqCtr %s %s))", match_list, op_list);
    free(match_list);
    free(op_list);
    return r;
}

/* Every transformer ends with an empty-pattern default rule, which
   CrDslProperties.transformer_has_default requires; it does nothing, so a
   state whose pc names no block passes through untouched. */
static char *default_rule(void) {
    return xsprintf("(Seq (SeqCtr Coq_nil Coq_nil))");
}

static char *pc_guard(int pc) {
    return xsprintf("(Coq_cons (Coq_pair (Coq_pair %d CmpEq) (MatchConst %d W64)) Coq_nil)",
                    H_PC, pc);
}

static void push_transformer(StrVec *rules) {
    sv_push(rules, default_rule());
    sv_push(&modules,
            xsprintf("(TransformerModule %d Coq_nil Coq_nil %s)",
                     next_mod++, sv_to_coq_list(rules)));
}

static char *set_pc(int pc) {
    return xsprintf("(StatelessOp AddOp W64 (OpConst %d) (OpConst 0) %d)", pc, H_PC);
}

/* ── Top level ──────────────────────────────────────────────────────── */

static AbsState *block_in;

static void translate_program(struct bpf_insn *insns, size_t n) {
    find_leaders(insns, n);
    scan_used_regs(insns, n);

    block_in = calloc((size_t)nblocks, sizeof(AbsState));
    if (!block_in) { perror("calloc"); exit(1); }

    /* Entry state: r1 is the context pointer, r10 the frame pointer.  Every
       other register is undefined on entry (the verifier rejects reading
       one), so it is left scalar and will read UninitVal if anything does. */
    AbsState *entry = &block_in[0];
    for (int i = 0; i < NUM_BPF_REGS; i++) entry->reg[i] = scalar();
    for (int i = 0; i <= BPF_STACK_SIZE; i++) entry->slot[i] = scalar();
    entry->reg[1] = pointer(T_CTX, 0);
    entry->reg[10] = pointer(T_STACK, 0);
    entry->live = 1;

    /* The preamble seeds pc, gives r1 its offset within the ctx region ("the
       context pointer" is offset 0 of region 1), and gives every other
       register and scratch header a defined u64 value.

       That last part is not cosmetic.  The symbolic header map starts seeded
       with SmtUninit, and a transformer's merge keeps the old value on the
       path where its guard did not match -- so without this, every register's
       symbolic expression has an SmtUninit leaf and the solver has to carry
       "this might not be an integer" through the whole program.  Initialising
       them roughly halves the solve time on a several-hundred-instruction
       program (measurements in <ir>/memo-memo.txt).

       It costs nothing in fidelity for any program the BPF verifier accepts:
       everything but r1 and r10 is undefined at entry and the verifier rejects
       reading an uninitialised register, so a valid program always writes
       before it reads.  What is given up is that the model no longer
       distinguishes such a read -- which the verifier catches anyway.

       Only registers the program mentions, and not the scratch headers: both
       were measured and neither made a difference beyond noise, so this keeps
       the preamble to what it can justify. */
    {
        StrVec rules;
        sv_init(&rules);
        sv_init(&cur_ops);
        for (int r = 0; r < NUM_BPF_REGS; r++)
            if (reg_used[r]) emit_set(H_REG(r), 0);
        sv_push(&cur_ops, set_pc(BLOCK_PC(0)));
        sv_push(&rules, rule(xsprintf("Coq_nil"), sv_to_coq_list(&cur_ops)));
        /* Already unconditional; no default rule needed beyond this one. */
        sv_push(&modules,
                xsprintf("(TransformerModule %d Coq_nil Coq_nil %s)",
                         next_mod++, sv_to_coq_list(&rules)));
    }

    for (int b = 0; b < nblocks; b++) {
        int start = block_start[b];
        int end = (b + 1 < nblocks) ? block_start[b + 1] : (int)n;
        AbsState st = block_in[b];
        if (!st.live) {
            /* Unreachable in the abstract sense only; still translated, with
               everything unknown, so the emitted program stays total. */
            for (int i = 0; i < NUM_BPF_REGS; i++) st.reg[i] = scalar();
            for (int i = 0; i <= BPF_STACK_SIZE; i++) st.slot[i] = scalar();
        }

        struct bpf_insn *term = &insns[end - 1];
        int has_term = is_jmp_class(term->code) && !is_nop_jump(term);
        int body_end = has_term ? end - 1 : end;

        sv_init(&cur_ops);
        for (int i = start; i < body_end; )
            i += translate_one((size_t)i, insns, n, &st);

        int cond_swap = 0;
        char *cond = NULL;
        /* Ops the two arms of the decision run, beyond setting the pc. */
        char *arm_hit = NULL, *arm_miss = NULL;
        if (has_term && jmp_is_conditional(term->code))
            cond = emit_condition((size_t)(end - 1), term, &cond_swap);

        /* Where control goes, and the abstract state each successor sees. */
        int fall_pc = PC_HALT, take_pc = PC_HALT;
        int fall_blk = -1, take_blk = -1;
        if (!has_term) {
            if (end < (int)n) { fall_blk = block_of[end]; fall_pc = BLOCK_PC(end); }
        } else {
            uint8_t op = BPF_OP(term->code);
            if (op == BPF_EXIT) {
                /* pc := 0; no later transformer guards on it. */
            } else if (op == BPF_CALL) {
                if (term->src_reg != 0)
                    unsupported((size_t)(end - 1), "subprogram call");
                else if (term->imm != BPF_FUNC_map_lookup_elem)
                    unsupported((size_t)(end - 1), "helper call %d "
                                "(only bpf_map_lookup_elem is modelled)",
                                term->imm);
                else
                    emit_map_lookup((size_t)(end - 1), &st,
                                    &cond, &arm_hit, &arm_miss);
                if (end < (int)n) { fall_blk = block_of[end]; fall_pc = BLOCK_PC(end); }
                /* Both arms rejoin at the next block. */
                take_pc = fall_pc;
            } else if (op == BPF_JA) {
                int t = end + term->off;
                if (t >= 0 && t < (int)n) { take_blk = block_of[t]; take_pc = BLOCK_PC(t); }
            } else {
                int t = end + term->off;
                if (t >= 0 && t < (int)n) { take_blk = block_of[t]; take_pc = BLOCK_PC(t); }
                if (end < (int)n) { fall_blk = block_of[end]; fall_pc = BLOCK_PC(end); }
            }
        }

        for (int *succ = (int[]){ fall_blk, take_blk }, k = 0; k < 2; k++)
            if (succ[k] >= 0) { st.live = 1; join_state(&block_in[succ[k]], &st); }

        StrVec rules;
        sv_init(&rules);
        if (cond) {
            /* Ops first, then a second transformer that reads what they
               computed.  A match pattern is evaluated on entry to its
               transformer, so the decision cannot live in this one. */
            sv_push(&cur_ops, set_pc(DECIDE_PC(start)));
            sv_push(&rules, rule(pc_guard(BLOCK_PC(start)), sv_to_coq_list(&cur_ops)));
            push_transformer(&rules);

            int first_pc = cond_swap ? fall_pc : take_pc;
            int second_pc = cond_swap ? take_pc : fall_pc;
            StrVec dec_rules, dec_ops;
            sv_init(&dec_rules);

            sv_init(&dec_ops);
            if (arm_hit) sv_push(&dec_ops, arm_hit);
            sv_push(&dec_ops, set_pc(first_pc));
            sv_push(&dec_rules,
                    rule(xsprintf("(Coq_cons (Coq_pair (Coq_pair %d CmpEq) "
                                  "(MatchConst %d W64)) (Coq_cons %s Coq_nil))",
                                  H_PC, DECIDE_PC(start), cond),
                         sv_to_coq_list(&dec_ops)));
            free(cond);

            sv_init(&dec_ops);
            if (arm_miss) sv_push(&dec_ops, arm_miss);
            sv_push(&dec_ops, set_pc(second_pc));
            sv_push(&dec_rules,
                    rule(pc_guard(DECIDE_PC(start)), sv_to_coq_list(&dec_ops)));

            push_transformer(&dec_rules);
        } else {
            int next_pc = (take_blk >= 0) ? take_pc : fall_pc;
            sv_push(&cur_ops, set_pc(next_pc));
            sv_push(&rules, rule(pc_guard(BLOCK_PC(start)), sv_to_coq_list(&cur_ops)));
            push_transformer(&rules);
        }
    }

    free(block_in);
}

static void emit_program(FILE *f) {
    /* Parser: a single accepting state that extracts nothing.  The IR packet
       is unused, but a network needs a parser source. */
    char *parser =
        xsprintf("(ParserModule %d ((parser_start 1) (parser_states "
                 "(Coq_cons ((psd_label 1) (psd_action None) "
                 "(psd_trans (Unconditional Accept))) Coq_nil))))", MOD_PARSER);
    /* Deparser: emit r0, which is what an eBPF program returns -- 32 bits of
       it, since a BPF return value is a u32.  [Deparser] is a one-field
       record, so extraction erases it to the emit list. */
    char *deparser =
        xsprintf("(DeparserModule %d (Coq_cons (EmitOpConstructor %d 32) Coq_nil))",
                 MOD_DEPARSER, H_REG(0));

    StrVec all;
    sv_init(&all);
    sv_push(&all, parser);
    for (int i = 0; i < modules.n; i++) sv_push(&all, xsprintf("%s", modules.v[i]));
    sv_push(&all, deparser);

    StrVec edges;
    sv_init(&edges);
    sv_push(&edges, xsprintf("(%d %d)", MOD_PARSER, MOD_FIRST_XFRM));
    for (int m = MOD_FIRST_XFRM; m + 1 < next_mod; m++)
        sv_push(&edges, xsprintf("(%d %d)", m, m + 1));
    sv_push(&edges, xsprintf("(%d %d)", next_mod - 1, MOD_DEPARSER));

    /* Regions: ctx, the packet, and one per declared map.  The checker
       refuses to compare two programs whose declarations differ, and the two
       objects declare the same maps because they come from one source. */
    StrVec regions;
    sv_init(&regions);
    sv_push(&regions, xsprintf("((mr_id %d) (mr_len %d))",
                               REGION_CTX, ctx_layout->len));
    sv_push(&regions, xsprintf("((mr_id %d) (mr_len %d))", REGION_PKT, PKT_LEN));
    for (int i = 0; i < nmaps; i++)
        sv_push(&regions, xsprintf("((mr_id %d) (mr_len %d))",
                                   map_region(i), map_tbl[i].len));

    fprintf(f, "(GeneralCaracaraProgramDef 0\n");
    for (int i = 0; i < nmaps; i++)
        fprintf(f, "  ; region %d = map %s (key %u, value %u, %d of %u slots)\n",
                map_region(i), map_tbl[i].name, map_tbl[i].key_size,
                map_tbl[i].value_size, map_tbl[i].nslots, map_tbl[i].max_entries);
    fprintf(f, "  %s\n", sv_to_coq_list(&regions));
    fprintf(f, "  ((net_modules %s)\n", sv_to_coq_list(&all));
    fprintf(f, "   (net_edges (");
    for (int i = 0; i < edges.n; i++) fprintf(f, "%s%s", i ? " " : "", edges.v[i]);
    fprintf(f, "))\n");
    sv_free(&edges);
    fprintf(f, "   (start_module %d)))\n", MOD_PARSER);
}

/* ── ELF ────────────────────────────────────────────────────────────── */

/*
 * Fill in insn_map_idx from the relocations that apply to section `sec`.  A
 * map reference is an R_BPF_64_64 against a symbol that names a map, sitting
 * on the LD_IMM64 that loads the map address.
 */
static void load_map_relocs(void *data, Elf64_Shdr *shdr, int nsec, int sec,
                            const Elf64_Sym *syms, size_t nsyms,
                            const char *strtab, size_t ninsns) {
    for (int i = 0; i < nsec; i++) {
        if (shdr[i].sh_type != SHT_REL && shdr[i].sh_type != SHT_RELA) continue;
        if ((int)shdr[i].sh_info != sec) continue;

        int is_rela = shdr[i].sh_type == SHT_RELA;
        size_t esz = is_rela ? sizeof(Elf64_Rela) : sizeof(Elf64_Rel);
        size_t n = shdr[i].sh_size / esz;
        char *base = (char *)data + shdr[i].sh_offset;

        for (size_t k = 0; k < n; k++) {
            Elf64_Rel *r = (Elf64_Rel *)(base + k * esz);
            if (ELF64_R_TYPE(r->r_info) != R_BPF_64_64) continue;
            uint32_t si = ELF64_R_SYM(r->r_info);
            if (si >= nsyms) continue;
            int m = find_map(strtab + syms[si].st_name);
            if (m < 0) continue;
            size_t idx = r->r_offset / sizeof(struct bpf_insn);
            if (idx < ninsns) insn_map_idx[idx] = m;
        }
    }
}

static int run(const char *filename) {
    int fd = open(filename, O_RDONLY);
    if (fd < 0) { perror("open"); return -1; }

    struct stat st;
    if (fstat(fd, &st) < 0) { perror("fstat"); close(fd); return -1; }

    void *data = malloc((size_t)st.st_size);
    if (!data) { perror("malloc"); close(fd); return -1; }
    if (read(fd, data, (size_t)st.st_size) != st.st_size) {
        perror("read"); free(data); close(fd); return -1;
    }
    close(fd);

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)data;
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "bpf_to_ir: not an ELF file\n");
        free(data);
        return -1;
    }

    Elf64_Shdr *shdr = (Elf64_Shdr *)((char *)data + ehdr->e_shoff);
    char *shstrtab = (char *)data + shdr[ehdr->e_shstrndx].sh_offset;

    /* Symbol table, needed to name the legacy `maps` entries and to resolve
       the map relocations on the program section. */
    Elf64_Sym *syms = NULL;
    size_t nsyms = 0;
    char *strtab = NULL;
    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (shdr[i].sh_type != SHT_SYMTAB) continue;
        syms = (Elf64_Sym *)((char *)data + shdr[i].sh_offset);
        nsyms = shdr[i].sh_size / sizeof(Elf64_Sym);
        if (shdr[i].sh_link < ehdr->e_shnum)
            strtab = (char *)data + shdr[shdr[i].sh_link].sh_offset;
        break;
    }

    /* Maps, from whichever declaration style the object uses. */
    for (int i = 0; i < ehdr->e_shnum; i++) {
        char *name = shstrtab + shdr[i].sh_name;
        if (shdr[i].sh_size == 0) continue;
        if (!strcmp(name, "maps") && syms && strtab)
            discover_legacy_maps((char *)data + shdr[i].sh_offset,
                                 shdr[i].sh_size, i, syms, nsyms, strtab);
        else if (!strcmp(name, ".BTF"))
            discover_btf_maps((char *)data + shdr[i].sh_offset, shdr[i].sh_size);
    }
    qsort(map_tbl, (size_t)nmaps, sizeof(MapInfo), map_name_cmp);

    for (int i = 0; i < ehdr->e_shnum; i++) {
        char *name = shstrtab + shdr[i].sh_name;
        if (shdr[i].sh_size == 0) continue;
        if (!(shdr[i].sh_flags & SHF_EXECINSTR) &&
            !strstr(name, "text") && !strstr(name, "xdp")) continue;

        ctx_layout = ctx_override ? ctx_override : ctx_layout_for(name);
        if (!ctx_layout) {
            fprintf(stderr, "bpf_to_ir: section %s: no context layout is known "
                            "for this program type; the ctx region would be the "
                            "wrong size and every field access an overrun.  "
                            "Pass --ctx=xdp_md or --ctx=__sk_buff to say which "
                            "it is.\n", name);
            free(data);
            return -1;
        }

        struct bpf_insn *insns = (struct bpf_insn *)((char *)data + shdr[i].sh_offset);
        size_t num = shdr[i].sh_size / sizeof(struct bpf_insn);
        if (num > MAX_INSNS) {
            fprintf(stderr, "bpf_to_ir: section %s has %zu instructions (max %d)\n",
                    name, num, MAX_INSNS);
            free(data);
            return -1;
        }

        for (size_t k = 0; k <= MAX_INSNS; k++) insn_map_idx[k] = -1;
        if (syms && strtab)
            load_map_relocs(data, shdr, ehdr->e_shnum, i, syms, nsyms, strtab, num);

        sv_init(&modules);
        translate_program(insns, num);
        emit_program(stdout);
        sv_free(&modules);
        free(data);
        return 0;
    }

    fprintf(stderr, "bpf_to_ir: no executable section found\n");
    free(data);
    return -1;
}

static void usage(const char *prog) {
    fprintf(stderr, "usage: %s [--ctx=xdp_md|__sk_buff] <bpf_object_file>\n",
            prog);
    fprintf(stderr, "Writes a Caracara GeneralCaracaraProgram s-expression "
                    "to stdout.\n");
    fprintf(stderr, "  --ctx=NAME  which struct the program's context is, for "
                    "objects whose\n              section name does not say "
                    "(default: inferred from it).\n");
}

int main(int argc, char **argv) {
    const char *file = NULL;
    for (int i = 1; i < argc; i++) {
        if (!strncmp(argv[i], "--ctx=", 6)) {
            ctx_override = ctx_layout_by_name(argv[i] + 6);
            if (!ctx_override) {
                fprintf(stderr, "bpf_to_ir: unknown context '%s'\n", argv[i] + 6);
                return 1;
            }
        } else if (!file) {
            file = argv[i];
        } else {
            usage(argv[0]);
            return 1;
        }
    }
    if (!file) { usage(argv[0]); return 1; }
    if (run(file) != 0) return 1;
    if (had_error) {
        fprintf(stderr, "bpf_to_ir: translation is incomplete; "
                        "the output does not faithfully model the input\n");
        return 2;
    }
    return 0;
}
