#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include "elf.h"
#include "bpf.h"

// Structure to hold function information
struct func_info {
    char *name;
    uint64_t offset;  // offset in bytes from start of section
    uint64_t size;    // size in bytes
};

int compare_funcs(const void *a, const void *b) {
    const struct func_info *fa = (const struct func_info *)a;
    const struct func_info *fb = (const struct func_info *)b;
    if (fa->offset < fb->offset) return -1;
    if (fa->offset > fb->offset) return 1;
    return 0;
}

int dump_bpf_from_file(const char *filename) {
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return -1;
    }
    
    struct stat st;
    if (fstat(fd, &st) < 0) {
        perror("fstat");
        close(fd);
        return -1;
    }
    
    void *data = malloc(st.st_size);
    if (!data) {
        perror("malloc");
        close(fd);
        return -1;
    }
    
    if (read(fd, data, st.st_size) != st.st_size) {
        perror("read");
        free(data);
        close(fd);
        return -1;
    }
    close(fd);
    
    // Check if it's an ELF file
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)data;
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "Not an ELF file\n");
        free(data);
        return -1;
    }
    
    printf("ELF file: %s\n", filename);
    printf("Section headers: %d\n", ehdr->e_shnum);
    
    // Get section header table
    Elf64_Shdr *shdr = (Elf64_Shdr *)((char *)data + ehdr->e_shoff);
    
    // Get string table for section names
    Elf64_Shdr *shstrtab_shdr = &shdr[ehdr->e_shstrndx];
    char *shstrtab = (char *)data + shstrtab_shdr->sh_offset;
    
    // Find symbol table and its string table
    Elf64_Shdr *symtab_shdr = NULL;
    char *strtab = NULL;
    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (shdr[i].sh_type == SHT_SYMTAB) {
            symtab_shdr = &shdr[i];
            // Symbol string table is linked
            strtab = (char *)data + shdr[symtab_shdr->sh_link].sh_offset;
            break;
        }
    }
    
    // Find and dump BPF code sections
    for (int i = 0; i < ehdr->e_shnum; i++) {
        char *name = shstrtab + shdr[i].sh_name;
        
        // Look for typical BPF section names or executable sections
        if (shdr[i].sh_size > 0 && 
            (shdr[i].sh_flags & SHF_EXECINSTR ||
             strstr(name, "text") != NULL ||
             strstr(name, "prog") != NULL ||
             strstr(name, "classifier") != NULL ||
             strstr(name, "kprobe") != NULL ||
             strstr(name, "tracepoint") != NULL)) {
            
            printf("\n=== Section: %s (offset=0x%llx, size=%lld bytes) ===\n",
                   name, shdr[i].sh_offset, shdr[i].sh_size);
            
            // Extract functions for this section from symbol table
            struct func_info *funcs = NULL;
            int num_funcs = 0;
            
            if (symtab_shdr && strtab) {
                Elf64_Sym *syms = (Elf64_Sym *)((char *)data + symtab_shdr->sh_offset);
                int num_syms = symtab_shdr->sh_size / sizeof(Elf64_Sym);
                
                // Count functions in this section
                for (int j = 0; j < num_syms; j++) {
                    if (ELF64_ST_TYPE(syms[j].st_info) == STT_FUNC && 
                        syms[j].st_shndx == i) {
                        num_funcs++;
                    }
                }
                
                if (num_funcs > 0) {
                    funcs = malloc(num_funcs * sizeof(struct func_info));
                    int func_idx = 0;
                    
                    for (int j = 0; j < num_syms; j++) {
                        if (ELF64_ST_TYPE(syms[j].st_info) == STT_FUNC && 
                            syms[j].st_shndx == i) {
                            funcs[func_idx].name = strtab + syms[j].st_name;
                            funcs[func_idx].offset = syms[j].st_value;
                            funcs[func_idx].size = syms[j].st_size;
                            func_idx++;
                        }
                    }
                    
                    // Sort by offset
                    qsort(funcs, num_funcs, sizeof(struct func_info), compare_funcs);
                    
                    printf("Functions found: %d\n", num_funcs);
                    for (int j = 0; j < num_funcs; j++) {
                        printf("  - %s (offset=%llu, size=%llu bytes, %llu insns)\n",
                               funcs[j].name, funcs[j].offset, funcs[j].size,
                               funcs[j].size / sizeof(struct bpf_insn));
                    }
                }
            }
            
            struct bpf_insn *insns = (struct bpf_insn *)((char *)data + shdr[i].sh_offset);
            size_t num_insns = shdr[i].sh_size / sizeof(struct bpf_insn);
            
            printf("Number of instructions: %zu\n\n", num_insns);
            
            int current_func = 0;
            for (size_t j = 0; j < num_insns; j++) {
                // Check if we're starting a new function
                if (funcs && current_func < num_funcs) {
                    size_t byte_offset = j * sizeof(struct bpf_insn);
                    if (byte_offset == funcs[current_func].offset) {
                        printf("\n--- Function: %s ---\n", funcs[current_func].name);
                        current_func++;
                    }
                }
                
                int skip = dump_bpf_insn(&insns[j], j);
                
                // If this was LD_IMM64, the next instruction is the upper 32 bits
                if (skip && j + 1 < num_insns) {
                    j++;  // Skip next instruction
                    uint64_t full_imm = ((uint64_t)(uint32_t)insns[j].imm << 32) | 
                                        (uint64_t)(uint32_t)insns[j-1].imm;
                    printf("[%4zu]   -> (upper 32 bits: 0x%x) Full 64-bit value: 0x%llx\n",
                           j, insns[j].imm, full_imm);
                }
            }
            
            if (funcs) {
                free(funcs);
            }
        }
    }
    
    free(data);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <bpf_object_file>\n", argv[0]);
        return 1;
    }
    
    return dump_bpf_from_file(argv[1]);
}
