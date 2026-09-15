"""Just enough 64-bit little-endian ELF to find a BPF object's program
sections, symbols and relocations.

The C version cast pointers into the mapped file; here every field is named
in a struct format string, so a wrong offset is a wrong format character
rather than a silent misread.
"""

import struct
from dataclasses import dataclass

ELFMAG = b"\x7fELF"

SHT_PROGBITS, SHT_SYMTAB, SHT_STRTAB, SHT_RELA, SHT_REL = 1, 2, 3, 4, 9
SHF_EXECINSTR = 0x4
STT_SECTION = 3

# The only BPF relocation the translator reads: a 64-bit immediate patched
# with a map address.  libbpf rewrites the LD_IMM64's src_reg to
# BPF_PSEUDO_MAP_FD at load time, so the object file carries no other marker.
R_BPF_64_64 = 1

_EHDR = "<16sHHIQQQIHHHHHH"          # e_ident .. e_shstrndx
_SHDR = "<IIQQQQIIQQ"                # 64 bytes
_SYM  = "<IBBHQQ"                    # 24 bytes
_REL  = "<QQ"                        # 16 bytes
_RELA = "<QQq"                       # 24 bytes


def _cstr(blob, off):
    if off >= len(blob):
        return ""
    end = blob.find(b"\0", off)
    return blob[off:end if end >= 0 else len(blob)].decode("utf-8", "replace")


@dataclass
class Section:
    index: int
    name: str
    type: int
    flags: int
    offset: int
    size: int
    link: int
    info: int
    data: bytes


@dataclass
class Sym:
    name: str
    info: int
    shndx: int
    value: int
    size: int

    @property
    def type(self):
        return self.info & 0xf


class Elf:
    """A parsed object.  `sections` is indexed by section number, so section
    links and a symbol's st_shndx can be used directly."""

    def __init__(self, blob):
        if blob[:4] != ELFMAG:
            raise ValueError("not an ELF file")
        (_ident, _type, _machine, _ver, _entry, _phoff, shoff, _flags,
         _ehsize, _phentsize, _phnum, shentsize, shnum, shstrndx
         ) = struct.unpack_from(_EHDR, blob, 0)
        self.blob = blob

        raw = []
        for i in range(shnum):
            (nm, ty, fl, _addr, off, sz, link, info, _al, _es) = \
                struct.unpack_from(_SHDR, blob, shoff + i * shentsize)
            raw.append((i, nm, ty, fl, off, sz, link, info))

        shstr = blob[raw[shstrndx][4]: raw[shstrndx][4] + raw[shstrndx][5]]
        self.sections = [
            Section(i, _cstr(shstr, nm), ty, fl, off, sz, link, info,
                    blob[off:off + sz] if ty != 8 else b"")   # 8 = SHT_NOBITS
            for (i, nm, ty, fl, off, sz, link, info) in raw]

        self.symbols = []
        self._symstr = b""
        for s in self.sections:
            if s.type != SHT_SYMTAB:
                continue
            self._symstr = self.sections[s.link].data if s.link < len(self.sections) else b""
            for off in range(0, len(s.data), 24):
                (nm, info, _other, shndx, val, sz) = struct.unpack_from(_SYM, s.data, off)
                self.symbols.append(Sym(_cstr(self._symstr, nm), info, shndx, val, sz))
            break

    def section(self, name):
        for s in self.sections:
            if s.name == name and s.size:
                return s
        return None

    def relocations(self, target_index):
        """(offset, sym_index, type) for every relocation applying to a
        section.  REL and RELA are both accepted; BPF emits REL."""
        out = []
        for s in self.sections:
            if s.type not in (SHT_REL, SHT_RELA) or s.info != target_index:
                continue
            fmt, esz = (_RELA, 24) if s.type == SHT_RELA else (_REL, 16)
            for off in range(0, len(s.data) - esz + 1, esz):
                vals = struct.unpack_from(fmt, s.data, off)
                r_offset, r_info = vals[0], vals[1]
                out.append((r_offset, r_info >> 32, r_info & 0xffffffff))
        return out
