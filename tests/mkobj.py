"""Build a minimal BPF object file from a list of instructions.

Lets a test exercise opcode forms clang will not emit -- it canonicalises
JSLE into JSGT with swapped arms, turns division by a constant into a
multiply-high, and never produces JSET from ordinary C.  Those are precisely
the forms that go through emit_condition's swap logic and the synthesized
operators, so they need coverage that does not depend on a compiler's mood.
"""

import struct

_EHDR = "<16sHHIQQQIHHHHHH"
_SHDR = "<IIQQQQIIQQ"
EM_BPF = 247


def insn(code, dst=0, src=0, off=0, imm=0):
    return struct.pack("<BBhi", code, (dst & 0xf) | ((src & 0xf) << 4), off, imm)


def build(insns, secname="xdp"):
    """insns: a list of 8-byte instruction blobs (or one concatenated blob)."""
    text = b"".join(insns) if isinstance(insns, (list, tuple)) else insns

    names = b"\0" + secname.encode() + b"\0" + b".shstrtab\0"
    off_sec = 1
    off_str = 1 + len(secname) + 1

    ehdr_size = struct.calcsize(_EHDR)
    text_off = ehdr_size
    str_off = text_off + len(text)
    sh_off = (str_off + len(names) + 7) & ~7

    shdrs = b""
    # 0: null
    shdrs += struct.pack(_SHDR, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    # 1: the program section -- PROGBITS, ALLOC|EXECINSTR
    shdrs += struct.pack(_SHDR, off_sec, 1, 0x2 | 0x4, 0,
                         text_off, len(text), 0, 0, 8, 0)
    # 2: .shstrtab
    shdrs += struct.pack(_SHDR, off_str, 3, 0, 0, str_off, len(names), 0, 0, 1, 0)

    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8
    ehdr = struct.pack(_EHDR, ident, 1, EM_BPF, 1, 0, 0, sh_off, 0,
                       ehdr_size, 0, 0, 64, 3, 2)

    blob = bytearray(ehdr + text + names)
    blob += b"\0" * (sh_off - len(blob))
    blob += shdrs
    return bytes(blob)
