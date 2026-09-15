"""Enough BTF to size a map.

Modern maps carry their key/value sizes ONLY here: the `.maps` section itself
is a block of zeroed pointers, so an object built without `-g` cannot be
sized at all.

The walk is the delicate part.  Each type record is a 12-byte header followed
by kind-specific data whose length depends on the kind, and the walk advances
by that length -- so a wrong entry in `_extra` does not produce one wrong
type, it desynchronises every type after it.
"""

import struct

MAGIC = 0xEB9F

(KIND_INT, KIND_PTR, KIND_ARRAY, KIND_STRUCT, KIND_UNION, KIND_ENUM,
 KIND_FWD, KIND_TYPEDEF, KIND_VOLATILE, KIND_CONST, KIND_RESTRICT,
 KIND_FUNC, KIND_FUNC_PROTO, KIND_VAR, KIND_DATASEC, KIND_FLOAT,
 KIND_DECL_TAG, KIND_TYPE_TAG, KIND_ENUM64) = range(1, 20)

_HDR = "<HBBIIIII"      # magic, version, flags, hdr_len, type_off/len, str_off/len
_TYPE = "<III"          # name_off, info, size-or-type
_MEMBER = 12            # name_off, type, offset
_ARRAY = 12             # type, index_type, nelems
_VARSEC = 12            # type, offset, size

_QUALIFIERS = (KIND_TYPEDEF, KIND_VOLATILE, KIND_CONST, KIND_RESTRICT,
               KIND_TYPE_TAG)


def _kind(info): return (info >> 24) & 0x1f
def _vlen(info): return info & 0xffff


class BtfError(Exception):
    pass


class Btf:
    """The `.BTF` section, indexed by type id.  Id 0 is void, so `types[0]`
    is a placeholder and real ids start at 1."""

    def __init__(self, blob):
        if len(blob) < struct.calcsize(_HDR):
            raise BtfError("section is shorter than a BTF header")
        (magic, _ver, _flags, hdr_len,
         type_off, type_len, str_off, str_len) = struct.unpack_from(_HDR, blob, 0)
        if magic != MAGIC:
            raise BtfError("magic is 0x%x, not 0x%x (big-endian object?)"
                           % (magic, MAGIC))
        if (hdr_len + type_off + type_len > len(blob)
                or hdr_len + str_off + str_len > len(blob)):
            raise BtfError("section is truncated")

        self._strs = blob[hdr_len + str_off: hdr_len + str_off + str_len]
        types_blob = blob[hdr_len + type_off: hdr_len + type_off + type_len]

        # (name_off, info, size_or_type, payload) per id; index 0 is void.
        self.types = [None]
        pos = 0
        while pos + 12 <= len(types_blob):
            name_off, info, sz = struct.unpack_from(_TYPE, types_blob, pos)
            extra = self._extra(info)
            if pos + 12 + extra > len(types_blob):
                break
            self.types.append((name_off, info, sz,
                               types_blob[pos + 12: pos + 12 + extra]))
            pos += 12 + extra

    @staticmethod
    def _extra(info):
        """Bytes of kind-specific data following the 12-byte header."""
        k, vlen = _kind(info), _vlen(info)
        return {
            KIND_INT: 4,
            KIND_ARRAY: _ARRAY,
            KIND_STRUCT: vlen * _MEMBER,
            KIND_UNION: vlen * _MEMBER,
            KIND_ENUM: vlen * 8,
            KIND_FUNC_PROTO: vlen * 8,
            KIND_VAR: 4,
            KIND_DATASEC: vlen * _VARSEC,
            KIND_DECL_TAG: 4,
            KIND_ENUM64: vlen * 12,
        }.get(k, 0)

    def name(self, off):
        if off >= len(self._strs):
            return ""
        end = self._strs.find(b"\0", off)
        return self._strs[off:end if end >= 0 else len(self._strs)].decode(
            "utf-8", "replace")

    def get(self, tid):
        return self.types[tid] if 0 < tid < len(self.types) else None

    def strip(self, tid):
        """Follow typedefs and qualifiers to the underlying type."""
        for _ in range(32):
            t = self.get(tid)
            if t is None:
                return None
            if _kind(t[1]) in _QUALIFIERS:
                tid = t[2]          # the union's `type` arm
                continue
            return t
        return None

    def size_of(self, tid):
        t = self.strip(tid)
        if t is None:
            return 0
        k = _kind(t[1])
        if k in (KIND_INT, KIND_STRUCT, KIND_UNION, KIND_ENUM, KIND_ENUM64,
                 KIND_FLOAT, KIND_DATASEC):
            return t[2]
        if k == KIND_PTR:
            return 8
        if k == KIND_ARRAY:
            elem, _idx, nelems = struct.unpack_from("<III", t[3], 0)
            return nelems * self.size_of(elem)
        return 0

    def uint_value(self, tid):
        """`__uint(name, val)` is `int (*name)[val]`: the value is the array
        length behind the pointer."""
        p = self.strip(tid)
        if p is None or _kind(p[1]) != KIND_PTR:
            return 0
        a = self.strip(p[2])
        if a is None or _kind(a[1]) != KIND_ARRAY:
            return 0
        return struct.unpack_from("<III", a[3], 0)[2]

    def type_size(self, tid):
        """`__type(name, val)` is `typeof(val) *name`: the size of the
        pointee."""
        p = self.strip(tid)
        if p is None or _kind(p[1]) != KIND_PTR:
            return 0
        return self.size_of(p[2])

    def datasec_vars(self, secname):
        """(variable name, its type id) for each member of a DATASEC."""
        for t in self.types[1:]:
            if _kind(t[1]) != KIND_DATASEC or self.name(t[0]) != secname:
                continue
            out = []
            for i in range(_vlen(t[1])):
                tid = struct.unpack_from("<III", t[3], i * _VARSEC)[0]
                var = self.get(tid)
                if var is None or _kind(var[1]) != KIND_VAR:
                    continue
                out.append((self.name(var[0]), var[2]))
            return out
        return []

    def struct_members(self, tid):
        """(member name, its type id) for a STRUCT, or None if not one."""
        st = self.strip(tid)
        if st is None or _kind(st[1]) != KIND_STRUCT:
            return None
        return [(self.name(struct.unpack_from("<III", st[3], i * _MEMBER)[0]),
                 struct.unpack_from("<III", st[3], i * _MEMBER)[1])
                for i in range(_vlen(st[1]))]
