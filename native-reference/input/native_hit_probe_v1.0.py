"""SF2 native hit-probe fragment v1.0, for the engine's offline patch builder.

Copies the actual 0x7919F0 native traversal, bypasses the vtable event callback,
and relocates three CALL rel32 instructions. Does not edit a PE, install, or run.
The two original eligibility predicates remain; their independent side effects
are not audited here. This suppresses event dispatch, not every possible write.
Usage from engine: code = build_probe(original_image_bytes, allocated_probe_va).
ECX=root UI object; original four stack arguments and RET 0x10 are retained.
Returns native hit object in EAX or zero. The caller must identify the battlefield
object separately; a nonzero hit alone is not proof of camera eligibility.
"""
import hashlib
import struct

VERSION = "1.0"
SOURCE_SHA256 = "b3f3cea9f6e94f7b75746b1f2cee9b5d00efcedc0f440d301630be1797a07aa4"
START, END = 0x7919F0, 0x791AFA
CALLS = ((0x791A07, 0x7920D0), (0x791A16, 0x792110), (0x791A9E, START))
SKIP, RETURN_HIT = 0x791AC2, 0x791AE8


def file_offset(data, va):
    if data[:2] != b"MZ":
        raise ValueError("MZ required")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe+4] != b"PE\0\0":
        raise ValueError("PE required")
    opt = pe + 24
    if struct.unpack_from("<H", data, opt)[0] != 0x10B:
        raise ValueError("PE32 required")
    base = struct.unpack_from("<I", data, opt+28)[0]
    table = opt + struct.unpack_from("<H", data, pe+20)[0]
    for i in range(struct.unpack_from("<H", data, pe+6)[0]):
        row = table + 40*i
        rva, size, raw = struct.unpack_from("<III", data, row+12)
        if rva <= va-base < rva+size:
            return raw + va-base-rva
    raise ValueError("VA not file-backed")


def build_probe(original, destination_va):
    if hashlib.sha256(original).hexdigest() != SOURCE_SHA256:
        raise ValueError("Only the preserved SF2 build 21967996 original is supported")
    if not isinstance(destination_va, int) or not 0 <= destination_va <= 0xFFFFFFFF-(END-START):
        raise ValueError("Invalid PE32 allocation address")
    off = file_offset(original, START)
    if file_offset(original, END-1) != off + END-START-1:
        raise ValueError("Noncontiguous code")
    code = bytearray(original[off:off+END-START])
    if code[:6] != bytes.fromhex("53 55 56 57 8b f9"):
        raise ValueError("Unexpected native prologue")
    if code[0xF5:0xF8] != bytes.fromhex("ff 52 14"):
        raise ValueError("Expected native dispatch callback is missing")
    for site, target in CALLS:
        pos = site-START
        if code[pos] != 0xE8 or site+5+struct.unpack_from("<i", code, pos+1)[0] != target:
            raise ValueError("Native CALL context mismatch")
        relocated_target = destination_va if target == START else target
        # rel32 is modulo 2^32 on x86. Same-image relocation preserves this delta.
        struct.pack_into("<I", code, pos+1, (relocated_target-(destination_va+pos+5)) & 0xFFFFFFFF)
    begin, end = SKIP-START, RETURN_HIT-START
    # Skip all argument pushes as well as the indirect event call; retain EDI
    # as the hit object and the original balanced epilogue / RET 16.
    code[begin:end] = b"\xEB" + bytes([end-begin-2]) + b"\x90"*(end-begin-2)
    if code[end:end+9] != bytes.fromhex("8b c7 5f 5e 5d 5b c2 10 00"):
        raise ValueError("Unexpected hit return ABI")
    return bytes(code)
