"""Guarded SF2 camera v1.43 Q/E yaw 60% -> 100% patch, v1.0.
Pure bytes API; never reads/writes an executable or installs/launches a game.
Use build(data, expected_sha256=<integrator's locked input digest>).
Returns (patched_bytes, changed_file_offsets). Rejects repeat application.
The native Q/E XMM1 loads precede the common 549D8D orbit entry F6F000;
selected path calls 54ABB0, unselected path consumes the same saved XMM1.
"""
import hashlib
import struct

VERSION = "1.0"
BASELINE_SHA256 = "76c45a638a75618349ab039432b6f69bb02a4b03cea5da18afa675cb00951db1"
ORBIT_SHA256 = "3a4e97bc84ebe8a22039d091674462e5b7670a243c5333a812b42fdcd9a7bbc3"
PATCHES = (
    (0x549D37, bytes.fromhex("f30f100db4b5ba00"), bytes.fromhex("f30f100dfcb7ba00")),
    (0x549D70, bytes.fromhex("f30f100d54d1ba00"), bytes.fromhex("f30f100d84d1ba00")),
)
PAN_GUARDS = (
    (0x549C91, "f30f100db4b5ba00"), (0x549CB5, "f30f100d54d1ba00"),
    (0x549CE1, "f30f101554d1ba00"), (0x549D05, "f30f1015b4b5ba00"),
    (0x549CBD, "6a000f57d2e8b90b0000"), (0x549D0D, "6a000f57c9e8690b0000"),
)

def offset(data, va):
    if data[:2] != b"MZ":
        raise ValueError("Not a PE image")
    pe = struct.unpack_from("<I", data, 60)[0]
    if data[pe:pe+4] != b"PE\0\0" or struct.unpack_from("<H", data, pe+4)[0] != 0x14c:
        raise ValueError("Not an x86 PE image")
    opt = pe + 24
    if struct.unpack_from("<H", data, opt)[0] != 0x10b or struct.unpack_from("<I", data, opt+28)[0] != 0x400000:
        raise ValueError("Unsupported image layout")
    table = opt + struct.unpack_from("<H", data, pe+20)[0]
    for i in range(struct.unpack_from("<H", data, pe+6)[0]):
        rva, size, raw = struct.unpack_from("<III", data, table+40*i+12)
        if rva <= va-0x400000 < rva+size:
            result = raw+va-0x400000-rva
            if result >= len(data):
                break
            return result
    raise ValueError("Address is not file backed")

def build(data, expected_sha256=BASELINE_SHA256):
    data = bytes(data)
    if hashlib.sha256(data).hexdigest() != expected_sha256:
        raise ValueError("Input SHA256 mismatch")
    def require(va, wanted):
        pos = offset(data, va)
        if data[pos:pos+len(wanted)] != wanted:
            raise ValueError(f"Context mismatch at {va:#x}")
        return pos
    for va, raw in PAN_GUARDS:
        require(va, bytes.fromhex(raw))
    require(0x549D8D, bytes.fromhex("e86e52a200"))
    for va, value in ((0xBAB5B4, .6), (0xBAD154, -.6), (0xBAB7FC, 1.), (0xBAD184, -1.)):
        require(va, struct.pack("<f", value))
    start = offset(data, 0xF6F000)
    if offset(data, 0xF72FFF) != start+0x3fff or hashlib.sha256(data[start:start+0x4000]).hexdigest() != ORBIT_SHA256:
        raise ValueError("Native orbit payload differs from camera v1.43")
    edits = [(require(va, old), old, new) for va, old, new in PATCHES]
    patched = bytearray(data)
    expected = set()
    for pos, old, new in edits:
        patched[pos:pos+len(old)] = new
        expected.update(pos+i for i, (a,b) in enumerate(zip(old,new)) if a != b)
    changed = [i for i,(a,b) in enumerate(zip(data,patched)) if a != b]
    if len(patched) != len(data) or set(changed) != expected:
        raise ValueError("Unexpected patch extent")
    return bytes(patched), changed
