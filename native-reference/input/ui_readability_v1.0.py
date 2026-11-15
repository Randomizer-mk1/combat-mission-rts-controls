"""SF2 UI readability v1.0: guarded, output-only patches for coordinator integration.

The original 21967996 executable is the evidence source. The coordinator owns
PE allocation, installation and integration with controls/HUD patches.
build(original, destination_va) returns a 64-byte executable blob and explicit
(VA, original bytes, replacement bytes) patches. All jumps are image-relative;
the blob has no new absolute addresses or relocation requirements.

Briefing body/headings use the game's existing modern 12 AA font instead of
jv 11. Both stock cells are 15 pixels high. This is a modest readability change,
not high-DPI scaling. Native ViewTextWrap receives the replacement font before
wrapping; the page-height lookup uses that same font. No font object or asset is
modified. Existing page buttons, two columns and their hit rectangles remain.
"""

import hashlib
import struct

VERSION = "1.0"
SOURCE_SHA256 = "b3f3cea9f6e94f7b75746b1f2cee9b5d00efcedc0f440d301630be1797a07aa4"
BLOB_SIZE = 64
# Site, displaced instructions, replacement font load, retained instruction.
# The register already contains the native app object: no global font mutation.
BRIEFING = (
    (0x4D5D8B, "8b41488945cc", "8b81b4000000", "8945cc"),
    (0x4D5F7B, "8b40488b4004", "8b80b4000000", "8b4004"),
    (0x4D60DD, "8b40488945b0", "8b80b4000000", "8945b0"),
    (0x4D61E5, "8b40488945b4", "8b80b4000000", "8945b4"),
)


def image_info(data):
    if data[:2] != b"MZ":
        raise ValueError("Expected PE32 image")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    opt = pe + 24
    if data[pe:pe + 4] != b"PE\0\0" or struct.unpack_from("<H", data, opt)[0] != 0x10B:
        raise ValueError("Expected PE32 image")
    base = struct.unpack_from("<I", data, opt + 28)[0]
    size = struct.unpack_from("<I", data, opt + 56)[0]
    table = opt + struct.unpack_from("<H", data, pe + 20)[0]
    sections = [struct.unpack_from("<III", data, table + i * 40 + 12)
                for i in range(struct.unpack_from("<H", data, pe + 6)[0])]
    return base, size, sections


def offset(data, va, length=1):
    base, _, sections = image_info(data)
    for rva, raw_size, raw in sections:
        if rva <= va - base and va - base + length <= rva + raw_size:
            pos = raw + va - base - rva
            if pos + length <= len(data):
                return pos
    raise ValueError("Patch range is not file-backed")


def jump(source, target):
    return b"\xe9" + struct.pack("<I", (target - source - 5) & 0xFFFFFFFF)


def build(original, destination_va):
    if hashlib.sha256(original).hexdigest() != SOURCE_SHA256:
        raise ValueError("Unsupported original executable")
    base, size, _ = image_info(original)
    if (type(destination_va) is not int or destination_va % 16 or
            not base + size <= destination_va <= 0xFFFFFFFF - BLOB_SIZE):
        raise ValueError("Reserve 64 aligned executable bytes beyond the original image")
    blob = bytearray(b"\x90" * BLOB_SIZE)
    patches = []
    for i, (site, old_hex, load_hex, retained_hex) in enumerate(BRIEFING):
        old = bytes.fromhex(old_hex)
        pos = offset(original, site, len(old))
        if original[pos:pos + len(old)] != old:
            raise ValueError(f"Unexpected instructions at {site:#x}")
        entry = destination_va + i * 16
        code = bytes.fromhex(load_hex + retained_hex)
        code += jump(entry + len(code), site + len(old))
        if len(code) > 16:
            raise ValueError("Trampoline exceeds its allocation")
        blob[i * 16:i * 16 + len(code)] = code
        patches.append((site, old, jump(site, entry) + b"\x90"))
    return {"version": VERSION, "blob_va": destination_va,
            "blob": bytes(blob), "patches": patches}


def apply_sites(payload, plan):
    """Apply guarded sites only; the coordinator separately places plan['blob'].

    All guards are checked before any replacement. An unrelated existing patch
    is preserved; a conflict at an owned instruction is rejected. No file writes.
    """
    positions = []
    for va, old, new in plan["patches"]:
        if len(old) != len(new):
            raise ValueError("Patch length mismatch")
        pos = offset(payload, va, len(old))
        if payload[pos:pos + len(old)] != old:
            raise ValueError(f"Integration conflict at {va:#x}")
        positions.append((pos, new))
    result = bytearray(payload)
    for pos, new in positions:
        result[pos:pos + len(new)] = new
    return bytes(result)
