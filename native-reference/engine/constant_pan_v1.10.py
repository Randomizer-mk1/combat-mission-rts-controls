"""SF2 native constant keyboard pan and yaw sensitivity candidate v1.10.
Output-only builder. Does not install, launch, inject, or change configuration.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from native_paths import SF2_ORIGINAL, COLDWAR_ORIGINAL, NORMANDY_IMAGE, INTERMEDIATES, capstone_path


VERSION = "1.10"
SOURCE_HASH = "b3f3cea9f6e94f7b75746b1f2cee9b5d00efcedc0f440d301630be1797a07aa4"
SOURCE = SF2_ORIGINAL
CONSTANTS = {"1.0": (0x00BAB7FC, 0x00BAD184), "0.6": (0x00BAB5B4, 0x00BAD154)}
LOADS = (
    (0x00549C91, "f30f100dfcb7ba00", "pan", 0),
    (0x00549CB5, "f30f100d84d1ba00", "pan", 1),
    (0x00549CE1, "f30f101584d1ba00", "pan", 1),
    (0x00549D05, "f30f1015fcb7ba00", "pan", 0),
    (0x00549D37, "f30f100dfcb7ba00", "yaw", 0),
    (0x00549D70, "f30f100d84d1ba00", "yaw", 1),
)

def digest(data):
    return hashlib.sha256(data).hexdigest()

def file_offset(data, va):
    if data[:2] != b"MZ":
        raise ValueError("Not PE")
    pe = struct.unpack_from("<I", data, 0x3c)[0]
    if data[pe:pe+4] != b"PE\0\0" or struct.unpack_from("<H", data, pe+4)[0] != 0x14c:
        raise ValueError("Not x86 PE")
    opt = pe + 24
    if struct.unpack_from("<H", data, opt)[0] != 0x10b:
        raise ValueError("Not PE32")
    base = struct.unpack_from("<I", data, opt+28)[0]
    table = opt + struct.unpack_from("<H", data, pe+20)[0]
    for i in range(struct.unpack_from("<H", data, pe+6)[0]):
        _, rva, raw_size, raw_ptr = struct.unpack_from("<IIII", data, table+40*i+8)
        if rva <= va-base < rva+raw_size:
            return raw_ptr + va-base-rva
    raise ValueError("VA not file-backed")

def plan(pan, yaw):
    if pan not in CONSTANTS or yaw not in CONSTANTS:
        raise ValueError("Only 1.0 and 0.6 factors are supported")
    edits = [
        (0x00549CBD, bytes.fromhex("6a010f57d2e8b90b0000"), bytes.fromhex("6a000f57d2e8b90b0000")),
        (0x00549D0D, bytes.fromhex("6a010f57c9e8690b0000"), bytes.fromhex("6a000f57c9e8690b0000")),
    ]
    for va, hex_bytes, axis, sign in LOADS:
        before = bytes.fromhex(hex_bytes)
        factor = pan if axis == "pan" else yaw
        after = before[:4] + struct.pack("<I", CONSTANTS[factor][sign])
        edits.append((va, before, after))
    return edits

def reverse(data, pan, yaw):
    restored = bytearray(data)
    for va, before, after in plan(pan, yaw):
        off = file_offset(data, va)
        if data[off:off+len(after)] != after:
            raise ValueError(f"Candidate context mismatch at {va:#x}")
        restored[off:off+len(before)] = before
    if digest(restored) != SOURCE_HASH:
        raise ValueError("Restored baseline hash mismatch")
    return bytes(restored)

def build(data, pan="0.6", yaw="0.6"):
    if digest(data) != SOURCE_HASH:
        raise ValueError("Unsupported baseline hash")
    for factor, addresses in CONSTANTS.items():
        for sign, va in enumerate(addresses):
            off = file_offset(data, va)
            expected = struct.pack("<f", float(factor) * (-1 if sign else 1))
            if data[off:off+4] != expected:
                raise ValueError("Constant bytes differ")
    patched = bytearray(data)
    expected_diff = set()
    for va, before, after in plan(pan, yaw):
        off = file_offset(data, va)
        if data[off:off+len(before)] != before:
            raise ValueError(f"Original context mismatch at {va:#x}")
        patched[off:off+len(after)] = after
        expected_diff.update(off+i for i,(a,b) in enumerate(zip(before,after)) if a != b)
    actual = {i for i,(a,b) in enumerate(zip(data,patched)) if a != b}
    if len(data) != len(patched) or actual != expected_diff:
        raise ValueError("Unexpected full-file difference")
    result = bytes(patched)
    if reverse(result,pan,yaw) != data:
        raise ValueError("Byte reversal mismatch")
    return result, sorted(actual)

def stem(pan, yaw):
    labels={"1.0":"100", "0.6":"60"}
    return f"SF2_ConstantPan_Pan{labels[pan]}_Yaw{labels[yaw]}_v{VERSION}"

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pan", choices=CONSTANTS, default="0.6")
    parser.add_argument("--yaw", choices=CONSTANTS, default="0.6", help="Configured rotation keys only; native arrow-key rotation is unchanged")
    parser.add_argument("--restore-copy", action="store_true", help="Export original bytes from the candidate without requiring the original file; does not install")
    args=parser.parse_args()
    folder=Path(__file__).resolve().parent / "candidates"
    candidate=folder / (stem(args.pan,args.yaw)+".exe")
    if args.restore_copy:
        payload=reverse(candidate.read_bytes(),args.pan,args.yaw)
        output=folder / (stem(args.pan,args.yaw)+"_Restored.exe")
        offsets=[]
    else:
        payload,offsets=build(SOURCE.read_bytes(),args.pan,args.yaw)
        output=candidate
    folder.mkdir(exist_ok=True)
    with output.open("xb") as handle:
        handle.write(payload)
    if output.read_bytes()!=payload:
        raise IOError("Readback mismatch")
    print(json.dumps({"version":VERSION,"pan_factor":args.pan,"yaw_factor":args.yaw,
        "mode":"restore-copy" if args.restore_copy else "candidate", "output":str(output),
        "sha256":digest(payload),"changed_file_offsets":[hex(i) for i in offsets],
        "runtime":"NOT_RUN","installation":"NOT_PERFORMED"},ensure_ascii=True))

if __name__ == "__main__":
    main()
