"""Compose reviewed SF2 HUD and text components v1.10. No install or game run."""
import argparse
import hashlib
import importlib.util
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from native_paths import SF2_ORIGINAL, COLDWAR_ORIGINAL, NORMANDY_IMAGE, INTERMEDIATES, capstone_path

import struct

ROOT = Path(__file__).resolve().parent.parent
CAMERA = INTERMEDIATES / 'SF2_NativeOrbit_Mmb_Wheel_Pan60_Yaw60_v1.43.exe'
CAMERA_HASH = '76c45a638a75618349ab039432b6f69bb02a4b03cea5da18afa675cb00951db1'
ORIGINAL = SF2_ORIGINAL
ORIGINAL_HASH = 'b3f3cea9f6e94f7b75746b1f2cee9b5d00efcedc0f440d301630be1797a07aa4'
BRIEF_VA = 0xF74000
BRIEF_CAPACITY = 0x1000
TEXT_DATA_VA = 0xF7C100
TEXT_DATA_CAPACITY = 16


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_offset(data, va, length, required_flags=0):
    if data[:2] != b'MZ':
        raise ValueError('Not a PE image')
    pe = struct.unpack_from('<I', data, 60)[0]
    if data[pe:pe+4] != b'PE\0\0' or struct.unpack_from('<H', data, pe+4)[0] != 0x14c:
        raise ValueError('Not an x86 PE image')
    opt = pe + 24
    base = struct.unpack_from('<I', data, opt+28)[0]
    table = opt + struct.unpack_from('<H', data, pe+20)[0]
    for i in range(struct.unpack_from('<H', data, pe+6)[0]):
        entry = table+i*40
        rva, size, raw = struct.unpack_from('<III', data, entry+12)
        if rva <= va-base and va-base+length <= rva+size:
            flags = struct.unpack_from('<I', data, entry+36)[0]
            if flags & required_flags != required_flags:
                raise ValueError('Component slot has incompatible section permissions')
            offset = raw + va-base-rva
            if offset+length > len(data):
                raise ValueError('Truncated file-backed section')
            return offset
    raise ValueError(f'Range is not file-backed: {va:#x}, {length}')


def compose(hud, module):
    original = ORIGINAL.read_bytes()
    camera = CAMERA.read_bytes()
    if digest(original) != ORIGINAL_HASH or digest(camera) != CAMERA_HASH:
        raise ValueError('Known source identity changed')
    result = module.build(original, BRIEF_VA)
    if result['blob_va'] != BRIEF_VA:
        raise ValueError('Text component requested a different executable address')
    blob = result['blob']
    patches = result['patches']
    if not isinstance(blob, bytes) or not 0 < len(blob) <= BRIEF_CAPACITY:
        raise ValueError('Briefing code does not fit the reserved executable slot')
    slot = file_offset(hud, BRIEF_VA, BRIEF_CAPACITY, 0x60000000)
    if hud[slot:slot+BRIEF_CAPACITY] != b'\x90' * BRIEF_CAPACITY:
        raise ValueError('HUD component overlaps the reserved briefing slot')
    if 'data_va' in result or 'data_size' in result:
        if (result.get('data_va') != TEXT_DATA_VA or
                result.get('data_size') != TEXT_DATA_CAPACITY):
            raise ValueError('Text component requested an unreserved data range')
        for image in (camera, hud):
            data_slot = file_offset(image, TEXT_DATA_VA, TEXT_DATA_CAPACITY, 0xC0000000)
            if image[data_slot:data_slot+TEXT_DATA_CAPACITY] != bytes(TEXT_DATA_CAPACITY):
                raise ValueError('Text state overlaps existing component data')
    out = bytearray(hud)
    allowed = set(range(slot, slot+len(blob)))
    out[slot:slot+len(blob)] = blob
    for va, before, after in patches:
        if not isinstance(before, bytes) or not isinstance(after, bytes) or len(before) != len(after) or not before:
            raise ValueError('Invalid native patch record')
        off = file_offset(hud, va, len(before))
        base_off = file_offset(camera, va, len(before))
        if hud[off:off+len(before)] != before or camera[base_off:base_off+len(before)] != before:
            raise ValueError(f'Component overlap or unexpected source at {va:#x}')
        touched = set(range(off, off+len(before)))
        if touched & allowed:
            raise ValueError(f'Overlapping briefing patches at {va:#x}')
        allowed.update(touched)
        out[off:off+len(before)] = after
    if len(out) != len(hud) or any(a != b and i not in allowed for i, (a, b) in enumerate(zip(hud, out))):
        raise ValueError('Composition changed bytes outside the component boundary')
    return bytes(out), len(patches), len(blob)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hud', required=True, type=Path)
    parser.add_argument('--hud-sha256', required=True)
    parser.add_argument('--brief-module', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--yaw-module', type=Path)
    parser.add_argument('--wheel-module', type=Path)
    parser.add_argument('--orbit-module', type=Path)
    parser.add_argument('--mmb-module', type=Path)
    args = parser.parse_args()
    for path in filter(None, (args.hud, args.brief_module, args.output, args.yaw_module, args.wheel_module, args.orbit_module, args.mmb_module)):
        if not path.resolve().is_relative_to(ROOT.resolve()):
            raise ValueError('Component and output paths must remain inside the game workspace')
    hud = args.hud.read_bytes()
    if digest(hud) != args.hud_sha256.lower():
        raise ValueError('Reviewed HUD candidate identity changed')
    spec = importlib.util.spec_from_file_location('briefing_component', args.brief_module)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    payload, count, size = compose(hud, module)
    # Keep component reservations separate and reject changes outside each boundary.
    for label, source, va, capacity in (
            ('yaw', args.yaw_module, None, None),
            ('wheel', args.wheel_module, 0xF75000, 0x6000),
            ('orbit', args.orbit_module, None, None),
            ('mmb', args.mmb_module, None, None)):
        if source is None:
            continue
        spec = importlib.util.spec_from_file_location(label + '_component', source)
        component = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(component)
        before = payload
        if label == 'wheel':
            plan = component.build(ORIGINAL.read_bytes())
            payload = component.apply_sites(before, plan)
        else:
            payload, declared = component.build(before, expected_sha256=digest(before))
            actual = {i for i, (a, b) in enumerate(zip(before, payload)) if a != b}
            if actual != set(declared):
                raise ValueError(label + ' declared changed offsets do not match output')
        if len(payload) != len(before):
            raise ValueError(label + ' changed PE length')
        if label == 'yaw':
            allowed = set()
            for address in (0x549D37, 0x549D70):
                off = file_offset(before, address, 8)
                allowed.update(range(off, off+8))
        elif label == 'orbit':
            allowed = set()
            for address, length in ((0xF6F220, 16), (0xF73400, 0xC00)):
                off = file_offset(before, address, length, 0x60000000)
                allowed.update(range(off, off+length))
        elif label == 'mmb':
            allowed = set()
            # Only the private MMB call and its reserved wrapper may change.
            for address, length in ((0xF6B410, 5), (0xF6C800, 0x200)):
                off = file_offset(before, address, length, 0x60000000)
                allowed.update(range(off, off+length))
        else:
            off = file_offset(before, va, capacity, 0x60000000)
            allowed = set(range(off, off+capacity))
        changed = {i for i, (a, b) in enumerate(zip(before, payload)) if a != b}
        if not changed or changed - allowed:
            raise ValueError(label + ' changed bytes outside its owned component')
        print('COMPONENT', label, 'DIFF_BYTES', len(changed), 'SHA256', digest(payload))
    with args.output.open('xb') as stream:
        stream.write(payload)
    if args.output.read_bytes() != payload:
        raise ValueError('Composed candidate readback mismatch')
    print('OUTPUT', args.output)
    print('SHA256', digest(payload))
    print('BRIEFING_PATCHES', count, 'CODE_BYTES', size)
    print('runtime=NOT_RUN; installation unchanged')


if __name__ == '__main__':
    main()
