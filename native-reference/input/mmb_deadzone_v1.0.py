"""MMB-only two-pixel dead zone v1.0. No install or executable output.

The private MMB call passes adjusted coordinate copies to the unchanged native
camera routine. For |delta| > 2, add sign(delta)*(old_dead_zone-2). The native
15/20-pixel subtraction then produces sign(delta)*(|delta|-2), retaining its
speed divisor, saturation, pitch limits and camera validation. Inside +/-2,
coordinates are unchanged and remain inside the native dead zone.

Only the RTS-mode MMB active-path CALL is adjusted; other modes tail-call the
native routine with unchanged arguments. No common constants, UI callbacks,
keyboard controls, modal checks, frame timing or input queues are changed.
"""
import hashlib
import re
import struct
from pathlib import Path

VERSION = '1.0'
HERE = Path(__file__).resolve().parent
SITE = 0xF6B410
ENTRY = 0xF6C800
RESERVED_SIZE = 0x200
NATIVE = 0x54A700
NATIVE_SHA256 = '52e7a8ccc5168ce92668b2da081fd4b9404343fa8c93594f424fd7bf7499d161'
OLD_CALL = bytes.fromhex('e8ebf25dff')


def offset(payload, va, length=1):
    pe = struct.unpack_from('<I', payload, 0x3c)[0]
    if payload[pe:pe+4] != b'PE\0\0': raise ValueError('Invalid PE')
    opt = pe+24
    if struct.unpack_from('<H', payload, opt)[0] != 0x10b: raise ValueError('Expected PE32')
    base = struct.unpack_from('<I', payload, opt+28)[0]
    table = opt+struct.unpack_from('<H', payload, pe+20)[0]
    for i in range(struct.unpack_from('<H', payload, pe+6)[0]):
        rva, raw_size, raw = struct.unpack_from('<III', payload, table+i*40+12)
        delta = va-base-rva
        if 0 <= delta and delta+length <= raw_size and raw+delta+length <= len(payload):
            return raw+delta
    raise ValueError('Requested range is not file backed')


def generate():
    code = bytearray()
    rows, labels, fixes = [], {}, []
    def emit(text, data):
        rows.append((ENTRY+len(code), text, bytes.fromhex(data)))
        code.extend(bytes.fromhex(data))
    def label(name): labels[name] = ENTRY+len(code)
    def branch(op, target):
        prefix = {'JG': '0f8f', 'JL': '0f8c', 'JZ': '0f84', 'JNE': '0f85', 'JMP': 'e9', 'CALL': 'e8'}[op]
        fixes.append((len(rows), len(code), target))
        emit(op+' '+str(target), prefix+'00000000')
    emit('PUSHFD', '9c')
    emit('PUSH EAX', '50')
    # Same RTS mode value as the existing left-camera gate. Use a call/pop
    # image base, so no new absolute address needs a loader relocation.
    branch('CALL', 'base')
    return_va = ENTRY+len(code)
    label('base')
    emit('POP EAX', '58')
    emit(f'SUB EAX,{return_va-0x400000:#x}', '2d'+struct.pack('<I',return_va-0x400000).hex())
    emit('MOV EAX,dword ptr [EAX+0xa57b18]', '8b80187ba500')
    emit('TEST EAX,EAX', '85c0')
    branch('JZ', 'restore')
    emit('CMP dword ptr [EAX+0xa7c],1', '83b87c0a000001')
    branch('JNE', 'restore')
    # Saved flags/EAX add eight bytes: native x/y arguments are ESP+12/+16.
    for name, arg, anchor, adjustment in [('x',12,8,13), ('y',16,12,18)]:
        emit(f'MOV EAX,dword ptr [ESP+0x{arg:x}]', f'8b4424{arg:02x}')
        emit(f'SUB EAX,dword ptr [ECX+0x{anchor:x}]', f'2b41{anchor:02x}')
        emit('CMP EAX,2', '83f802')
        branch('JG', name+'_positive')
        emit('CMP EAX,-2', '83f8fe')
        branch('JL', name+'_negative')
        branch('JMP', name+'_done')
        label(name+'_positive')
        emit(f'ADD dword ptr [ESP+0x{arg:x}],{adjustment}', f'834424{arg:02x}{adjustment:02x}')
        branch('JMP', name+'_done')
        label(name+'_negative')
        emit(f'SUB dword ptr [ESP+0x{arg:x}],{adjustment}', f'836c24{arg:02x}{adjustment:02x}')
        label(name+'_done')
    label('restore')
    emit('POP EAX', '58')
    emit('POPFD', '9d')
    branch('JMP', NATIVE)
    for index, pos, target in fixes:
        va, text, raw = rows[index]
        dest = labels[target] if isinstance(target, str) else target
        data = raw[:-4]+struct.pack('<i', dest-va-len(raw))
        code[pos:pos+len(raw)] = data
        rows[index] = (va, text.split()[0]+f' {dest:#x}', data)
    assert len(code) <= RESERVED_SIZE
    return dict(version=VERSION, entry=ENTRY, blob=bytes(code), rows=rows, labels=labels)


def build(payload, expected_sha256):
    """Return (patched_bytes, actual_changed_offsets); never write a candidate."""
    if not isinstance(expected_sha256, str) or not re.fullmatch('[0-9a-f]{64}', expected_sha256):
        raise ValueError('An explicit lowercase input SHA-256 is required')
    if hashlib.sha256(payload).hexdigest() != expected_sha256:
        raise ValueError('Input SHA-256 mismatch')
    native = offset(payload, NATIVE, 0x172)
    if hashlib.sha256(payload[native:native+0x172]).hexdigest() != NATIVE_SHA256:
        raise ValueError('Native camera implementation changed')
    for va, expected in [(0xbad398,-20.0), (0xbacc50,20.0), (0xbad390,-15.0), (0xbacbf4,15.0), (0xbace94,400.0)]:
        if payload[offset(payload,va,4):offset(payload,va,4)+4] != struct.pack('<f',expected):
            raise ValueError('Native camera constants changed')
    site = offset(payload, SITE, 5)
    if payload[site:site+5] != OLD_CALL: raise ValueError('MMB call integration conflict')
    pos = offset(payload, ENTRY, RESERVED_SIZE)
    if payload[pos:pos+RESERVED_SIZE] != b'\x90'*RESERVED_SIZE:
        raise ValueError('MMB wrapper reservation is occupied')
    blob = generate()['blob']
    result = bytearray(payload)
    result[site:site+5] = b'\xe8'+struct.pack('<i', ENTRY-SITE-5)
    result[pos:pos+len(blob)] = blob
    footprint = set(range(site,site+5)) | set(range(pos,pos+len(blob)))
    changed = {i for i in footprint if payload[i] != result[i]}
    return bytes(result), changed


if __name__ == '__main__':
    plan = generate()
    (HERE/'mmb_deadzone_v1.0.bin').write_bytes(plan['blob'])
    (HERE/'mmb_deadzone_v1.0.asm').write_text(''.join(f'{va:08x}\t{text}\n' for va,text,_ in plan['rows']),encoding='ascii')
    print('Generated', len(plan['blob']), 'bytes;', hashlib.sha256(plan['blob']).hexdigest())
