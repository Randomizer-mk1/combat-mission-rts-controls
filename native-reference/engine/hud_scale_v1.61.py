"""SF2 HUD v1.61: close-fit upward integer scaling on immutable pre-shadow v1.55.
Output only. No game launch or installation. Texture/font resources are unchanged.
"""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from native_paths import SF2_ORIGINAL, COLDWAR_ORIGINAL, NORMANDY_IMAGE, INTERMEDIATES, capstone_path

import hashlib
import struct
import sys

VERSION = '1.61'
HERE = Path(__file__).resolve().parent
SOURCE = INTERMEDIATES/'SF2_ReadableUI_NativeCamera_v1.55.exe'
SOURCE_SHA256 = '2dbe63635ba0bab9e1e60cade1900c5c7e4a43e6b15ba304410447a283a6daf5'
ENTRY = 0xf84000
HOOK = 0xf7eff0
PAYLOAD_SHA256 = '5aab31a66b63b87a91c47f357419538d213eb5550a434ff6faa4eeac6ba625eb'

def offset(b, va):
    pe = struct.unpack_from('<I', b, 60)[0]
    st = pe+24+struct.unpack_from('<H', b, pe+20)[0]
    for i in range(struct.unpack_from('<H', b, pe+6)[0]):
        r, n, p = struct.unpack_from('<III', b, st+40*i+12)
        if r <= va-0x400000 < r+n:
            return p+va-0x400000-r
    raise ValueError('Unmapped address')

def numerator(width, height):
    original = min(max(height, 768), width*3//4)
    integer = (original+767)//768
    candidate = integer*768
    if ((candidate-original)*12 <= original and
            integer*1024 <= width and integer*164 <= height):
        return candidate
    return original

def instructions():
    rows = []; labels = {}
    def e(s): rows.append(s)
    def label(s): labels[s] = ENTRY+len(rows)*16
    # EDX is the original numerator. E0 is unused private wrapper stack space.
    e('MOV dword ptr [EBP+0xe0],EDX')
    e('MOV EAX,EDX'); e('ADD EAX,767'); e('XOR EDX,EDX')
    e('MOV ECX,768'); e('DIV ECX'); e('MOV ECX,EAX')
    e('IMUL EAX,EAX,768'); e('SUB EAX,dword ptr [EBP+0xe0]')
    e('IMUL EAX,EAX,12'); e('CMP EAX,dword ptr [EBP+0xe0]'); e('JA @fallback')
    e('IMUL EAX,ECX,1024'); e('CMP EAX,dword ptr [EBP+0x88]'); e('JA @fallback')
    e('IMUL EAX,ECX,164'); e('MOV EDX,dword ptr [EBX+0xa53a94]')
    e('CMP EAX,dword ptr [EDX+4]'); e('JA @fallback')
    e('IMUL EDX,ECX,768'); e('JMP @resume')
    label('fallback'); e('MOV EDX,dword ptr [EBP+0xe0]')
    label('resume'); e('MOV dword ptr [EBP+0x84],EDX'); e(f'JMP 0x{HOOK+16:x}')
    return [(ENTRY+i*16, s.replace('@fallback', hex(labels['fallback'])).replace('@resume', hex(labels['resume']))) for i,s in enumerate(rows)]

def build(source):
    if hashlib.sha256(source).hexdigest() != SOURCE_SHA256:
        raise ValueError('Expected exact pre-shadow v1.55')
    raw = (HERE/'hud_scale_v1.61.bin').read_bytes()
    if len(raw) != len(instructions())*16 or hashlib.sha256(raw).hexdigest() != PAYLOAD_SHA256:
        raise ValueError('Unverified payload')
    b = bytearray(source); h = offset(b, HOOK); p = offset(b, ENTRY)
    if b[h:h+16] != bytes.fromhex('899584000000')+b'\x90'*10:
        raise ValueError('HUD hook differs')
    if b[p:p+len(raw)] != b'\x90'*len(raw):
        raise ValueError('HUD cave is occupied')
    b[h:h+16] = b'\xe9'+struct.pack('<i', ENTRY-HOOK-5)+b'\x90'*11
    b[p:p+len(raw)] = raw
    return bytes(b)

if __name__ == '__main__':
    if '--emit' in sys.argv:
        out = HERE/'hud_scale_v1.61.asm'
        out.write_text(''.join(f'{a:08x}\t{s}\n' for a,s in instructions()), encoding='ascii')
        print('ASM',len(instructions()))
    else:
        out = HERE/'candidates/SF2_ReadableUI_NativeCamera_v1.61.exe'
        result = build(SOURCE.read_bytes())
        if out.exists() and out.read_bytes() != result:
            raise ValueError('Refusing to overwrite a different candidate')
        out.write_bytes(result)
        print(out.name, hashlib.sha256(result).hexdigest())
