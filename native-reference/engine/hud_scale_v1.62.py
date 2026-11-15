"""Camera Control Fix v1.62: 70% HUD size after v1.61 integer snapping."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from native_paths import SF2_ORIGINAL, COLDWAR_ORIGINAL, NORMANDY_IMAGE, INTERMEDIATES, capstone_path

import hashlib
import runpy
import struct

VERSION = '1.62'
HERE = Path(__file__).resolve().parent
SOURCE = INTERMEDIATES/'SF2_ReadableUI_NativeCamera_v1.61.exe'
SOURCE_SHA256 = 'f35f7dfe895fccc48f96fb4a165a8f2e60cefef9ef4fdbfa6c71ac8dd3da372c'
PREVIOUS = runpy.run_path(str(HERE/'hud_scale_v1.61.py'))
offset = PREVIOUS['offset']
HOOK = 0xf84160
ENTRY = 0xf84200
RESUME = 0xf7f000

def numerator(width, height):
    return (PREVIOUS['numerator'](width, height)*7+5)//10

def payload():
    # Eight 16-byte slots. Preserve stack, EBX/ESI/EDI/EBP and all XMM registers.
    # Shared context numerator drives viewport zoom, rectangles and inverse hits.
    instructions = [bytes.fromhex(x) for x in (
        '69c207000000',  # imul eax,edx,7
        '83c005',        # add eax,5 (nearest numerator unit)
        '31d2',          # xor edx,edx
        'b90a000000',    # mov ecx,10
        'f7f1',          # div ecx
        '89c2',          # mov edx,eax
        '899584000000',  # mov [ebp+84],edx
    )]
    instructions.append(b'\xe9'+struct.pack('<i',RESUME-(ENTRY+7*16)-5))
    return b''.join(x+b'\x90'*(16-len(x)) for x in instructions)

def build(source):
    if hashlib.sha256(source).hexdigest() != SOURCE_SHA256:
        raise ValueError('Expected exact mod v1.61')
    result = bytearray(source)
    hook = offset(result,HOOK)
    cave = offset(result,ENTRY)
    raw = payload()
    if result[hook:hook+16] != bytes.fromhex('899584000000')+b'\x90'*10:
        raise ValueError('Post-snap context hook differs')
    if result[cave:cave+len(raw)] != b'\x90'*len(raw):
        raise ValueError('HUD cave occupied')
    result[hook:hook+16] = b'\xe9'+struct.pack('<i',ENTRY-HOOK-5)+b'\x90'*11
    result[cave:cave+len(raw)] = raw
    return bytes(result)

if __name__ == '__main__':
    result = build(SOURCE.read_bytes())
    out = HERE/'candidates/SF2_ReadableUI_NativeCamera_v1.62.exe'
    if out.exists() and out.read_bytes() != result:
        raise FileExistsError(out)
    out.write_bytes(result)
    print(out,hashlib.sha256(result).hexdigest())
