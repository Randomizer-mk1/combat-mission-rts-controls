"""SF2 Q/E ground-orbit code generator. Engine-owned integration; no PE writes.

Hook ONLY CALL 0x549d8d (native target 0x54abb0) to entry. Keep existing
Q/E +/-0.6 operands: this entry applies the native elapsed-time/FOV scaling.
Reserve 0x4000 executable bytes; assemble returned (VA, instruction) rows into
16-byte NOP-padded slots. Copy terrain_blob to terrain_va in the same image.
No additional PE relocations are needed. All original absolute data references
use a runtime image-base register; native external calls remain rel32.

Ground anchor: forward camera ray, half-grid marching then 16 bisections.
This is a bounded numerical intersection, not an exact triangle ray tracer;
very narrow terrain crossings may be missed. No hit falls back to native yaw.
Orbit retains altitude and native terrain/boundary validation. A boundary clamp
rolls the whole orbit step back. Runtime behavior requires owner play testing.
"""
import hashlib
import struct

VERSION = '1.0'
SOURCE_SHA256 = 'b3f3cea9f6e94f7b75746b1f2cee9b5d00efcedc0f440d301630be1797a07aa4'
HOOK_VA = 0x549d8d
HOOK_ORIGINAL = bytes.fromhex('e81e0e0000')


def offset(data, va):
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    opt = pe + 24
    base = struct.unpack_from('<I', data, opt + 28)[0]
    table = opt + struct.unpack_from('<H', data, pe + 20)[0]
    for i in range(struct.unpack_from('<H', data, pe + 6)[0]):
        rva, size, raw = struct.unpack_from('<III', data, table + i*40 + 12)
        if rva <= va-base < rva+size:
            return raw+va-base-rva
    raise ValueError('Address is not file backed')


def build(original, destination_va):
    if hashlib.sha256(original).hexdigest() != SOURCE_SHA256:
        raise ValueError('Unsupported original image')
    if not 0x400000 <= destination_va <= 0xffffbfff:
        raise ValueError('Invalid allocation')
    if original[offset(original, HOOK_VA):offset(original, HOOK_VA)+5] != HOOK_ORIGINAL:
        raise ValueError('Q/E call context mismatch')
    # Native grid interpolation ends immediately before the object/bridge loop.
    # No CALLs or absolute addresses exist in this retained instruction range.
    terrain = original[offset(original, 0x4f64c0):offset(original, 0x4f6705)]
    assert terrain[:9] == bytes.fromhex('558bec83e4f883ec18')
    # Finish the two pending interpolations, return XMM0, preserve native ABI.
    terrain += bytes.fromhex('f30f5cc8 f30f58cb 0f28c1 5f5e5d5b8be55dc3')
    terrain_va = destination_va + 0x3000
    rows, labels = [], {}
    def e(s): rows.append(s)
    def label(s): labels[s] = destination_va + len(rows)*16
    def loc(n): return f'dword ptr [EBP+0x{n:x}]'
    def glob(va, kind='dword'): return f'{kind} ptr [EBX+0x{va-0x400000:x}]'
    def load(dst, n): e(f'MOVSS {dst},'+loc(n))
    def store(n, src): e('MOVSS '+loc(n)+f',{src}')
    def const(n, f): e('MOV '+loc(n)+','+hex(struct.unpack('<I',struct.pack('<f',f))[0]))
    # Stack locals: saved XMM[0..127], angle80, step84, lo88, hi8c,
    # t90, original position94..9c, directiona0..a8, upac..b4,
    # clearanceb8, sample xbc/y c0/z c4, extent c8/cc, half d0,
    # desired position d4/d8; loop counter dc; original previous e0..e8.
    label('entry'); e('PUSHFD'); e('PUSHAD'); e('SUB ESP,0x100'); e('MOV EBP,ESP')
    for i in range(8): e(f'MOVDQU xmmword ptr [EBP+0x{i*16:x}],XMM{i}')
    e('CALL @base'); ret = destination_va+(len(rows)-1)*16+5
    label('base'); e('POP EBX'); e(f'SUB EBX,0x{ret-0x400000:x}')
    e('MOV EAX,'+glob(0xe57b10)); e('TEST EAX,EAX'); e('JZ @done')
    e('MOV ESI,dword ptr [EAX+0x10]'); e('TEST ESI,ESI'); e('JZ @done')
    e('MOV EDI,dword ptr [EAX+0x14]'); e('TEST EDI,EDI'); e('JZ @done')
    # Same capped elapsed milliseconds and constants as 0x54abb0.
    e('MOV EAX,'+glob(0xe53a94)); e('TEST EAX,EAX'); e('JZ @done')
    e('MOV EAX,dword ptr [EAX+0xc]'); e('MOV ECX,0x6f'); e('CMP EAX,ECX'); e('CMOVA EAX,ECX')
    e('TEST EAX,EAX'); e('JZ @done'); e('CVTSI2SD XMM0,EAX')
    e('MULSD XMM0,'+glob(0xbab6d8,'qword')); e('CVTSS2SD XMM1,XMM1'); e('MULSD XMM1,XMM0')
    e('MOVSS XMM0,'+glob(0xbacce4)); e('DIVSS XMM0,dword ptr [ESI+0x34]')
    e('CVTSS2SD XMM0,XMM0'); e('DIVSD XMM1,XMM0'); e('CVTSD2SS XMM1,XMM1'); store(0x80,'XMM1')
    for src,dst in [(8,0x94),(12,0x98),(16,0x9c),(24,0xa0),(28,0xa4),(32,0xa8),(40,0xac),(44,0xb0),(48,0xb4),(0xf0,0xb8),(0x4c,0xe0),(0x50,0xe4),(0x54,0xe8)]:
        e(f'MOV EAX,dword ptr [ESI+0x{src:x}]'); e('MOV '+loc(dst)+',EAX')
    # Only a downward centre ray can supply a stable terrain pivot.
    e('XORPS XMM0,XMM0'); e('UCOMISS XMM0,dword ptr [ESI+0x20]'); e('JP @fallback'); e('JBE @fallback')
    const(0xd0,0.5)
    e('MOVSS XMM0,dword ptr [EDI+0x38]'); e('XORPS XMM1,XMM1'); e('UCOMISS XMM0,XMM1'); e('JP @fallback'); e('JBE @fallback')
    for off,dst in [(0xa0,0xc8),(0xa4,0xcc)]:
        e(f'MOV EAX,dword ptr [EDI+0x{off:x}]'); e('DEC EAX'); e('JLE @fallback'); e('CVTSI2SS XMM1,EAX'); e('DIVSS XMM1,XMM0'); store(dst,'XMM1')
    # Half a cell in the dominant horizontal axis; at least 0.01 direction.
    e('MOV EAX,'+loc(0xa0)); e('AND EAX,0x7fffffff'); e('MOVD XMM1,EAX')
    e('MOV EAX,'+loc(0xa4)); e('AND EAX,0x7fffffff'); e('MOVD XMM2,EAX'); e('MAXSS XMM1,XMM2')
    const(0x84,0.01); e('MAXSS XMM1,'+loc(0x84)); e('MULSS XMM1,XMM0')
    load('XMM0',0xd0); e('DIVSS XMM0,XMM1'); store(0x84,'XMM0')
    e('MOV '+loc(0x88)+',0'); e('MOV '+loc(0x90)+',0'); e('CALL @sample')
    e('TEST EAX,EAX'); e('JZ @fallback'); e('XORPS XMM1,XMM1'); e('UCOMISS XMM0,XMM1'); e('JP @fallback'); e('JBE @fallback')
    e('MOV '+loc(0xdc)+',0x1000')
    label('march'); load('XMM0',0x88); e('ADDSS XMM0,'+loc(0x84)); store(0x90,'XMM0')
    e('UCOMISS XMM0,dword ptr [ESI+0x40]'); e('JP @fallback'); e('JA @fallback')
    e('CALL @sample'); e('TEST EAX,EAX'); e('JZ @fallback'); e('XORPS XMM1,XMM1'); e('UCOMISS XMM0,XMM1'); e('JP @fallback'); e('JBE @bracket')
    load('XMM0',0x90); store(0x88,'XMM0'); e('DEC '+loc(0xdc)); e('JNZ @march'); e('JMP @fallback')
    label('bracket'); load('XMM0',0x90); store(0x8c,'XMM0'); e('MOV '+loc(0xdc)+',16')
    label('bisect'); load('XMM0',0x88); e('ADDSS XMM0,'+loc(0x8c)); e('MULSS XMM0,'+loc(0xd0)); store(0x90,'XMM0')
    e('CALL @sample'); e('TEST EAX,EAX'); e('JZ @fallback'); e('XORPS XMM1,XMM1'); e('UCOMISS XMM0,XMM1'); e('JP @fallback'); e('JBE @lower')
    load('XMM0',0x90); store(0x88,'XMM0'); e('JMP @next')
    label('lower'); load('XMM0',0x90); store(0x8c,'XMM0')
    label('next'); e('DEC '+loc(0xdc)); e('JNZ @bisect')
    # Native cos/sin functions take angle in XMM0 and return XMM0.
    load('XMM0',0x80); e('CALL 0x4e82e0'); store(0x88,'XMM0')
    load('XMM0',0x80); e('CALL 0x4e8300'); store(0x8c,'XMM0')
    # C' = C + t*(D - rotate(D)); same angle as native direction/up yaw.
    load('XMM0',0xa0); e('MULSS XMM0,'+loc(0x88)); load('XMM1',0xa4); e('MULSS XMM1,'+loc(0x8c)); e('SUBSS XMM0,XMM1')
    load('XMM1',0xa0); e('SUBSS XMM1,XMM0'); e('MULSS XMM1,'+loc(0x90)); e('ADDSS XMM1,'+loc(0x94)); store(0xd4,'XMM1')
    load('XMM0',0xa0); e('MULSS XMM0,'+loc(0x8c)); load('XMM1',0xa4); e('MULSS XMM1,'+loc(0x88)); e('ADDSS XMM0,XMM1')
    load('XMM1',0xa4); e('SUBSS XMM1,XMM0'); e('MULSS XMM1,'+loc(0x90)); e('ADDSS XMM1,'+loc(0x98)); store(0xd8,'XMM1')
    # Reject an off-map orbit position before changing the camera.
    for val,extent in [(0xd4,0xc8),(0xd8,0xcc)]:
        load('XMM0',val); e('XORPS XMM1,XMM1'); e('UCOMISS XMM0,XMM1'); e('JP @done'); e('JB @done'); e('UCOMISS XMM0,'+loc(extent)); e('JA @done')
    for old,prev in [(0x94,0x4c),(0x98,0x50),(0x9c,0x54)]:
        e('MOV EAX,'+loc(old)); e(f'MOV dword ptr [ESI+0x{prev:x}],EAX')
    load('XMM0',0xd4); e('MOVSS dword ptr [ESI+8],XMM0'); load('XMM0',0xd8); e('MOVSS dword ptr [ESI+0xc],XMM0')
    e('CMP dword ptr [ESI+0xf8],0'); e('JZ @rotate')
    # Use the exact helper that native 0x545da0 itself uses for floor height.
    e('MOV ECX,ESI'); e('CALL 0x5456f0'); load('XMM1',0x9c); e('SUBSS XMM1,XMM0')
    e('XORPS XMM0,XMM0'); e('UCOMISS XMM1,XMM0'); e('JP @rollback'); e('JBE @rollback'); e('MOVSS dword ptr [ESI+0xf0],XMM1')
    label('rotate'); e('MOV ECX,ESI'); load('XMM1',0x80); e('CALL 0x544e70')
    for off,val in [(8,0xd4),(12,0xd8)]:
        e(f'MOVSS XMM0,dword ptr [ESI+0x{off:x}]'); e('UCOMISS XMM0,'+loc(val)); e('JP @rollback'); e('JNE @rollback')
    e('JMP @changed')
    label('rollback')
    for dst,src in [(8,0x94),(12,0x98),(16,0x9c),(24,0xa0),(28,0xa4),(32,0xa8),(40,0xac),(44,0xb0),(48,0xb4),(0xf0,0xb8),(0x4c,0xe0),(0x50,0xe4),(0x54,0xe8)]:
        e('MOV EAX,'+loc(src)); e(f'MOV dword ptr [ESI+0x{dst:x}],EAX')
    e('MOV byte ptr [ESI+0x11c],0'); e('JMP @changed')
    label('fallback'); e('MOV ECX,ESI'); load('XMM1',0x80); e('CALL 0x544e70')
    label('changed'); e('MOV EAX,'+glob(0xe57b10)); e('MOV byte ptr [EAX+0xb2c4],0')
    label('done')
    for i in range(8): e(f'MOVDQU XMM{i},xmmword ptr [EBP+0x{i*16:x}]')
    e('ADD ESP,0x100'); e('POPAD'); e('POPFD'); e('RET')
    # Sample ray clearance. EAX=0 on out-of-grid/NaN; otherwise XMM0=z-h.
    label('sample')
    for pos,direction,dst in [(0x94,0xa0,0xbc),(0x98,0xa4,0xc0),(0x9c,0xa8,0xc4)]:
        load('XMM0',direction); e('MULSS XMM0,'+loc(0x90)); e('ADDSS XMM0,'+loc(pos)); store(dst,'XMM0')
    for val,extent in [(0xbc,0xc8),(0xc0,0xcc)]:
        load('XMM0',val); e('XORPS XMM1,XMM1'); e('UCOMISS XMM0,XMM1'); e('JP @miss'); e('JB @miss'); e('UCOMISS XMM0,'+loc(extent)); e('JA @miss')
    e('MOV ECX,EDI'); load('XMM1',0xbc); load('XMM2',0xc0); e(f'CALL 0x{terrain_va:x}')
    load('XMM1',0xc4); e('SUBSS XMM1,XMM0'); e('MOVAPS XMM0,XMM1'); e('MOV EAX,1'); e('RET')
    label('miss'); e('XOR EAX,EAX'); e('RET')
    assert len(rows)*16 < 0x3000
    result = []
    for i,s in enumerate(rows):
        if '@' in s:
            head,name=s.split('@'); s=head+hex(labels[name])
        result.append((destination_va+i*16,s))
    return dict(instructions=result, entry=labels['entry'], terrain_va=terrain_va,
                terrain_blob=terrain, allocation_size=0x4000,
                hook_va=HOOK_VA, hook_original=HOOK_ORIGINAL)
