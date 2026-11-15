"""SF2 cursor-ground dolly core v1.0. Native code generator, not a simulator.

ECX=camera, EDI=terrain, EDX=signed wheel delta, XMM1/XMM2=viewport UV.
Caller owns viewport/UI eligibility. Preserves GPRs, flags, and XMM0..7.
No hit, outside-map target, or too little clearance leaves the camera unchanged.
"""
import hashlib
import struct

SOURCE_HASH = 'b3f3cea9f6e94f7b75746b1f2cee9b5d00efcedc0f440d301630be1797a07aa4'


def offset(data, va):
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    opt = pe + 24
    table = opt + struct.unpack_from('<H', data, pe+20)[0]
    base = struct.unpack_from('<I', data, opt+28)[0]
    for i in range(struct.unpack_from('<H', data, pe+6)[0]):
        rva, size, raw = struct.unpack_from('<III', data, table+i*40+12)
        if rva <= va-base < rva+size:
            return raw+va-base-rva
    raise ValueError('VA not file backed')


def build(original, destination_va):
    if hashlib.sha256(original).hexdigest() != SOURCE_HASH:
        raise ValueError('Unsupported SF2 original')
    if not 0x400000 <= destination_va <= 0xffff8fff:
        raise ValueError('Invalid allocation address')
    # Native terrain-only interpolation, identical to the orbit module's slice.
    terrain = original[offset(original, 0x4f64c0):offset(original, 0x4f6705)]
    terrain += bytes.fromhex('f30f5cc8 f30f58cb 0f28c1 5f5e5d5b8be55dc3')
    terrain_va = destination_va + 0x6000
    rows, labels = [], {}
    def e(s): rows.append(s)
    def label(s): labels[s] = destination_va + len(rows)*16
    def m(n): return f'dword ptr [EBP+0x{n:x}]'
    def load(reg,n): e(f'MOVSS {reg},'+m(n))
    def store(n,reg): e('MOVSS '+m(n)+f',{reg}')
    def const(n,value): e('MOV '+m(n)+','+hex(struct.unpack('<I',struct.pack('<f',value))[0]))
    def glob(va): return f'dword ptr [EBX+0x{va-0x400000:x}]'
    # 00..7f XMM; 80 delta; 84 step; 88 lo; 8c hi; 90 ray t;
    # 94..9c ray origin; a0..a8 unit ray; ac fraction; b0 ray magnitude;
    # bc..c4 sample; c8/cc map extents; d0 half; d4..dc proposed camera;
    # e0 loop; e4 min clearance; e8..f0 target; 100..123 native Line output.
    label('entry'); e('PUSHFD'); e('PUSHAD'); e('SUB ESP,0x140'); e('MOV EBP,ESP')
    for i in range(8): e(f'MOVDQU xmmword ptr [EBP+0x{i*16:x}],XMM{i}')
    e('MOV ESI,ECX'); e('MOV '+m(0x80)+',EDX')
    e('CALL @base'); ret = destination_va+(len(rows)-1)*16+5
    label('base'); e('POP EBX'); e(f'SUB EBX,0x{ret-0x400000:x}')
    e('TEST ESI,ESI'); e('JZ @done'); e('TEST EDI,EDI'); e('JZ @done')
    e('CMP '+m(0x80)+',0'); e('JZ @done')
    const(0xd0,0.5); const(0xe4,2.0)
    # Generate the same near-to-far ray used by native world picking.
    e('LEA EAX,[EBP+0x100]'); e('PUSH EAX'); e('MOV ECX,ESI'); e('CALL 0x545f50')
    e('XORPS XMM3,XMM3')
    for src,dst in [(0x118,0xa0),(0x11c,0xa4),(0x120,0xa8)]:
        load('XMM0',src); store(dst,'XMM0'); e('MULSS XMM0,XMM0'); e('ADDSS XMM3,XMM0')
    e('SQRTSS XMM3,XMM3'); e('XORPS XMM0,XMM0'); e('UCOMISS XMM3,XMM0'); e('JP @done'); e('JBE @done'); store(0xb0,'XMM3')
    for src,dst in [(0x108,0x94),(0x10c,0x98),(0x110,0x9c)]:
        e('MOV EAX,'+m(src)); e('MOV '+m(dst)+',EAX')
    for n in (0xa0,0xa4,0xa8):
        load('XMM0',n); e('DIVSS XMM0,XMM3'); store(n,'XMM0')
    # Ground dolly requires a downward ray. Sky scrolling is a no-op.
    e('XORPS XMM0,XMM0'); e('UCOMISS XMM0,'+m(0xa8)); e('JP @done'); e('JBE @done')
    e('MOVSS XMM0,dword ptr [EDI+0x38]'); e('XORPS XMM1,XMM1'); e('UCOMISS XMM0,XMM1'); e('JP @done'); e('JBE @done')
    for src,dst in [(0xa0,0xc8),(0xa4,0xcc)]:
        e(f'MOV EAX,dword ptr [EDI+0x{src:x}]'); e('DEC EAX'); e('JLE @done'); e('CVTSI2SS XMM1,EAX'); e('DIVSS XMM1,XMM0'); store(dst,'XMM1')
    e('MOV EAX,'+m(0xa0)); e('AND EAX,0x7fffffff'); e('MOVD XMM1,EAX')
    e('MOV EAX,'+m(0xa4)); e('AND EAX,0x7fffffff'); e('MOVD XMM2,EAX'); e('MAXSS XMM1,XMM2')
    const(0x84,0.01); e('MAXSS XMM1,'+m(0x84)); e('MULSS XMM1,XMM0')
    load('XMM0',0xd0); e('DIVSS XMM0,XMM1'); store(0x84,'XMM0')
    # Clip the ray to the terrain rectangle, allowing a camera outside the map.
    e('MOV '+m(0x88)+',0'); const(0xf8,0.000001)
    for axis,pos,direction,extent in [('x',0x94,0xa0,0xc8),('y',0x98,0xa4,0xcc)]:
        e('MOV EAX,'+m(direction)); e('AND EAX,0x7fffffff'); e('MOVD XMM0,EAX')
        e('UCOMISS XMM0,'+m(0xf8)); e('JP @done'); e('JBE @parallel_'+axis)
        e('XORPS XMM0,XMM0'); e('SUBSS XMM0,'+m(pos)); e('DIVSS XMM0,'+m(direction))
        load('XMM1',extent); e('SUBSS XMM1,'+m(pos)); e('DIVSS XMM1,'+m(direction))
        e('MOVAPS XMM2,XMM0'); e('MINSS XMM0,XMM1'); e('MAXSS XMM1,XMM2')
        e('MAXSS XMM0,'+m(0x88)); store(0x88,'XMM0'); e('MINSS XMM1,'+m(0xb0)); store(0xb0,'XMM1')
        e('UCOMISS XMM1,XMM0'); e('JP @done'); e('JB @done'); e('JMP @clip_next_'+axis)
        label('parallel_'+axis); load('XMM0',pos); e('XORPS XMM1,XMM1'); e('UCOMISS XMM0,XMM1'); e('JP @done'); e('JB @done')
        e('UCOMISS XMM0,'+m(extent)); e('JA @done'); label('clip_next_'+axis)
    load('XMM0',0x88); const(0xfc,0.001); e('ADDSS XMM0,'+m(0xfc)); store(0x88,'XMM0'); store(0x90,'XMM0')
    e('UCOMISS XMM0,'+m(0xb0)); e('JA @done'); e('CALL @sample')
    e('TEST EAX,EAX'); e('JZ @done'); e('XORPS XMM1,XMM1'); e('UCOMISS XMM0,XMM1'); e('JP @done'); e('JBE @done')
    e('MOV '+m(0xe0)+',0x1000')
    label('march'); load('XMM0',0x88); e('ADDSS XMM0,'+m(0x84)); store(0x90,'XMM0')
    e('UCOMISS XMM0,'+m(0xb0)); e('JP @done'); e('JA @done')
    e('CALL @sample'); e('TEST EAX,EAX'); e('JZ @done'); e('XORPS XMM1,XMM1'); e('UCOMISS XMM0,XMM1'); e('JP @done'); e('JBE @bracket')
    load('XMM0',0x90); store(0x88,'XMM0'); e('DEC '+m(0xe0)); e('JNZ @march'); e('JMP @done')
    label('bracket'); load('XMM0',0x90); store(0x8c,'XMM0'); e('MOV '+m(0xe0)+',16')
    label('bisect'); load('XMM0',0x88); e('ADDSS XMM0,'+m(0x8c)); e('MULSS XMM0,'+m(0xd0)); store(0x90,'XMM0')
    e('CALL @sample'); e('TEST EAX,EAX'); e('JZ @done'); e('XORPS XMM1,XMM1'); e('UCOMISS XMM0,XMM1'); e('JP @done'); e('JBE @lower')
    load('XMM0',0x90); store(0x88,'XMM0'); e('JMP @next')
    label('lower'); load('XMM0',0x90); store(0x8c,'XMM0')
    label('next'); e('DEC '+m(0xe0)); e('JNZ @bisect')
    # Wheel motion is independent of frame time: 120 units move 12% toward hit.
    const(0xac,0.001); e('CVTSI2SS XMM0,'+m(0x80)); e('MULSS XMM0,'+m(0xac))
    const(0xac,-0.5); e('MAXSS XMM0,'+m(0xac)); e('MINSS XMM0,'+m(0xd0)); store(0xac,'XMM0')
    for pos,direction,camera,dst in [(0x94,0xa0,8,0xd4),(0x98,0xa4,12,0xd8),(0x9c,0xa8,16,0xdc)]:
        load('XMM0',direction); e('MULSS XMM0,'+m(0x90)); e('ADDSS XMM0,'+m(pos))
        e(f'SUBSS XMM0,dword ptr [ESI+0x{camera:x}]'); e('MULSS XMM0,'+m(0xac)); e(f'ADDSS XMM0,dword ptr [ESI+0x{camera:x}]'); store(dst,'XMM0')
    # Validate before committing: no partial camera writes on a rejected zoom.
    for value,extent in [(0xd4,0xc8),(0xd8,0xcc)]:
        load('XMM0',value); e('XORPS XMM1,XMM1'); e('UCOMISS XMM0,XMM1'); e('JP @done'); e('JB @done'); e('UCOMISS XMM0,'+m(extent)); e('JA @done')
    e('MOV ECX,EDI'); load('XMM1',0xd4); load('XMM2',0xd8); e(f'CALL 0x{terrain_va:x}')
    load('XMM1',0xdc); e('SUBSS XMM1,XMM0'); store(0xe8,'XMM1')
    e('UCOMISS XMM1,'+m(0xe4)); e('JP @done'); e('JB @done')
    e('MOV EAX,dword ptr [ESI+0xf0]'); e('MOV '+m(0xf4)+',EAX')
    for src,old,new in [(0xd4,8,0x4c),(0xd8,12,0x50),(0xdc,16,0x54)]:
        e(f'MOV EAX,dword ptr [ESI+0x{old:x}]'); e(f'MOV dword ptr [ESI+0x{new:x}],EAX')
        e('MOV EAX,'+m(src)); e(f'MOV dword ptr [ESI+0x{old:x}],EAX')
    # Native validation can enforce terrain-relative height through +F0/+F8.
    # Keep its clearance consistent with the requested new XYZ.
    e('CMP dword ptr [ESI+0xf8],0'); e('JZ @validate')
    load('XMM0',0xe8); e('MOVSS dword ptr [ESI+0xf0],XMM0')
    label('validate'); e('MOV ECX,ESI'); e('CALL 0x545da0')
    # A native collision rejection restores position, but not relative height.
    for previous,camera in [(0x4c,8),(0x50,12),(0x54,16)]:
        e(f'MOV EAX,dword ptr [ESI+0x{previous:x}]'); e(f'CMP EAX,dword ptr [ESI+0x{camera:x}]'); e('JNZ @detach')
    label('restore_height'); e('MOV EAX,'+m(0xf4)); e('MOV dword ptr [ESI+0xf0],EAX')
    label('detach')
    e('MOV EAX,'+glob(0xe57b10)); e('MOV dword ptr [EAX+0xb2c0],0'); e('MOV byte ptr [EAX+0xb2c4],0')
    label('done')
    for i in range(8): e(f'MOVDQU XMM{i},xmmword ptr [EBP+0x{i*16:x}]')
    e('ADD ESP,0x140'); e('POPAD'); e('POPFD'); e('RET')
    label('sample')
    for pos,direction,dst in [(0x94,0xa0,0xbc),(0x98,0xa4,0xc0),(0x9c,0xa8,0xc4)]:
        load('XMM0',direction); e('MULSS XMM0,'+m(0x90)); e('ADDSS XMM0,'+m(pos)); store(dst,'XMM0')
    for value,extent in [(0xbc,0xc8),(0xc0,0xcc)]:
        load('XMM0',value); e('XORPS XMM1,XMM1'); e('UCOMISS XMM0,XMM1'); e('JP @miss'); e('JB @miss'); e('UCOMISS XMM0,'+m(extent)); e('JA @miss')
    e('MOV ECX,EDI'); load('XMM1',0xbc); load('XMM2',0xc0); e(f'CALL 0x{terrain_va:x}')
    load('XMM1',0xc4); e('SUBSS XMM1,XMM0'); e('MOVAPS XMM0,XMM1'); e('MOV EAX,1'); e('RET')
    label('miss'); e('XOR EAX,EAX'); e('RET')
    assert len(rows)*16 < 0x6000
    result = []
    for i,s in enumerate(rows):
        if '@' in s:
            head,name=s.split('@'); s=head+hex(labels[name])
        result.append((destination_va+i*16,s))
    return dict(instructions=result, entry=labels['entry'], terrain_va=terrain_va,
                terrain_blob=terrain, allocation_size=0x7000)
