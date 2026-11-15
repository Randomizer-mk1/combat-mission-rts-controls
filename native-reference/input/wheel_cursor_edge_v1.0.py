"""SF2 bounded cursor-ground edge dolly v1.0. Output-only native patch module.

ECX=camera, EDI=terrain, EDX=signed wheel delta, XMM1/XMM2=viewport UV.
Caller owns viewport/UI eligibility. Preserves GPRs, flags, and XMM0..7.
Terrain misses use a camera-local ground plane. XY stops at map edges while
vertical dolly remains available. Terrain search uses 64 steps and 8 bisections.
Sky/nonfinite input remains a no-op; native collision validation is retained.
"""
import hashlib
import struct
from pathlib import Path

VERSION = "1.0"
HERE = Path(__file__).resolve().parent
DEFAULT_VA = 0xF75000
CODE_SIZE = 0x6000
BLOB_SHA256 = "e6cdf7a22580fef683249847de78d024a60cc436028369bff33a872e8109abfd"
OLD_REGION_SHA256 = "d1faf00e26bc5b7c1db291d3a19de6b1c49d3bcb8322890da8ad876d42d2eb19"

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


def generate(original, destination_va=DEFAULT_VA):
    if hashlib.sha256(original).hexdigest() != SOURCE_HASH:
        raise ValueError('Unsupported SF2 original')
    if destination_va != DEFAULT_VA:
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
    # e0 loop; e4 min clearance; e8 clearance; f4 saved height;
    # 100..123 native Line output; 124 original far length.
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
    e('SQRTSS XMM3,XMM3'); e('XORPS XMM0,XMM0'); e('UCOMISS XMM3,XMM0'); e('JP @done'); e('JBE @done'); store(0xb0,'XMM3'); store(0x124,'XMM3')
    for src,dst in [(0x108,0x94),(0x10c,0x98),(0x110,0x9c)]:
        e('MOV EAX,'+m(src)); e('MOV '+m(dst)+',EAX')
    for n in (0xa0,0xa4,0xa8):
        load('XMM0',n); e('DIVSS XMM0,XMM3'); store(n,'XMM0')
    # Ground dolly requires a downward ray. Sky scrolling is a no-op.
    e('XORPS XMM0,XMM0'); e('UCOMISS XMM0,'+m(0xa8)); e('JP @done'); e('JBE @done')
    e('MOVSS XMM0,dword ptr [EDI+0x38]'); e('XORPS XMM1,XMM1'); e('UCOMISS XMM0,XMM1'); e('JP @done'); e('JBE @done')
    for src,dst in [(0xa0,0xc8),(0xa4,0xcc)]:
        e(f'MOV EAX,dword ptr [EDI+0x{src:x}]'); e('DEC EAX'); e('JLE @done'); e('CVTSI2SS XMM1,EAX'); e('DIVSS XMM1,XMM0'); store(dst,'XMM1')
    # Clip the ray to the terrain rectangle, allowing a camera outside the map.
    e('MOV '+m(0x88)+',0'); const(0xf8,0.000001)
    for axis,pos,direction,extent in [('x',0x94,0xa0,0xc8),('y',0x98,0xa4,0xcc)]:
        e('MOV EAX,'+m(direction)); e('AND EAX,0x7fffffff'); e('MOVD XMM0,EAX')
        e('UCOMISS XMM0,'+m(0xf8)); e('JP @fallback'); e('JBE @parallel_'+axis)
        e('XORPS XMM0,XMM0'); e('SUBSS XMM0,'+m(pos)); e('DIVSS XMM0,'+m(direction))
        load('XMM1',extent); e('SUBSS XMM1,'+m(pos)); e('DIVSS XMM1,'+m(direction))
        e('MOVAPS XMM2,XMM0'); e('MINSS XMM0,XMM1'); e('MAXSS XMM1,XMM2')
        e('MAXSS XMM0,'+m(0x88)); store(0x88,'XMM0'); e('MINSS XMM1,'+m(0xb0)); store(0xb0,'XMM1')
        e('UCOMISS XMM1,XMM0'); e('JP @fallback'); e('JB @fallback'); e('JMP @clip_next_'+axis)
        label('parallel_'+axis); load('XMM0',pos); e('XORPS XMM1,XMM1'); e('UCOMISS XMM0,XMM1'); e('JP @fallback'); e('JB @fallback')
        e('UCOMISS XMM0,'+m(extent)); e('JA @fallback'); label('clip_next_'+axis)
    load('XMM0',0x88); const(0xfc,0.001); e('ADDSS XMM0,'+m(0xfc)); store(0x88,'XMM0'); store(0x90,'XMM0')
    e('UCOMISS XMM0,'+m(0xb0)); e('JA @fallback'); e('CALL @sample')
    e('TEST EAX,EAX'); e('JZ @fallback'); e('XORPS XMM1,XMM1'); e('UCOMISS XMM0,XMM1'); e('JP @fallback'); e('JBE @fallback')
    # Cover the entire clipped interval with at most 64 height queries.
    load('XMM0',0xb0); e('SUBSS XMM0,'+m(0x88)); const(0x84,64.0)
    e('DIVSS XMM0,'+m(0x84)); store(0x84,'XMM0')
    e('MOV '+m(0xe0)+',64')
    label('march'); load('XMM0',0x88); e('ADDSS XMM0,'+m(0x84)); e('MINSS XMM0,'+m(0xb0)); store(0x90,'XMM0')
    e('UCOMISS XMM0,'+m(0xb0)); e('JP @fallback'); e('JA @fallback')
    e('CALL @sample'); e('TEST EAX,EAX'); e('JZ @fallback'); e('XORPS XMM1,XMM1'); e('UCOMISS XMM0,XMM1'); e('JP @fallback'); e('JBE @bracket')
    load('XMM0',0x90); store(0x88,'XMM0'); e('DEC '+m(0xe0)); e('JNZ @march'); e('JMP @fallback')
    label('bracket'); load('XMM0',0x90); store(0x8c,'XMM0'); e('MOV '+m(0xe0)+',8')
    label('bisect'); load('XMM0',0x88); e('ADDSS XMM0,'+m(0x8c)); e('MULSS XMM0,'+m(0xd0)); store(0x90,'XMM0')
    e('CALL @sample'); e('TEST EAX,EAX'); e('JZ @fallback'); e('XORPS XMM1,XMM1'); e('UCOMISS XMM0,XMM1'); e('JP @fallback'); e('JBE @lower')
    load('XMM0',0x90); store(0x88,'XMM0'); e('JMP @next')
    label('lower'); load('XMM0',0x90); store(0x8c,'XMM0')
    label('next'); e('DEC '+m(0xe0)); e('JNZ @bisect')
    e('JMP @dolly')
    # Miss fallback intersects the cursor ray with a horizontal plane at the
    # closest valid ground sample beneath the camera. No extra terrain march.
    label('fallback')
    for camera,dst,extent in [(8,0xd4,0xc8),(12,0xd8,0xcc)]:
        e(f'MOVSS XMM0,dword ptr [ESI+0x{camera:x}]'); e('XORPS XMM1,XMM1')
        e('MAXSS XMM0,XMM1'); e('MINSS XMM0,'+m(extent)); store(dst,'XMM0')
    e('MOV ECX,EDI'); load('XMM1',0xd4); load('XMM2',0xd8); e(f'CALL 0x{terrain_va:x}')
    # Keep a positive two-unit reference clearance even below the local ground.
    e('MOVSS XMM1,dword ptr [ESI+0x10]'); e('SUBSS XMM1,XMM0')
    e('MAXSS XMM1,'+m(0xe4)); e('XORPS XMM0,XMM0'); e('SUBSS XMM0,'+m(0xa8))
    e('DIVSS XMM1,XMM0'); e('MINSS XMM1,'+m(0x124)); store(0x90,'XMM1')
    for camera,dst in [(8,0x94),(12,0x98),(16,0x9c)]:
        e(f'MOV EAX,dword ptr [ESI+0x{camera:x}]'); e('MOV '+m(dst)+',EAX')
    label('dolly')
    # Wheel motion is independent of frame time: 120 units move 12% toward hit.
    const(0xac,0.001); e('CVTSI2SS XMM0,'+m(0x80)); e('MULSS XMM0,'+m(0xac))
    const(0xac,-0.5); e('MAXSS XMM0,'+m(0xac)); e('MINSS XMM0,'+m(0xd0)); store(0xac,'XMM0')
    for pos,direction,camera,dst in [(0x94,0xa0,8,0xd4),(0x98,0xa4,12,0xd8),(0x9c,0xa8,16,0xdc)]:
        load('XMM0',direction); e('MULSS XMM0,'+m(0x90)); e('ADDSS XMM0,'+m(pos))
        e(f'SUBSS XMM0,dword ptr [ESI+0x{camera:x}]'); e('MULSS XMM0,'+m(0xac)); e(f'ADDSS XMM0,dword ptr [ESI+0x{camera:x}]'); store(dst,'XMM0')
    # Stop only the horizontal component at a map edge, not the whole dolly.
    # Reject nonfinite coordinates before SSE clamps can turn a NaN into zero.
    for value in (0xd4,0xd8,0xdc):
        e('MOV EAX,'+m(value)); e('AND EAX,0x7f800000')
        e('CMP EAX,0x7f800000'); e('JE @done')
    # If native controls already placed the camera outside terrain bounds,
    # allow motion back toward the map without snapping it to the boundary.
    for value,extent,camera,sample in [(0xd4,0xc8,8,0xbc),(0xd8,0xcc,12,0xc0)]:
        load('XMM0',value); e('XORPS XMM1,XMM1')
        e(f'MINSS XMM1,dword ptr [ESI+0x{camera:x}]'); e('MAXSS XMM0,XMM1')
        load('XMM1',extent); e(f'MAXSS XMM1,dword ptr [ESI+0x{camera:x}]')
        e('MINSS XMM0,XMM1'); store(value,'XMM0')
        e('XORPS XMM1,XMM1'); e('MAXSS XMM0,XMM1'); e('MINSS XMM0,'+m(extent)); store(sample,'XMM0')
    e('MOV ECX,EDI'); load('XMM1',0xbc); load('XMM2',0xc0); e(f'CALL 0x{terrain_va:x}')
    e('ADDSS XMM0,'+m(0xe4)); load('XMM1',0xdc); e('MAXSS XMM1,XMM0'); store(0xdc,'XMM1')
    e('SUBSS XMM0,'+m(0xe4)); e('SUBSS XMM1,XMM0'); store(0xe8,'XMM1')
    e('MOV EAX,'+m(0xe8)); e('AND EAX,0x7f800000')
    e('CMP EAX,0x7f800000'); e('JE @done')
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
    return dict(version=VERSION, instructions=result, labels=labels, entry=labels['entry'],
                blob_va=destination_va, blob_size=len(rows)*16, terrain_va=terrain_va,
                terrain_blob=terrain, allocation_size=CODE_SIZE)


def build(original, destination_va=DEFAULT_VA):
    plan = generate(original, destination_va)
    blob = (HERE / "wheel_cursor_edge_v1.0.bin").read_bytes()
    if len(blob) != plan["blob_size"] or hashlib.sha256(blob).hexdigest() != BLOB_SHA256:
        raise ValueError("Unvalidated wheel blob")
    plan["blob"] = blob
    return plan


def apply_sites(payload, plan):
    """Replace only the original v1.43 wheel reservation, preserving all else."""
    start = offset(payload, DEFAULT_VA)
    end = offset(payload, DEFAULT_VA + CODE_SIZE - 1) + 1
    if end - start != CODE_SIZE or hashlib.sha256(payload[start:end]).hexdigest() != OLD_REGION_SHA256:
        raise ValueError("Wheel integration conflict")
    terrain = plan["terrain_blob"]
    terrain_pos = offset(payload, DEFAULT_VA + CODE_SIZE)
    if payload[terrain_pos:terrain_pos+len(terrain)] != terrain:
        raise ValueError("Copied terrain conflict")
    blob = plan["blob"]
    if len(blob) > CODE_SIZE or hashlib.sha256(blob).hexdigest() != BLOB_SHA256:
        raise ValueError("Unvalidated replacement")
    result = bytearray(payload)
    result[start:end] = blob + b"\x90" * (CODE_SIZE - len(blob))
    return bytes(result)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("original", type=Path)
    args = parser.parse_args()
    plan = generate(args.original.read_bytes())
    text = "".join(f"{va:08x}\t{ins}\n" for va,ins in plan["instructions"])
    text += f"{DEFAULT_VA+plan['blob_size']:08x}\tEND\n"
    (HERE / "wheel_cursor_edge_v1.0.asm").write_text(text, encoding="ascii")
    print(f"Generated {len(plan['instructions'])} slots, {plan['blob_size']} bytes")
