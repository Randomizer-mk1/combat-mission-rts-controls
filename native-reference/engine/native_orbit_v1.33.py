"""Native SF2 selected-unit orbit math reused without changing unit selection; v1.33."""
import re
from pathlib import Path
import hashlib
import struct

VERSION = '1.33'
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
    terrain_va = destination_va + 0x4000
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
    # Selection and camera tracking are distinct. Wheel dolly detaches tracking.
    # Resolve the real selected unit through the same wrapper vtable as native 0x741930.
    e('MOV EDI,EAX'); e('MOV ECX,'+glob(0xe57b18)); e('TEST ECX,ECX'); e('JZ @selection_ready')
    e('MOV ECX,dword ptr [ECX+0x8a0]'); e('TEST ECX,ECX'); e('JZ @selection_ready')
    e('CMP dword ptr [ECX+0x18],0'); e('JNZ @selection_ready')
    e('MOV EDX,dword ptr [ECX]'); e('CALL dword ptr [EDX+0x44]'); e('TEST EAX,EAX'); e('JZ @selection_ready')
    e('CMP EAX,dword ptr [EDI+0xb2c0]'); e('JZ @selection_ready')
    e('PUSH EAX'); e('MOV ECX,EDI'); e('CALL 0x7c7a60')
    label('selection_ready'); load('XMM1',0x10); e('MOV EAX,EDI')
    e('CMP dword ptr [EAX+0xb2c0],0'); e('JNZ @native_selected'); e('LEA ECX,[EAX+0xb7e0]'); e('CMP ESI,ECX'); e('JNZ @native_selected'); e('MOV EDI,dword ptr [EAX+0x14]'); e('TEST EDI,EDI'); e('JZ @done')
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
    # Reuse the vanilla selected-unit orbit position block with a terrain pivot.
    # Unit selection/target pointer is never forged. Only camera distance is temporary.
    for pos,direction,dst in [(0x94,0xa0,0xd4),(0x98,0xa4,0xd8)]:
        load('XMM0',direction); e('MULSS XMM0,'+loc(0x90)); e('ADDSS XMM0,'+loc(pos)); store(dst,'XMM0')
    load('XMM0',0xa0); e('MULSS XMM0,XMM0'); load('XMM1',0xa4); e('MULSS XMM1,XMM1'); e('ADDSS XMM0,XMM1'); e('SQRTSS XMM0,XMM0'); e('MULSS XMM0,'+loc(0x90)); store(0xec,'XMM0')
    e('MOV ECX,ESI'); load('XMM1',0x80); e('CALL 0x544e70')
    e('MOVSS XMM0,dword ptr [ESI+0x1c]'); e('MOVSS XMM1,dword ptr [ESI+0x18]'); e('CALL 0x4e82a0')
    e('MOV EDX,'+glob(0xe57b10)); e('MOV ECX,dword ptr [EDX+0x58]'); e('MOV '+loc(0xf0)+',ECX'); load('XMM1',0xec); e('MOVSS dword ptr [EDX+0x58],XMM1')
    e('MOV EAX,EBP'); e('PUSH ESI'); e('PUSH EDI'); e('PUSH EBP'); e('SUB ESP,0x80'); e('MOV EBP,ESP'); e('ADD EBP,0x80'); e('MOV EDI,EDX')
    e('MOVSS dword ptr [EBP + -0x1c],XMM0')
    e('MOVSS XMM0,dword ptr [EAX+0xd4]'); e('MOVSS dword ptr [EBP + -0x44],XMM0')
    e('MOVSS XMM0,dword ptr [EAX+0xd8]'); e('MOVSS dword ptr [EBP + -0x40],XMM0')
    e(f'CALL 0x{destination_va+0x2000:x}')
    e('ADD ESP,0x80'); e('POP EBP'); e('POP EDI'); e('POP ESI')
    e('MOV EDX,'+glob(0xe57b10)); e('MOV EAX,'+loc(0xf0)); e('MOV dword ptr [EDX+0x58],EAX'); e('JMP @changed')
    label('fallback'); e('MOV ECX,ESI'); load('XMM1',0x80); e('CALL 0x544e70')
    label('changed'); e('MOV EAX,'+glob(0xe57b10)); e('MOV byte ptr [EAX+0xb2c4],0')
    e('JMP @done')
    label('native_selected'); e('CALL 0x54abb0')
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
    assert len(rows)*16 < 0x2000
    result = []
    for i,s in enumerate(rows):
        if '@' in s:
            head,name=s.split('@'); s=head+hex(labels[name])
        result.append((destination_va+i*16,s))
    # Exact reachable vanilla instructions, with only control-flow displacements relocated.
    # Decode the caller-supplied, hash-guarded original instead of depending on
    # a private Ghidra listing. Do not distribute the original or that listing.
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from native_paths import capstone_path
    capstone_path()
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    decoder=Cs(CS_ARCH_X86,CS_MODE_32)
    first=0x7c63af;end=0x7c6d34
    code=original[offset(original,first):offset(original,end)]
    ins={}
    for item in decoder.disasm(code,first):
        op={'je':'JZ','jne':'JNZ'}.get(item.mnemonic,item.mnemonic.upper())
        operand=item.op_str.upper().replace('0X','0x')
        ins[item.address]=(bytes(item.bytes),op+' '+operand)
    seen=set();todo=[0x7c63af];end=0x7c6d34
    while todo:
        a=todo.pop()
        if a in seen or a==end:continue
        seen.add(a);raw,text=ins[a];op=text.split()[0]
        assert 'EBX' not in text and not re.search(r'\[0x00',text)
        assert original[offset(original,a):offset(original,a)+len(raw)]==raw
        if op=='JMP':todo.append(int(text.split()[-1],16))
        elif op.startswith('J'):todo.extend([int(text.split()[-1],16),a+len(raw)])
        else:todo.append(a+len(raw))
    ordered=sorted(seen);mapping={a:destination_va+0x2000+i*16 for i,a in enumerate(ordered+[end])}
    for a in ordered:
        raw,text=ins[a];op=text.split()[0]
        if op.startswith('J'):text=op+' '+hex(mapping[int(text.split()[-1],16)])
        elif op!='CALL':text='HEX '+raw.hex()
        result.append((mapping[a],text))
    result.append((mapping[end],'RET'))
    return dict(instructions=result, entry=labels['entry'], terrain_va=terrain_va,
                terrain_blob=terrain, allocation_size=0x5000,
                hook_va=HOOK_VA, hook_original=HOOK_ORIGINAL)
