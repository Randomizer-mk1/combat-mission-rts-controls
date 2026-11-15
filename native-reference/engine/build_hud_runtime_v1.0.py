"""Build independent runtime HUD/briefing spec from native correspondences.

Only engine/ outputs are owned here. No process writes or released-file edits.
"""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from native_paths import SF2_ORIGINAL, COLDWAR_ORIGINAL, NORMANDY_IMAGE, INTERMEDIATES, capstone_path

import importlib.util
import base64
import hashlib
import json
import re
import struct

HERE=Path(__file__).resolve().parent
ROOT=HERE.parent
def load(name,path):
    s=importlib.util.spec_from_file_location(name,path);o=importlib.util.module_from_spec(s);s.loader.exec_module(o);return o
common=load('hud_common_source',ROOT/'planning/build_engine_runtime_v1.83.py')
m=common.m
SF=common.SF
MOD=m.PE(INTERMEDIATES/'SF2_ReadableUI_NativeCamera_v1.62.exe','84340818198a40eb27653c2f8e7b69c5ff60a7de0dfecccc78eeaac8aa0e76cf')
brief=load('hud_brief_source',ROOT/'input/ui_readability_v1.0.py')
C=0xf7d000
D=C+0x8000

class MappedImage:
    def __init__(self,path):
        self.path=Path(path);self.data=self.path.read_bytes();self.base=0x400000;self.md=SF.md
        b=self.data;pe=struct.unpack_from('<I',b,60)[0];st=pe+24+struct.unpack_from('<H',b,pe+20)[0];self.sections=[]
        for i in range(struct.unpack_from('<H',b,pe+6)[0]):
            o=st+i*40;vs,rva=struct.unpack_from('<II',b,o+8)
            self.sections.append(dict(va=self.base+rva,off=rva,size=vs,flags=struct.unpack_from('<I',b,o+36)[0]))
    def off(self,va):return va-self.base
    def raw(self,va,n):return self.data[va-self.base:va-self.base+n]
    def u32(self,p):return struct.unpack_from('<I',self.data,p)[0]
    def ins(self,va,n=256):return list(self.md.disasm(self.raw(va,n),va))

BN=MappedImage(NORMANDY_IMAGE)
IMAGES=[SF,BN,common.CW]

def make_anchor(va,count):
    # Keep all object field offsets exact. Every variant must match the layout.
    a=common.anchor(va,count)
    # The common generator masks camera fields. HUD has no such operand license.
    if any(e['kind']=='field' for e in a['extract']):return None
    return a

def choose(va,counts=(48,32,24,16,12,8)):
    for count in counts:
        a=make_anchor(va,count)
        if a and all(len(common.matches(im,a))==1 for im in IMAGES):return a
    return None

def build():
    if (HERE/'hud_runtime/HANDOFF-v1.0').exists():
        raise FileExistsError('Handed-off v1.0 is frozen; create the next tool version')
    anchors=[];aliases=[];hooks=[]
    # Native config->font load provides the selected AA font field, rather than
    # assuming every game's configuration object uses SF2's +B4 member.
    font=make_anchor(0x4d8c8d,16)
    fm=bytearray(base64.b64decode(font['mask']));fm[8:12]=bytes(4)
    font['mask']=common.encoded(fm)
    font['extract'].append(dict(kind='field',key=0xb4,offset=8,size=4))
    assert all(len(common.matches(im,font))==1 for im in IMAGES)
    anchors.append(font)
    hudsites=[(0x791cf2,6),(0x791e86,6),(0x6f9d85,8),(0x7919f0,6),
              (0x56047c,5),(0x79ecd0,5),(0x79ee6b,5)]
    for va,n in hudsites:
        a=choose(va)
        if not a and va==0x56047c:
            a=choose(0x56044e,(10,))
        if not a:raise ValueError('Unresolved HUD hook '+hex(va))
        anchors.append(a)
        old=MOD.raw(va,n);dest=va+5+struct.unpack_from('<i',old,1)[0]
        assert C<=dest<C+0x8000
        hooks.append(dict(key=va,size=n,opcode=old[0],payload_target=dest-C))
    bp=brief.build(SF.data,C+0x7a00)
    for va,old,new in bp['patches']:
        a=choose(va)
        if not a:raise ValueError('Unresolved briefing hook '+hex(va))
        anchors.append(a);hooks.append(dict(key=va,size=len(old),opcode=0xe9,payload_target=va+5+struct.unpack_from('<i',new,1)[0]-C))
        aliases.append(dict(key=va+len(old),source=va,delta=len(old)))
    aliases += [dict(key=0x6f9d8d,source=0x6f9d85,delta=8),dict(key=0x7919f6,source=0x7919f0,delta=6),dict(key=0x79ecd5,source=0x79ecd0,delta=5)]
    payload=bytearray(MOD.raw(C,0x8000)+bytes(0x1000))
    assert payload[0x7a00:0x7a40]==b'\x90'*64
    payload[0x7a00:0x7a40]=bp['blob']
    fixes=[];required=set()
    for begin,length in [(0,0x7800),(0x7a00,64)]:
        ins=list(SF.md.disasm(payload[begin:begin+length],C+begin))
        assert ins[-1].address+ins[-1].size==C+begin+length
        for i in ins:
            pos=i.address-C
            if i.operands and (i.group(m.cs.CS_GRP_CALL) or i.group(m.cs.CS_GRP_JUMP)) and i.operands[0].type==m.cs.x86.X86_OP_IMM:
                dest=i.operands[0].imm
                if not C<=dest<C+0x8000:
                    assert i.imm_size==4
                    fixes.append(dict(kind='relative',offset=pos+i.imm_offset,key=dest,end=pos+i.size));required.add(dest)
            for o in i.operands:
                if o.type==m.cs.x86.X86_OP_MEM:
                    if o.mem.base==m.cs.x86.X86_REG_EBX and o.mem.disp>=0x100000:
                        native=o.mem.disp+0x400000
                        if C<=native<C+0x9000:fixes.append(dict(kind='private',offset=pos+i.disp_offset,key=native-C))
                        else:fixes.append(dict(kind='module',offset=pos+i.disp_offset,key=native));required.add(native)
                    elif o.mem.base==m.cs.x86.X86_REG_EAX and o.mem.disp==0xb4:
                        assert i.disp_size==4
                        fixes.append(dict(kind='field',offset=pos+i.disp_offset,key=0xb4))
                    elif o.mem.base==0 and o.mem.disp>=0x400000:raise ValueError('Absolute HUD operand '+hex(i.address))
            if i.mnemonic=='sub' and i.operands[0].type==m.cs.x86.X86_OP_REG and i.operands[0].reg==m.cs.x86.X86_REG_EBX and i.operands[1].type==m.cs.x86.X86_OP_IMM and i.operands[1].imm>=0x100000:
                fixes.append(dict(kind='base',offset=pos+i.imm_offset,key=i.operands[1].imm-(C-0x400000)))
    # Functions provide both ABI/layout evidence and references used by the HUD.
    for va in [0x609260,0x609870,0x7920d0,0x792110,0x951734]:
        a=choose(va)
        if not a:raise ValueError('Unresolved native HUD dependency '+hex(va))
        anchors.append(a)
    def known():
        out=common.resolve(SF,anchors)[0]
        for a in aliases:out[a['key']]=out[a['source']]+a['delta']
        return out
    # Resolve IAT/global operands via native executable references, never by a
    # shared title address or by resolved imported function pointer values.
    for key in sorted(required-known().keys()):
        candidates=[]
        for rel in sorted(SF.relocs):
            if SF.u32(SF.off(rel))!=key:continue
            if not any(s['flags']&0x20000000 and s['va']<=rel<s['va']+s['size'] for s in SF.sections):continue
            for back in range(1,9):
                va=rel-back
                first=SF.ins(va,16)
                if not first or not first[0].address<=rel<first[0].address+first[0].size:continue
                i=first[0]
                if not ((i.disp_size==4 and i.address+i.disp_offset==rel) or (i.imm_size==4 and i.address+i.imm_offset==rel)):continue
                a=choose(va,(24,16,12,8))
                if a and any(e['key']==key and e['kind']=='module' for e in a['extract']):candidates.append(a);break
            if candidates:break
        if not candidates:raise ValueError('Unresolved native HUD global/IAT '+hex(key))
        anchors.append(candidates[0])
    maps=[]
    for im in IMAGES:
        values,fields,sites=common.resolve(im,anchors)
        for a in aliases:values[a['key']]=values[a['source']]+a['delta']
        # Native clock coordinates use either PUSH imm8 or PUSH imm32.
        # Decode their lengths; Normandy's 0x10 Y uses a shorter encoding.
        at=values[0x56044e]+im.base+0x24
        for _ in range(2):
            op=im.raw(at,1)[0]
            if op not in (0x68,0x6a):raise ValueError('Clock coordinate ABI mismatch')
            at+=5 if op==0x68 else 2
        if im.raw(at,1)!=b'\xe8':raise ValueError('Clock call missing')
        dest=at+5+struct.unpack('<i',im.raw(at+1,4))[0]
        if dest!=values[0x609870]+im.base:raise ValueError('Clock font call mismatch')
        values[0x56047c]=at-im.base
        assert not required-values.keys()
        assert 4<=fields[0xb4]<=0x10000
        maps.append(dict(image=str(im.path),values={hex(k):hex(v+im.base) for k,v in values.items()},fields={hex(k):hex(v) for k,v in fields.items()},sites={hex(k):hex(v) for k,v in sites.items()}))
    for a in anchors:
        mask=base64.b64decode(a['mask']);raw=base64.b64decode(a['pattern']);runs=list(re.finditer(b'\xff+',mask));longest=max(runs,key=lambda x:x.end()-x.start());a.update(literal=common.encoded(raw[longest.start():longest.end()]),literal_offset=longest.start())
    # Exact v1.62 detection preserves accepted on-disk UI, including briefing.
    existing=[dict(rva=va-0x400000,bytes=common.encoded(MOD.raw(va,n))) for va,n in hudsites]
    existing += [dict(rva=va-0x400000,bytes=common.encoded(MOD.raw(va,len(old)))) for va,old,_ in bp['patches']]
    spec=dict(version='1.0',template_base=C,payload_size=0x9000,writable_offset=0x8000,anchors=anchors,aliases=aliases,fixups=fixes,hooks=hooks,keyboard=[],required_keys=sorted(required),required_fields=[0xb4],existing=existing)
    out=HERE/'hud_runtime';out.mkdir(exist_ok=True)
    for name,data in [('hud_spec_v1.0.json',json.dumps(spec,separators=(',',':')).encode()),('hud_payload_v1.0.bin',bytes(payload)),('hud_correspondence_v1.0.json',json.dumps(maps,indent=2).encode())]:
        (out/name).write_bytes(data)
    print('HUD/briefing',len(anchors),'anchors',len(fixes),'fixups',len(hooks),'hooks; SF2/Normandy/ColdWar matched')

if __name__=='__main__':build()
