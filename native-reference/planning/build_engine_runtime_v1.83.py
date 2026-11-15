"""Build address-independent Camera Control Fix engine matching data v1.83."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from native_paths import SF2_ORIGINAL, COLDWAR_ORIGINAL, NORMANDY_IMAGE, INTERMEDIATES, capstone_path

import base64
import hashlib
import importlib.util
import json
import re
import struct

HERE=Path(__file__).resolve().parent
sp=importlib.util.spec_from_file_location('mapper',HERE/'cm_native_map_v1.0.py')
m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
m.FIELDS.update([0xb2ac,0xb7f8,0xb7fc])
SF=m.PE(m.SF,m.SF_HASH);CW=m.PE(m.CW,m.CW_HASH)
MOD=m.PE(INTERMEDIATES/'SF2_ReadableUI_NativeCamera_v1.55.exe','2dbe63635ba0bab9e1e60cade1900c5c7e4a43e6b15ba304410447a283a6daf5')
C=0xf6b000


def encoded(b):return base64.b64encode(b).decode('ascii')


def anchor(va,count):
    ins=SF.ins(va,count*15)[:count]
    size=ins[-1].address+ins[-1].size-va
    raw=SF.raw(va,size);mask=bytearray([255]*size);extract=[]
    for i in ins:
        for pos in range(i.size):
            if i.address+pos in SF.relocs:
                off=i.address-va+pos
                mask[off:off+4]=bytes(4)
                extract.append(dict(kind='module',key=SF.u32(SF.off(i.address+pos)),offset=off,size=4))
        if i.operands and (i.group(m.cs.CS_GRP_CALL) or i.group(m.cs.CS_GRP_JUMP)) and i.operands[0].type==m.cs.x86.X86_OP_IMM:
            dest=i.operands[0].imm
            if not va<=dest<va+size:
                off=i.address-va+i.imm_offset
                mask[off:off+i.imm_size]=bytes(i.imm_size)
                extract.append(dict(kind='branch',key=dest,offset=off,size=i.imm_size,end=i.address-va+i.size))
        if i.disp_size and any(o.type==m.cs.x86.X86_OP_MEM and o.mem.disp in m.FIELDS for o in i.operands):
            field=next(o.mem.disp for o in i.operands if o.type==m.cs.x86.X86_OP_MEM)
            off=i.address-va+i.disp_offset;mask[off:off+i.disp_size]=bytes(i.disp_size)
            extract.append(dict(kind='field',key=field,offset=off,size=i.disp_size))
    literal=max(re.finditer(b'\xff+',bytes(mask)),key=lambda x:x.end()-x.start())
    return dict(key=va,pattern=encoded(raw),mask=encoded(mask),literal_offset=literal.start(),literal=encoded(raw[literal.start():literal.end()]),extract=extract)


def matches(image,a):
    raw=base64.b64decode(a['pattern']);mask=base64.b64decode(a['mask'])
    rx=re.compile(b''.join(re.escape(bytes([v])) if mask[i] else b'.' for i,v in enumerate(raw)),re.S)
    hits=[]
    for sec in image.sections:
        if sec['flags'] & 0x20000000:
            area=image.data[sec['off']:sec['off']+sec['size']]
            hits += [sec['va']+h.start() for h in rx.finditer(area)]
    return hits


def resolve(image,anchors):
    values={};fields={};sites={}
    def add(d,k,v):
        if k in d and d[k]!=v:raise ValueError(f'Conflicting mapping {k:x}: {d[k]:x}, {v:x}')
        d[k]=v
    for a in anchors:
        hits=matches(image,a)
        if len(hits)!=1:raise ValueError(f'Anchor {a["key"]:x}: {len(hits)} hits in {image.path}')
        at=hits[0];add(values,a['key'],at-image.base);sites[a['key']]=at
        for ex in a['extract']:
            raw=image.raw(at+ex['offset'],ex['size'])
            val=int.from_bytes(raw,'little',signed=ex['kind']=='branch')
            if ex['kind']=='field':add(fields,ex['key'],val)
            elif ex['kind']=='branch':add(values,ex['key'],at+ex['end']+val-image.base)
            else:add(values,ex['key'],val-image.base)
    return values,fields,sites


def build():
    seeds=[0x549c91,0x549d37,0x549d8d,0x54a1d0,0x54a700,0x6f9d80,0x610d43,0x743cdd,0x7920d0,0x792110,0x544e70,0x4e82a0,0x4e82e0,0x4e8300,0x545da0,0x545f50,0x7c7a60,0x54abb0,0x503a70,0x5499e3,0x543836,0x738cfc,0x738d07]
    anchors=[]
    for va in seeds:
        hit=m.match(SF,CW,va,fields=True)
        if not hit['target']:raise ValueError(f'No build correspondence: {va:x}')
        anchors.append(anchor(va,hit['instructions']))
    for va,end in [(0x4f64c0,0x4f6705),(0x7919f0,0x791afa),(0x7c63af,0x7c6d34)]:
        anchors.append(anchor(va,len(SF.ins(va,end-va))))
    maps=[resolve(im,anchors) for im in (SF,CW)]
    payload=bytearray(MOD.raw(C,0x11000)+MOD.raw(C+0x11000,0x200)+bytes(0xe00))
    payload[0x9000:0xa000]=b'\x90'*0x1000 # omit SF2-only briefing code
    fixes=[];required=set();fields=set()
    for begin,length in [(0,0x9000),(0xa000,0x7000)]:
        ins=list(MOD.md.disasm(payload[begin:begin+length],C+begin))
        if ins[-1].address+ins[-1].size != C+begin+length:raise ValueError('Incomplete template decode')
        for i in ins:
            pos=i.address-C
            if i.operands and (i.group(m.cs.CS_GRP_CALL) or i.group(m.cs.CS_GRP_JUMP)) and i.operands[0].type==m.cs.x86.X86_OP_IMM:
                dest=i.operands[0].imm
                if not C<=dest<C+0x11000:
                    if i.imm_size!=4:raise ValueError('External short branch')
                    fixes.append(dict(kind='relative',offset=pos+i.imm_offset,key=dest,end=pos+i.size));required.add(dest)
            for o in i.operands:
                if o.type==m.cs.x86.X86_OP_MEM:
                    if o.mem.base in (m.cs.x86.X86_REG_EBX,m.cs.x86.X86_REG_EAX) and o.mem.disp>=0x100000:
                        if i.disp_size!=4:raise ValueError('PIC displacement width')
                        native=o.mem.disp+0x400000
                        if C<=native<C+0x12000:fixes.append(dict(kind='private',offset=pos+i.disp_offset,key=native-C))
                        else:fixes.append(dict(kind='module',offset=pos+i.disp_offset,key=native));required.add(native)
                    elif o.mem.disp in m.FIELDS:
                        if i.disp_size!=4:raise ValueError('Field displacement width')
                        fixes.append(dict(kind='field',offset=pos+i.disp_offset,key=o.mem.disp));fields.add(o.mem.disp)
                    elif o.mem.base==0 and o.mem.disp>=0x400000:raise ValueError('Untranslated absolute reference')
            if i.mnemonic=='sub' and i.operands[0].type==m.cs.x86.X86_OP_REG and i.operands[0].reg in (m.cs.x86.X86_REG_EBX,m.cs.x86.X86_REG_EAX) and i.operands[1].type==m.cs.x86.X86_OP_IMM and i.operands[1].imm>=0x100000:
                fixes.append(dict(kind='base',offset=pos+i.imm_offset,key=i.operands[1].imm-(C-0x400000)))
    # Return-to-native addresses derive from complete displaced entry instructions.
    aliases=[dict(key=0x610d49,source=0x610d43,delta=6),dict(key=0x6f9d85,source=0x6f9d80,delta=5)]
    hooks=[]
    for va,n in [(0x6f9d80,5),(0x610d43,6),(0x54a1d0,5),(0x549d8d,5),(0x743cdd,6)]:
        patched=MOD.raw(va,n);dest=va+5+struct.unpack_from('<i',patched,1)[0]
        if not C<=dest<C+0x11000:raise ValueError('Unexpected template hook')
        hooks.append(dict(key=va,size=n,opcode=patched[0],payload_target=dest-C))
    keyboard=[]
    for va,key in [(0x549c91,0xbab5b4),(0x549cb5,0xbad154),(0x549ce1,0xbad154),(0x549d05,0xbab5b4)]:
        keyboard.append(dict(key=0x549c91,delta=va-0x549c91,size=8,offset=4,module_value=key));required.add(key)
    for va in [0x549cbd,0x549d0d]:keyboard.append(dict(key=0x549c91,delta=va-0x549c91,size=10,offset=1,byte_value=0))
    for vals,fs,_ in maps:
        for a in aliases:vals[a['key']]=vals[a['source']]+a['delta']
        if required-vals.keys() or fields-fs.keys():raise ValueError(('Missing refs',required-vals.keys(),fields-fs.keys()))
    existing=[dict(rva=h['key']-0x400000,bytes=encoded(MOD.raw(h['key'],h['size']))) for h in hooks]
    spec=dict(version='1.83',template_base=C,payload_size=0x12000,writable_offset=0x11000,anchors=anchors,aliases=aliases,fixups=fixes,hooks=hooks,keyboard=keyboard,required_keys=sorted(required),required_fields=sorted(fields),existing=existing)
    out=HERE/'runtime';out.mkdir(exist_ok=True)
    for name,data in [('engine_spec_v1.83.json',json.dumps(spec,separators=(',',':')).encode()),('engine_payload_v1.83.bin',bytes(payload))]:
        path=out/name
        if (out/'RELEASED-v1.83').exists():raise FileExistsError('Released engine data is immutable')
        path.write_bytes(data);print(path.name,len(data),hashlib.sha256(data).hexdigest())
    print('MATCHED',len(anchors),'anchors across SF2 and Cold War;',len(fixes),'payload fixups;',len(hooks)+len(keyboard),'native edits')
    print('FIELD_MAP', {hex(k):hex(maps[1][1][k]) for k in fields})


if __name__=='__main__':build()
