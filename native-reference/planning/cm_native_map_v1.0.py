"""Offline x86 address correspondence for the preserved SF2 and Cold War builds.

Only relocation operands and relative control-flow operands are masked. Object
field offsets, opcodes and register use remain exact. A unique match is evidence
for a code window, not permission to install a patch.
"""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from native_paths import SF2_ORIGINAL, COLDWAR_ORIGINAL, NORMANDY_IMAGE, INTERMEDIATES, capstone_path

import hashlib
import json
import re
import struct
import sys

capstone_path()
import capstone as cs

ROOT = Path(__file__).resolve().parent.parent
SF = SF2_ORIGINAL
CW = COLDWAR_ORIGINAL
SF_HASH = 'b3f3cea9f6e94f7b75746b1f2cee9b5d00efcedc0f440d301630be1797a07aa4'
CW_HASH = 'd44a0dc0ffd4165a4d223da924810aeae9397af54ac530722c9e3e8be22422ba'


class PE:
    def __init__(self, path, expected=None):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        self.hash = hashlib.sha256(self.data).hexdigest()
        if expected and self.hash != expected:
            raise ValueError('Unexpected executable: ' + str(path))
        b = self.data
        self.pe = self.u32(60)
        self.opt = self.pe + 24
        if b[:2] != b'MZ' or b[self.pe:self.pe+4] != b'PE\0\0' or self.u16(self.pe+4) != 0x14c or self.u16(self.opt) != 0x10b:
            raise ValueError('Expected x86 PE32')
        self.base = self.u32(self.opt+28)
        self.table = self.opt + self.u16(self.pe+20)
        self.sections = []
        for i in range(self.u16(self.pe+6)):
            p = self.table + i*40
            name, vs, rva, size, off = struct.unpack_from('<8sIIII', b, p)
            self.sections.append(dict(name=name.rstrip(b'\0').decode('ascii'), va=self.base+rva, vs=vs, size=size, off=off, flags=self.u32(p+36)))
        self.relocs = set()
        rva, size = struct.unpack_from('<II', b, self.opt+96+40)
        if size:
            p = self.off(self.base+rva)
            end = p+size
            while p < end:
                page, length = struct.unpack_from('<II', b, p)
                if length < 8 or p+length > end:
                    raise ValueError('Invalid relocation block')
                for q in range(p+8, p+length, 2):
                    v = self.u16(q)
                    if v >> 12 == 3:
                        self.relocs.add(self.base+page+(v & 4095))
                p += length
        self.md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_32)
        self.md.detail = True

    def u32(self, p): return struct.unpack_from('<I', self.data, p)[0]
    def u16(self, p): return struct.unpack_from('<H', self.data, p)[0]
    def off(self, va):
        for s in self.sections:
            if s['va'] <= va < s['va'] + s['size']:
                return s['off'] + va-s['va']
        raise ValueError('Not file-backed: ' + hex(va))
    def raw(self, va, n):
        p = self.off(va)
        if n and self.off(va+n-1) != p+n-1:
            raise ValueError('Noncontiguous span')
        return self.data[p:p+n]
    def ins(self, va, n=256):
        return list(self.md.disasm(self.raw(va,n),va))


FIELDS = {0x8a0,0xa7c,0xb2c0,0xb2c4,0xb7e0,0xb7e8,0xb7ec,0xb7f0}


def window(source, va, count, fields=False):
    ins = source.ins(va, max(512,count*15))[:count]
    if len(ins) != count:
        raise ValueError('Incomplete instruction window')
    size = ins[-1].address + ins[-1].size - va
    raw = source.raw(va,size)
    masked = set()
    for r in source.relocs:
        if va <= r < va+size:
            masked.update(range(r-va, r-va+4))
    for i in ins:
        if (i.group(cs.CS_GRP_CALL) or i.group(cs.CS_GRP_JUMP)) and i.operands and i.operands[0].type == cs.x86.X86_OP_IMM:
            masked.update(range(i.address-va+i.imm_offset, i.address-va+i.imm_offset+i.imm_size))
        if fields and any(o.type==cs.x86.X86_OP_MEM and o.mem.disp in FIELDS for o in i.operands):
            masked.update(range(i.address-va+i.disp_offset,i.address-va+i.disp_offset+i.disp_size))
    pattern = b''.join(b'.' if i in masked else re.escape(bytes([v])) for i,v in enumerate(raw))
    return ins, re.compile(pattern,re.DOTALL)


def match(source, target, va, counts=(48,32,24,16,12,8), fields=False):
    for count in counts:
        ins, pattern = window(source,va,count,fields)
        hits=[]
        for s in target.sections:
            if s['flags'] & 0x20000000:
                area=target.data[s['off']:s['off']+s['size']]
                for m in pattern.finditer(area):
                    hits.append(s['va']+m.start())
        if len(hits)==1:
            dst=hits[0]
            other=target.ins(dst,ins[-1].address+ins[-1].size-va)
            if len(other)!=count or any(a.id!=b.id or a.size!=b.size for a,b in zip(ins,other)):
                raise ValueError('Matched window decoded differently')
            pairs=[]
            for a,b in zip(ins,other):
                if fields and a.disp_size and any(o.type==cs.x86.X86_OP_MEM and o.mem.disp in FIELDS for o in a.operands):
                    av=next(o.mem.disp for o in a.operands if o.type==cs.x86.X86_OP_MEM)
                    bv=next(o.mem.disp for o in b.operands if o.type==cs.x86.X86_OP_MEM)
                    pairs.append((av,bv,'field',a.address,b.address))
                for n in range(a.size):
                    if a.address+n in source.relocs:
                        av=source.u32(source.off(a.address+n));bv=target.u32(target.off(b.address+n))
                        pairs.append((av,bv,'relocation',a.address,b.address))
                if (a.group(cs.CS_GRP_CALL) or a.group(cs.CS_GRP_JUMP)) and a.operands[0].type==cs.x86.X86_OP_IMM:
                    pairs.append((a.operands[0].imm,b.operands[0].imm,'branch',a.address,b.address))
            return dict(source=va,target=dst,instructions=count,bytes=ins[-1].address+ins[-1].size-va,pairs=pairs)
    return dict(source=va,target=None)


def main():
    source=PE(SF,SF_HASH);target=PE(CW,CW_HASH)
    seeds=[0x549c91,0x549d37,0x549d8d,0x54a1d0,0x54a700,0x6f9d80,0x610d43,0x743cdd,0x7920d0,0x792110,0x7919f0,0x4f64c0,0x544e70,0x4e82a0,0x7c7a60,0x741930,0x54abb0]
    if len(sys.argv)>1:seeds=[int(v,0) for v in sys.argv[1:]]
    rows=[match(source,target,va) for va in seeds]
    out=ROOT/'planning/coldwar_native_correspondence_v1.0.json'
    if len(sys.argv)==1:
        if out.exists(): raise FileExistsError(out)
        out.write_text(json.dumps(dict(source_sha256=source.hash,target_sha256=target.hash,windows=rows),indent=2),encoding='utf-8')
    for r in rows:
        print(hex(r['source']), hex(r['target']) if r['target'] else 'UNRESOLVED',r.get('instructions'),r.get('bytes'))


if __name__=='__main__':main()
