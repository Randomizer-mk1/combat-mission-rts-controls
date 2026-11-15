"""Selected-unit Q/E orbit without heading snap, v1.0. Output-only module.
Hook F6F220 replaces only the injected v1.43 selection-to-follow transition.
The real selection remains untouched; camera tracking B2C0/B2C4 is detached
only after a valid orbit proposal. Position and orientation rotate equally.
Native Vector-return ABI at 7C6324 uses out+4/+8/+C and callee cleanup.
"""
from pathlib import Path
import struct, hashlib, importlib.util
HERE=Path(__file__).resolve().parent
C=0xF73400
HOOK=0xF6F220
BASE_HASH="76c45a638a75618349ab039432b6f69bb02a4b03cea5da18afa675cb00951db1"
ORBIT_HASH="3a4e97bc84ebe8a22039d091674462e5b7670a243c5333a812b42fdcd9a7bbc3"
VERSION="1.0"
def rows():
 r=[];labels={}
 def e(s):r.append(s)
 def label(s):labels[s]=C+len(r)*16
 def m(n):return f"dword ptr [EBP+0x{n:x}]"
 def g(n):return f"dword ptr [EBX+0x{n-0x400000:x}]"
 def load(x,n):e(f"MOVSS {x},"+m(n))
 def store(n,x):e("MOVSS "+m(n)+f",{x}")
 # Entry inherits full original orbit save frame: ESI camera, EDI Game, EAX unit.
 e('CMP dword ptr [EDI+4],2');e('JZ @done');e('CMP dword ptr [EDI+4],3');e('JZ @done')
 e('CMP byte ptr [EAX+0xac],0');e('JZ @done');e('CMP '+g(0xe57b1c)+',0');e('JNZ @visible');e('CMP byte ptr [EAX+0xcc],0');e('JNZ @done')
 label('visible');e('LEA ECX,[EDI+0xb7e0]');e('CMP ECX,ESI');e('JNZ @done')
 e('MOV ECX,EAX');e('MOV EDX,dword ptr [ECX]');e('LEA EAX,[EBP+0xb8]');e('PUSH EAX');e('CALL dword ptr [EDX+0x4c]')
 # Pivot is the same native unit-position vector used by follow mode.
 for n in (0xbc,0xc0):
  e('MOV EAX,'+m(n));e('AND EAX,0x7f800000');e('CMP EAX,0x7f800000');e('JZ @done')
 e('MOV EAX,'+g(0xe53a94));e('TEST EAX,EAX');e('JZ @done');e('MOV EAX,dword ptr [EAX+0xc]');e('MOV ECX,0x6f');e('CMP EAX,ECX');e('CMOVA EAX,ECX');e('TEST EAX,EAX');e('JZ @done');e('CVTSI2SD XMM0,EAX')
 e('MULSD XMM0,qword ptr [EBX+0x7ab6d8]');load('XMM1',0x10);e('CVTSS2SD XMM1,XMM1');e('MULSD XMM1,XMM0')
 e('MOVSS XMM0,'+g(0xbacce4));e('DIVSS XMM0,dword ptr [ESI+0x34]');e('CVTSS2SD XMM0,XMM0');e('DIVSD XMM1,XMM0');e('CVTSD2SS XMM1,XMM1');store(0x80,'XMM1')
 e('MOV EAX,'+m(0x80));e('AND EAX,0x7f800000');e('CMP EAX,0x7f800000');e('JZ @done')
 load('XMM0',0x80);e('CALL 0x4e82e0');store(0x84,'XMM0');load('XMM0',0x80);e('CALL 0x4e8300');store(0x88,'XMM0')
 e('MOVSS XMM1,dword ptr [ESI+8]');e('SUBSS XMM1,'+m(0xbc));e('MOVSS XMM2,dword ptr [ESI+0xc]');e('SUBSS XMM2,'+m(0xc0))
 e('MOVAPS XMM0,XMM1');e('MULSS XMM0,'+m(0x84));e('MOVAPS XMM3,XMM2');e('MULSS XMM3,'+m(0x88));e('SUBSS XMM0,XMM3');e('ADDSS XMM0,'+m(0xbc));store(0xd4,'XMM0')
 e('MULSS XMM1,'+m(0x88));e('MULSS XMM2,'+m(0x84));e('ADDSS XMM1,XMM2');e('ADDSS XMM1,'+m(0xc0));store(0xd8,'XMM1')
 # Preserve above-ground height through the existing copied terrain interpolator.
 e('MOV EDI,dword ptr [EDI+0x14]');e('TEST EDI,EDI');e('JZ @done')
 for n,extent in ((0xd4,0xa0),(0xd8,0xa4),(8,0xa0),(0xc,0xa4)):
  if n<0x80:e(f'MOVSS XMM0,dword ptr [ESI+0x{n:x}]')
  else:load('XMM0',n)
  e('XORPS XMM1,XMM1');e('UCOMISS XMM0,XMM1');e('JP @done');e('JB @done');e(f'MOV EAX,dword ptr [EDI+0x{extent:x}]');e('DEC EAX');e('CVTSI2SS XMM1,EAX');e('DIVSS XMM1,dword ptr [EDI+0x38]');e('UCOMISS XMM0,XMM1');e('JP @done');e('JA @done')
 e('MOV ECX,EDI');e('MOVSS XMM1,dword ptr [ESI+8]');e('MOVSS XMM2,dword ptr [ESI+0xc]');e('CALL 0xf73000');store(0x8c,'XMM0')
 e('MOV ECX,EDI');load('XMM1',0xd4);load('XMM2',0xd8);e('CALL 0xf73000');e('SUBSS XMM0,'+m(0x8c));e('ADDSS XMM0,dword ptr [ESI+0x10]');store(0xdc,'XMM0')
 e('MOV EAX,'+m(0xdc));e('AND EAX,0x7f800000');e('CMP EAX,0x7f800000');e('JZ @done')
 e('MOV EDI,'+g(0xe57b10));e('MOV dword ptr [EDI+0xb2c0],0');e('MOV byte ptr [EDI+0xb2c4],0')
 for src,previous,n in ((8,0x4c,0xd4),(0xc,0x50,0xd8),(0x10,0x54,0xdc)):
  e(f'MOV EAX,dword ptr [ESI+0x{src:x}]');e(f'MOV dword ptr [ESI+0x{previous:x}],EAX');e('MOV EAX,'+m(n));e(f'MOV dword ptr [ESI+0x{src:x}],EAX')
 e('MOV ECX,ESI');load('XMM1',0x80);e('CALL 0x544e70')
 label('done');e('JMP 0xf6fea0')
 assert len(r)*16<=0xc00,len(r)
 return [(C+i*16, s.split('@')[0]+hex(labels[s.split('@')[1]]) if '@' in s else s) for i,s in enumerate(r)]
def emit():
 data=''.join(f'{va:08x}\t{s}\n' for va,s in rows())
 (HERE/'camera_selected_orbit_v1.0.asm').write_text(data,encoding='ascii')
 return len(rows())
def build(data,expected_sha256=BASE_HASH):
 spec=importlib.util.spec_from_file_location('yaw_guard',HERE/'camera_yaw_v1.0.py');mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);off=mod.offset
 data=bytes(data)
 if hashlib.sha256(data).hexdigest()!=expected_sha256:raise ValueError('Input hash mismatch')
 a=off(data,0xf6f000)
 if hashlib.sha256(data[a:a+0x4000]).hexdigest()!=ORBIT_HASH:raise ValueError('Original orbit differs')
 code=(HERE/'camera_selected_orbit_v1.0.bin').read_bytes()
 if len(code)!=len(rows())*16:raise ValueError('Payload length mismatch')
 # SHA locked after independent decoding.
 if hashlib.sha256(code).hexdigest()!=PAYLOAD_HASH:raise ValueError('Payload hash mismatch')
 h=off(data,HOOK);start=off(data,C)
 old=bytes.fromhex('3b87c0b20000')+b'\x90'*10
 if data[h:h+16]!=old or data[start:start+len(code)]!=b'\x90'*len(code):raise ValueError('Hook/cave differs')
 result=bytearray(data);result[start:start+len(code)]=code
 result[h:h+16]=b'\xe9'+struct.pack('<i',C-HOOK-5)+b'\x90'*11
 changed=[i for i,(x,y) in enumerate(zip(data,result)) if x!=y]
 if any(not(h<=i<h+16 or start<=i<start+len(code)) for i in changed):raise ValueError('Patch extent differs')
 return bytes(result),changed
PAYLOAD_HASH='2833ff0ca6b73caa6f390df4c9bb131d9ad268dbb8259c48cc0482f15e9bc229'
if __name__=='__main__':print('ASM instructions',emit())
