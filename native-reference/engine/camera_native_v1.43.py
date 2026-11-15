"""Output-only SF2 native MMB camera and Q/E ground-orbit candidate v1.43. No install or game launch."""
import importlib.util,struct,hashlib,json,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
def module(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
pan=module('pan',HERE/'constant_pan_v1.10.py')
probe=module('probe',HERE.parent/'input/native_hit_probe_v1.0.py')
original=pan.SOURCE.read_bytes()
assert pan.digest(original)==pan.SOURCE_HASH
base=0x400000
u32=lambda b,o:struct.unpack_from('<I',b,o)[0]
align=lambda n,a:(n+a-1)&-a
pe=u32(original,0x3c);opt=pe+24;st=opt+struct.unpack_from('<H',original,pe+20)[0]
n=struct.unpack_from('<H',original,pe+6)[0]
assert n==6 and st+(n+2)*40<=u32(original,opt+60)
last=st+(n-1)*40
code_rva=align(u32(original,last+12)+max(u32(original,last+8),u32(original,last+16)),0x1000)
C=base+code_rva;D=code_rva+0x11000;P=C+0x3000
lines=[];labels={}
def emit(s):lines.append(s)
def label(s):labels[s]=C+len(lines)*16
def mem(off):return f'dword ptr [EBX+0x{D+off:x}]'
def glob(va):return f'dword ptr [EBX+0x{va-base:x}]'
def pic(tag):
 emit('CALL @'+tag); ret=C+(len(lines)-1)*16+5
 label(tag);emit('POP EBX');emit(f'SUB EBX,0x{ret-base:x}')
def save():
 emit('PUSHFD');emit('PUSHAD');emit('SUB ESP,0x80');emit('MOV EAX,ESP')
 for i in range(8):emit(f'MOVDQU xmmword ptr [EAX+0x{i*16:x}],XMM{i}')
 emit('MOV EBP,ESP');emit('ADD EBP,0xa4')
def restore():
 emit('MOV EAX,ESP')
 for i in range(8):emit(f'MOVDQU XMM{i},xmmword ptr [EAX+0x{i*16:x}]')
 emit('ADD ESP,0x80');emit('POPAD');emit('POPFD')
label('entry');save();emit('MOV ESI,ECX');pic('base')
emit('CMP dword ptr [EBP+4],0');emit('JNZ @nonmove')
emit('CMP '+mem(0)+',3');emit('JZ @drain')
emit('PUSH 4');emit('CALL '+glob(0x9cc40c));emit('TEST AX,0x8000');emit('JZ @release')
emit('CMP '+mem(0)+',2');emit('JZ @fallback')
emit('CMP byte ptr [ESI+0x25],0');emit('JNZ @block')
# Match native game/modal eligibility; do not infer battlefield identity from root hit.
for vk in (1,2):
 emit(f'PUSH {vk}');emit('CALL '+glob(0x9cc40c));emit('TEST AX,0x8000');emit('JNZ @conflict')
emit('CMP '+glob(0xe9c564)+',0');emit('JNZ @block')
emit('MOV EDI,'+glob(0xe57b10));emit('TEST EDI,EDI');emit('JZ @block')
emit('CMP dword ptr [EDI+4],3');emit('JZ @block')
emit('CMP dword ptr [EDI+0x10],0');emit('JZ @block')
emit('MOV ECX,dword ptr [EDI+0x44]');emit('TEST ECX,ECX');emit('JZ @menu_ok')
emit('CALL 0x7920d0');emit('TEST AL,AL');emit('JNZ @block');label('menu_ok')
emit('MOV ECX,dword ptr [ESI+0x34]');emit('TEST ECX,ECX');emit('JZ @block')
emit('MOV EAX,dword ptr [ECX+0x40]');emit('SUB EAX,dword ptr [ECX+0x3c]');emit('CMP EAX,4');emit('JG @block')
emit('CMP '+mem(0)+',1');emit('JNZ @begin')
# Native function consumes an anchor object in ECX and current x/y on the stack.
# It retains the game's original dead zones, time scaling, pitch constraints and feel.
emit('PUSH dword ptr [EBP+0xc]');emit('PUSH dword ptr [EBP+8]')
emit(f'LEA ECX,[EBX+0x{D-4:x}]');emit('CALL 0x54a700');emit('JMP @consume')
label('begin');emit('MOV '+mem(0)+',1');emit('CALL @remember');emit('JMP @consume')
label('remember');emit('MOV EAX,dword ptr [EBP+8]');emit('MOV '+mem(4)+',EAX');emit('MOV EAX,dword ptr [EBP+0xc]');emit('MOV '+mem(8)+',EAX');emit('RET')
label('nonmove');emit('CMP '+mem(0)+',1');emit('JZ @drain_start');emit('CMP '+mem(0)+',3');emit('JZ @consume');emit('JMP @block')
label('conflict');emit('CMP '+mem(0)+',1');emit('JZ @drain_start');emit('JMP @block')
label('drain_start');emit('MOV '+mem(0)+',3');emit('JMP @consume')
label('drain')
for vk in (1,2,4):
 emit(f'PUSH {vk}');emit('CALL '+glob(0x9cc40c));emit('TEST AX,0x8000');emit('JNZ @consume')
label('release');emit('MOV '+mem(0)+',0');emit('JMP @fallback')
label('block');emit('MOV '+mem(0)+',2');emit('JMP @fallback')
label('consume');restore();emit('RET 0xc')
label('fallback');restore();emit('PUSH ECX');emit('PUSH EBX');emit('MOV EBX,ECX');emit('PUSH ESI');emit('JMP 0x6f9d85')
label('focus');emit('PUSHFD');emit('PUSH EAX');emit('PUSH EBX');pic('focus_base')
emit('MOV '+mem(0)+',2');emit('MOV ECX,'+glob(0xe538d0));emit('POP EBX');emit('POP EAX');emit('POPFD');emit('JMP 0x610d49')
# Suppress only the RTS LMB camera-drag call; leave its button events and UI routes intact.
label('left_camera_gate');emit('PUSH EAX');emit('PUSH EBX');pic('left_base')
emit('MOV EAX,'+glob(0xe57b18));emit('CMP dword ptr [EAX+0xa7c],1');emit('JNZ @left_native')
emit('MOV EAX,'+glob(0xe57b14));emit('CMP byte ptr [EAX+4],0');emit('JZ @left_native')
emit('POP EBX');emit('POP EAX');emit('RET 8')
label('left_native');emit('POP EBX');emit('POP EAX');emit('JMP 0x54a700')
# RTS-only wheel entry: native saved ESI is popped before our own save frame.
while len(lines)*16<0x2000:emit('NOP')
label('wheel_entry');emit('POP ESI');save();pic('wheel_base')
emit('MOV EAX,'+glob(0xe57b10));emit('TEST EAX,EAX');emit('JZ @wheel_fallback')
emit('MOV EAX,dword ptr [EAX+0x20]');emit('TEST EAX,EAX');emit('JZ @wheel_fallback');emit('MOV '+mem(40)+',EAX')
emit('MOV ESI,'+glob(0xe63058));emit('MOV EDI,'+glob(0xe63054))
emit('MOV ECX,'+glob(0xe53a94));emit('MOV ECX,dword ptr [ECX+0x34]');emit('TEST ECX,ECX');emit('JZ @wheel_fallback')
emit('MOV EAX,dword ptr [ECX+0x40]');emit('CMP EAX,dword ptr [ECX+0x3c]');emit('JZ @wheel_fallback')
emit('SUB EAX,4');emit('MOV ECX,dword ptr [EAX]')
emit('PUSH 0');emit('PUSH EDI');emit('PUSH ESI');emit('PUSH 0');emit(f'CALL 0x{C+0x3000:x}')
emit('CMP EAX,'+mem(40));emit('JNZ @wheel_fallback');emit('MOV ECX,EAX')
# Native GameView rectangle uses signed short origin and dimensions, bottom-up Y.
for coord,origin,size,xmm in [('ESI',0x10,0x14,'XMM1'),('EDI',0x12,0x16,'XMM2')]:
 emit(f'MOVSX EAX,word ptr [ECX+0x{origin:x}]');emit(f'SUB {coord},EAX');emit(f'TEST {coord},{coord}');emit('JS @wheel_fallback')
 emit(f'MOVSX EAX,word ptr [ECX+0x{size:x}]');emit('TEST EAX,EAX');emit('JLE @wheel_fallback');emit(f'CMP {coord},EAX');emit('JGE @wheel_fallback')
 emit(f'CVTSI2SS {xmm},{coord}');emit('CVTSI2SS XMM0,EAX');emit(f'DIVSS {xmm},XMM0')
emit('MOV EAX,'+glob(0xe57b10));emit('MOV ECX,dword ptr [EAX+0x10]');emit('MOV EDI,dword ptr [EAX+0x14]');emit('MOV EDX,dword ptr [EBP+4]');emit(f'CALL 0x{C+0xa000:x}')
restore();emit('RET 4')
label('wheel_fallback');restore();emit('RET 4');emit('NOP');emit('NOP')
assert len(lines)*16<0x3000
for i,s in enumerate(lines):
 for k,v in labels.items():s=s.replace('@'+k+' ',f'0x{v:x} ')
 if '@' in s:
  head,key=s.split('@');s=head+hex(labels[key])
 lines[i]=s
orbit=module('orbit',HERE/'native_orbit_v1.33.py').build(original,C+0x4000)
wheel=module('wheel',HERE/'wheel_cursor_v1.0.py').build(original,C+0xa000)
asm=HERE/'camera_native_v1.43.asm'
if '--emit' in sys.argv:
 asm.write_text('\n'.join([f'{C+i*16:08x}\t{s}' for i,s in enumerate(lines)]+[f'{va:08x}\t{s}' for va,s in orbit['instructions']]+[f'{va:08x}\t{s}' for va,s in wheel['instructions']])+'\n',encoding='ascii')
 print('ASM',len(lines),'instructions',hex(C),'focus',hex(labels['focus']));sys.exit()
code=(HERE/'camera_native_v1.43.bin').read_bytes();assert len(code)==wheel['instructions'][-1][0]-C+16
payload,_=pan.build(original)
b=bytearray(payload)
raw=align(len(b),0x200);b.extend(bytes(raw-len(b)))
section=bytearray(b'\x90'*0x11000);section[:len(code)]=code
section[0x8000:0x8000+len(orbit['terrain_blob'])]=orbit['terrain_blob']
fragment=probe.build_probe(original,C+0x3000);section[0x3000:0x3000+len(fragment)]=fragment
section[0x10000:0x10000+len(wheel['terrain_blob'])]=wheel['terrain_blob']
b.extend(section);state=bytearray(0x200);struct.pack_into('<I',state,0,2)
struct.pack_into('<ff',state,32,0.003,-0.003);b.extend(state)
for idx,(name,vs,rva,rs,rp,flags) in enumerate([(b'.mmbcode',0x11000,code_rva,0x11000,raw,0x60000020),(b'.mmbdata',0x1000,D,0x200,raw+0x11000,0xc0000040)]):
 struct.pack_into('<8sIIIIIIHHI',b,st+(n+idx)*40,name,vs,rva,rs,rp,0,0,0,0,flags)
struct.pack_into('<H',b,pe+6,n+2);struct.pack_into('<I',b,opt+56,D+0x1000)
struct.pack_into('<I',b,opt+4,u32(b,opt+4)+0x11000);struct.pack_into('<I',b,opt+8,u32(b,opt+8)+0x200)
struct.pack_into('<I',b,opt+64,0) # modified-image checksum
hooks=[(0x6f9d80,bytes.fromhex('51538bd956'),labels['entry']),(0x610d43,bytes.fromhex('8b0dd038e500'),labels['focus'])]
hooks.append((0x54a1d0,bytes.fromhex('e82b050000'),labels['left_camera_gate']))
hooks.append((orbit['hook_va'],orbit['hook_original'],orbit['entry']))
hooks.append((0x743cdd,bytes.fromhex('85d25e0f9fc0'),labels['wheel_entry']))
for va,old,target in hooks:
 off=pan.file_offset(original,va);assert original[off:off+len(old)]==old
 b[off:off+len(old)]=(b'\xe8' if va in (0x54a1d0,orbit['hook_va']) else b'\xe9')+struct.pack('<i',target-va-5)+b'\x90'*(len(old)-5)
# Remove the relocation for the displaced absolute MOV operand; replay is PIC.
rr,sz=struct.unpack_from('<II',original,opt+96+5*8);rp=pan.file_offset(original,base+rr);end=rp+sz;removed=[]
while rp<end:
 page,size=struct.unpack_from('<II',original,rp)
 if not size:break
 for q in range(rp+8,rp+size,2):
  v=struct.unpack_from('<H',original,q)[0]
  if v>>12==3 and base+page+(v&4095)==0x610d45:
   struct.pack_into('<H',b,q,0);removed.append(q)
 rp+=size
assert len(removed)==1
# The copied probe must have no embedded original absolute-relocation operands.
rp=pan.file_offset(original,base+rr)
while rp<end:
 page,size=struct.unpack_from('<II',original,rp)
 if not size:break
 for q in range(rp+8,rp+size,2):
  v=struct.unpack_from('<H',original,q)[0];va=base+page+(v&4095)
  assert not(v>>12==3 and probe.START<=va<probe.END),'Probe needs an additional relocation'
 rp+=size
out=HERE/'candidates/SF2_NativeOrbit_Mmb_Wheel_Pan60_Yaw60_v1.43.exe'
with out.open('xb') as f:f.write(b)
assert out.read_bytes()==b
print('CANDIDATE',out,'SHA256',hashlib.sha256(b).hexdigest(),'SIZE',len(b))
print('HOOKS',hooks,'RELOCATION_REMOVED',removed,'RUNTIME NOT RUN')
