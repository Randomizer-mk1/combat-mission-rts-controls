"""SF2 centered uniformly scaled HUD and input candidate v1.55. Output only."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from native_paths import SF2_ORIGINAL, COLDWAR_ORIGINAL, NORMANDY_IMAGE, INTERMEDIATES, capstone_path

import struct, hashlib, sys, re
HERE=Path(__file__).resolve().parent
SOURCE=INTERMEDIATES/'SF2_NativeOrbit_Mmb_Wheel_Pan60_Yaw60_v1.43.exe'
SHA='76c45a638a75618349ab039432b6f69bb02a4b03cea5da18afa675cb00951db1'
baseline=SOURCE.read_bytes(); assert hashlib.sha256(baseline).hexdigest()==SHA
u32=lambda b,o:struct.unpack_from('<I',b,o)[0]
align=lambda n,a:(n+a-1)&-a
pe=u32(baseline,60);opt=pe+24;n=struct.unpack_from('<H',baseline,pe+6)[0];st=opt+struct.unpack_from('<H',baseline,pe+20)[0]
assert n==8 and st+(n+2)*40<=u32(baseline,opt+60)
sections=[struct.unpack_from('<IIII',baseline,st+i*40+8) for i in range(n)]
def off(va):
 r=va-0x400000
 return next(r-v+p for z,v,s,p in sections if v<=r<v+s)
C=0x400000+align(max(v+max(z,s) for z,v,s,p in sections),4096);D=C+0x8000
L=[];labels={}
def e(s):L.append(s)
def label(s):assert s not in labels;labels[s]=C+16*len(L)
def m(o):return f'dword ptr [EBP+0x{o:x}]'
def g(a):return f'dword ptr [EBX+0x{a-0x400000:x}]'
def data(o):return g(D+o)
def pic(tag):
 e('CALL @'+tag);ret=C+16*(len(L)-1)+5;label(tag);e('POP EBX');e(f'SUB EBX,0x{ret-0x400000:x}')
def save(tag):
 e('PUSHFD');e('PUSHAD');e('SUB ESP,0x100');e('MOV EBP,ESP')
 for i in range(8):e(f'MOVDQU xmmword ptr [EBP+0x{i*16:x}],XMM{i}')
 pic(tag)
def restore():
 for i in range(8):e(f'MOVDQU XMM{i},xmmword ptr [EBP+0x{i*16:x}]')
 e('ADD ESP,0x100');e('POPAD');e('POPFD')
# Local context: 80 HUD,84 numerator /768,88 screen W,8C logical root X.
# D8 physical HUD width,DC centered physical HUD left; original panel spacing is preserved.
# Panel: 90 pointer,94 physical X,98 physical Y,9C W,A0 H,A4 original X,A8 original Y.
# Working B0..DC. Saved regs 100..11C, flags120, entry stack124.
label('viewport');save('vp_base');e('MOV EAX,'+m(0x108));e('MOV '+m(0xb0)+',EAX');e('JMP @vp_begin')
label('viewport_restore');save('vr_base');e('MOV EAX,'+m(0x118));e('MOV '+m(0xb0)+',EAX')
label('vp_begin');e('CALL @resolve');e('CALL @context')
e('CMP '+m(0x80)+',0');e('JZ @vp_identity')
e('MOV ESI,'+m(0xb0));e('CALL @find_panel');e('TEST ESI,ESI');e('JZ @vp_identity')
e('CMP ESI,'+m(0x80));e('JZ @vp_root');e('CALL @panel_rect')
# Four glViewport arguments already on the original stack.
e('MOV EAX,'+m(0x128));e('SUB EAX,'+m(0xa4));e('MOV '+m(0xb4)+',EAX');e('CALL @scaled');e('MOV '+m(0xb8)+',EAX');e('ADD EAX,'+m(0x94));e('MOV '+m(0x128)+',EAX')
e('MOV EAX,'+m(0xb4));e('ADD EAX,'+m(0x130));e('CALL @scaled');e('SUB EAX,'+m(0xb8));e('MOV '+m(0x130)+',EAX')
e('MOV EAX,'+m(0x12c));e('SUB EAX,'+m(0xa8));e('MOV '+m(0xb4)+',EAX');e('CALL @scaled');e('MOV '+m(0xb8)+',EAX');e('ADD EAX,'+m(0x98));e('MOV '+m(0x12c)+',EAX')
e('MOV EAX,'+m(0xb4));e('ADD EAX,'+m(0x134));e('CALL @scaled');e('SUB EAX,'+m(0xb8));e('MOV '+m(0x134)+',EAX');e('JMP @vp_scaled')
label('vp_root');e('MOV EAX,'+m(0xdc));e('MOV '+m(0x128)+',EAX');e('MOV EAX,'+m(0xd8));e('MOV '+m(0x130)+',EAX');e('MOV EAX,'+m(0x12c));e('CALL @scaled');e('MOV '+m(0x12c)+',EAX');e('MOV EAX,'+m(0x134));e('CALL @scaled');e('MOV '+m(0x134)+',EAX')
label('vp_scaled');e('CVTSI2SS XMM0,'+m(0x84));e('MOV EAX,768');e('CVTSI2SS XMM1,EAX');e('DIVSS XMM0,XMM1');e('MOVD EAX,XMM0');e('JMP @vp_zoom')
label('vp_identity');e('MOV EAX,0x3f800000')
label('vp_zoom');e('CALL @set_zoom');e('MOV EAX,'+g(0x9cc320));e('MOV '+m(0x11c)+',EAX');restore();e('JMP EAX')
# Both native viewport setup paths use the same HUD affine transform and pixel zoom.
# Native mouse dispatcher is hooked after the unchanged v1.43 MMB trampoline.
label('input');save('in_base');e('MOV '+data(4)+',0');e('MOV EAX,'+m(0x138));e('MOV '+data(8)+',EAX');e('MOV EAX,'+m(0x13c));e('MOV '+data(12)+',EAX');e('CALL @context');e('CMP '+m(0x80)+',0');e('JZ @in_done')
e('MOV ESI,'+m(0x80));e('CALL @eligible');e('TEST AL,AL');e('JZ @in_done')
# Require the HUD's ancestor to be the current top-level view; exclude modal dialogs.
e('MOV EAX,'+g(0xe53a94));e('MOV EAX,dword ptr [EAX+0x34]');e('TEST EAX,EAX');e('JZ @in_done');e('MOV ECX,dword ptr [EAX+0x40]');e('CMP ECX,dword ptr [EAX+0x3c]');e('JZ @in_done');e('MOV EDI,dword ptr [ECX+-0x4]');e('MOV ESI,'+m(0x80));e('MOV ECX,64')
label('top_walk');e('CMP ESI,EDI');e('JZ @top_ok');e('MOV ESI,dword ptr [ESI+4]');e('TEST ESI,ESI');e('JZ @in_done');e('DEC ECX');e('JNZ @top_walk');e('JMP @in_done')
label('top_ok');e('MOV ESI,'+g(0xe9c564));e('TEST ESI,ESI');e('JZ @in_bounds');e('CALL @eligible');e('TEST AL,AL');e('JZ @in_done');e('CALL @find_panel');e('TEST ESI,ESI');e('JZ @in_done');e('CMP ESI,'+m(0x80));e('JZ @in_bounds');e('CALL @panel_rect');e('JMP @in_inverse')
label('in_bounds');e('CMP '+m(0x138)+',0');e('JL @in_done');e('MOV EAX,'+m(0x88));e('CMP '+m(0x138)+',EAX');e('JGE @in_done');e('MOV EAX,164');e('CALL @scaled');e('CMP '+m(0x13c)+',0');e('JL @in_done');e('CMP '+m(0x13c)+',EAX');e('JGE @in_done');e('MOV EAX,'+m(0x138));e('SUB EAX,'+m(0xdc));e('JS @in_margin');e('CMP EAX,'+m(0xd8));e('JGE @in_margin')
e('MOV ESI,'+m(0x80));e('MOV EDI,dword ptr [ESI+0x40]');e('MOV EAX,dword ptr [ESI+0x3c]');e('MOV '+m(0xc0)+',EAX')
label('in_panels');e('CMP EDI,'+m(0xc0));e('JZ @in_gap');e('SUB EDI,4');e('MOV ESI,dword ptr [EDI]');e('CALL @eligible');e('TEST AL,AL');e('JZ @in_panels');e('CALL @panel_rect')
for value,start,size in [(0x138,0x94,0x9c),(0x13c,0x98,0xa0)]:
 e('MOV EAX,'+m(value));e('SUB EAX,'+m(start));e('JS @in_panels');e('CMP EAX,'+m(size));e('JGE @in_panels')
label('in_inverse')
for value,start,origin in [(0x138,0x94,0xa4),(0x13c,0x98,0xa8)]:
 e('MOV EAX,'+m(value));e('SUB EAX,'+m(start));e('CALL @unscaled');e('ADD EAX,'+m(origin));e('MOV '+m(value)+',EAX')
e('JMP @in_done')
label('in_gap');e('MOV '+data(4)+',1');e('MOV EAX,'+m(0x80));e('MOV '+data(16)+',EAX');e('MOV EAX,'+m(0x8c));e('MOV '+m(0x138)+',EAX');e('MOV '+m(0x13c)+',0');e('JMP @in_done')
# Side margins skip only the HUD hit test; preserve raw input for the world and other views.
label('in_margin');e('MOV '+data(4)+',2');e('MOV EAX,'+m(0x80));e('MOV '+data(16)+',EAX')
label('in_done');e('MOV EAX,'+m(0x138));e('MOV '+g(0xe63058)+',EAX');e('MOV EAX,'+m(0x13c));e('MOV '+g(0xe63054)+',EAX');restore();e('MOV ESI,dword ptr [ESP+0x10]');e('MOV dword ptr [ESP+8],EBX');e('JMP 0x6f9d8d')
# Gap hits return the HUD container without invoking any child button.
label('hit');e('PUSHFD');e('PUSH EAX');e('PUSH EBX');pic('hit_base');e('CMP '+data(4)+',0');e('JZ @hit_native');e('CMP ECX,'+data(16));e('JNZ @hit_native');e('CMP '+data(4)+',2');e('JZ @hit_margin');e('POP EBX');e('POP EAX');e('POPFD');e('MOV EAX,ECX');e('RET 0x10')
label('hit_margin');e('POP EBX');e('POP EAX');e('POPFD');e('MOV EAX,0');e('RET 0x10')
label('hit_native');e('POP EBX');e('POP EAX');e('POPFD');e('PUSH EBX');e('PUSH EBP');e('PUSH ESI');e('PUSH EDI');e('MOV EDI,ECX');e('JMP 0x7919f6')
# Only the CommandView time draw call uses existing white Modern12 AA.
# Preserve native white/red tint, center alignment and all GL current/texture state.
label('clock');save('clock_base');e('MOV EAX,'+g(0xe57b18));e('TEST EAX,EAX');e('JZ @clock_fallback');e('MOV ECX,dword ptr [EAX+0xb4]');e('TEST ECX,ECX');e('JZ @clock_fallback');e('CMP dword ptr [ECX],2');e('JNZ @clock_fallback');e('MOV '+m(0x80)+',ECX')
e('PUSH 0x40001');e('CALL '+g(0x9cc308));e('PUSH 0x2100');e('PUSH 0x2200');e('PUSH 0x2300');e('CALL '+g(0x9cc2e4))
e('MOV EAX,'+m(0x138));e('TEST EAX,EAX');e('JNZ @clock_color');e(f'LEA EAX,[EBX+0x{0xb20be0-0x400000:x}]')
label('clock_color');e('PUSH dword ptr [EAX+8]');e('PUSH dword ptr [EAX+4]');e('PUSH dword ptr [EAX]');e('CALL '+g(0x9cc268));e('CALL '+g(0x9cc2a8))
e('MOV ECX,'+m(0x80));e('PUSH '+m(0x130));e('CALL 0x609260');e('CMP EAX,64');e('JLE @clock_draw');e('CVTSI2SS XMM1,EAX');e('MOV EAX,64');e('CVTSI2SS XMM0,EAX');e('DIVSS XMM0,XMM1');e('MOVD '+m(0x84)+',XMM0')
# Uniformly shrink only unusually long strings about the original timer anchor.
for negative in (False,True):
 if negative:
  e('PUSH 0x3f800000');e('PUSH '+m(0x84));e('PUSH '+m(0x84));e('CALL '+g(0x9cc30c))
 e('PUSH 0')
 for a in (0x12c,0x128):
  e('CVTSI2SS XMM0,'+m(a));e('MOVD EAX,XMM0')
  if negative:e('XOR EAX,0x80000000')
  e('PUSH EAX')
 e('CALL '+g(0x9cc390))
label('clock_draw')
for a in (0x13c,0x138,0x134,0x130,0x12c,0x128):e('PUSH '+m(a))
e('MOV ECX,'+m(0x80));e('CALL 0x609870');e('CALL '+g(0x9cc298));e('CALL '+g(0x9cc31c));restore();e('RET 0x18')
label('clock_fallback');restore();e('JMP 0x609870')
# Native creation entry invalidates any preceding scene's registration.
label('hud_begin');save('begin_base');e('MOV '+data(0x20)+',0');e('MOV '+data(4)+',0');restore();e('PUSH EBP');e('MOV EBP,ESP');e('PUSH -1');e('JMP 0x79ecd5')
# Called at 79EE6B, after 79EE68 published the constructed HUD to its real owner.
# Tail-call the displaced allocator with its original one cdecl argument untouched.
label('hud_register');save('register_base');e('MOV '+data(0x20)+',0');e('MOV ESI,'+m(0x11c));e('MOV EAX,'+g(0xe53a94));e('MOV EDI,dword ptr [EAX+0x34]');e('MOV '+data(0x24)+',EDI');e('TEST EDI,EDI');e('JZ @reg_done');e('XOR ECX,ECX')
label('reg_path');e('CMP ESI,EDI');e('JZ @reg_publish');e('TEST ESI,ESI');e('JZ @reg_done');e('CMP ECX,32');e('JGE @reg_done');e(f'MOV dword ptr [EBX+ECX*4+0x{D+0x40-0x400000:x}],ESI');e('INC ECX');e('MOV ESI,dword ptr [ESI+4]');e('JMP @reg_path')
label('reg_publish');e('MOV '+data(0x20)+',ECX')
label('reg_done');restore();e('JMP 0x951734')
# Context is computed from live client dimensions, never configuration files.
label('context');e('MOV '+m(0x80)+',0');e('CMP '+data(0)+',0');e('JZ @ctx_ret')
# Ready is published only after native HUD construction. Never dereference Game+24.
e('MOV EDI,'+data(0x20));e('TEST EDI,EDI');e('JZ @ctx_ret');e('CMP EDI,32');e('JG @ctx_ret')
e('MOV EAX,'+g(0xe53a94));e('TEST EAX,EAX');e('JZ @ctx_ret');e('MOV ESI,dword ptr [EAX+0x34]');e('TEST ESI,ESI');e('JZ @ctx_ret');e('CMP ESI,'+data(0x24));e('JNZ @ctx_ret');e('DEC EDI')
# Validate cached path addresses by membership in live child vectors BEFORE dereference.
label('live_level');e('CMP byte ptr [ESI+0x1b],0');e('JNZ @ctx_ret');e('MOV ECX,dword ptr [ESI+0x3c]');e('MOV EDX,dword ptr [ESI+0x40]')
label('live_child');e('CMP ECX,EDX');e('JNC @ctx_ret');e('MOV EAX,dword ptr [ECX]');e(f'CMP EAX,dword ptr [EBX+EDI*4+0x{D+0x40-0x400000:x}]');e('JZ @live_found');e('ADD ECX,4');e('JMP @live_child')
label('live_found');e('MOV ESI,EAX');e('DEC EDI');e('JNS @live_level')
e('CMP byte ptr [ESI+0x1b],0');e('JNZ @ctx_ret');e('CMP word ptr [ESI+0x14],1024');e('JNZ @ctx_ret');e('CMP word ptr [ESI+0x16],164');e('JNZ @ctx_ret');e('CMP word ptr [ESI+0x12],0');e('JNZ @ctx_ret');e('CMP byte ptr [ESI+0x1a],0');e('JNZ @ctx_ret');e('MOV EAX,'+g(0xe53a94));e('TEST EAX,EAX');e('JZ @ctx_ret');e('MOV ECX,dword ptr [EAX]');e('CMP ECX,1024');e('JL @ctx_ret');e('CMP ECX,16384');e('JG @ctx_ret');e('MOV '+m(0x88)+',ECX');e('MOV EDX,dword ptr [EAX+4]');e('CMP EDX,768');e('JGE @ctx_height');e('MOV EDX,768')
label('ctx_height');e('LEA ECX,[ECX+ECX*2]');e('SHR ECX,2');e('CMP EDX,ECX');e('JLE @ctx_scale');e('MOV EDX,ECX')
label('ctx_scale');e('MOV '+m(0x84)+',EDX');e('MOVSX EAX,word ptr [ESI+0x10]');e('MOV '+m(0x8c)+',EAX');e('MOV '+m(0x80)+',ESI');e('MOV byte ptr [ESI+0x22],1');e('MOV EAX,1024');e('CALL @scaled');e('MOV '+m(0xd8)+',EAX');e('MOV ECX,'+m(0x88));e('SUB ECX,EAX');e('SHR ECX,1');e('MOV '+m(0xdc)+',ECX')
label('ctx_ret');e('RET')
# Match native hit eligibility, including +1E ancestry, +1F, +1A and modal order.
label('eligible');e('MOV ECX,ESI');e('CALL 0x7920d0');e('TEST AL,AL');e('JZ @eligible_ret');e('MOV ECX,ESI');e('CALL 0x792110')
label('eligible_ret');e('RET')
# ESI -> direct child of HUD; zero for unrelated views, HUD itself is valid.
label('find_panel');e('MOV ECX,64')
label('find_loop');e('TEST ESI,ESI');e('JZ @find_ret');e('CMP ESI,'+m(0x80));e('JZ @find_ret');e('MOV EAX,dword ptr [ESI+4]');e('CMP EAX,'+m(0x80));e('JZ @find_ret');e('MOV ESI,EAX');e('DEC ECX');e('JNZ @find_loop');e('XOR ESI,ESI')
label('find_ret');e('RET')
# Integer floor helpers preserve ESI/EDI; signed inverse supports captured drags.
label('scaled');e('IMUL EAX,'+m(0x84));e('CDQ');e('MOV ECX,768');e('IDIV ECX');e('TEST EDX,EDX');e('JNS @scaled_ret');e('DEC EAX')
label('scaled_ret');e('RET')
label('unscaled');e('INC EAX');e('IMUL EAX,EAX,768');e('SUB EAX,1');e('CDQ');e('IDIV '+m(0x84));e('TEST EDX,EDX');e('JNS @unscaled_ret');e('DEC EAX')
label('unscaled_ret');e('RET')
label('panel_rect');e('MOV '+m(0x90)+',ESI');e('MOVSX EAX,word ptr [ESI+0x10]');e('MOV '+m(0xa4)+',EAX');e('SUB EAX,'+m(0x8c));e('CALL @scaled');e('ADD EAX,'+m(0xdc));e('MOV '+m(0x94)+',EAX')
label('panel_no_gap');e('MOVSX EAX,word ptr [ESI+0x14]');e('CALL @scaled');e('MOV '+m(0x9c)+',EAX');e('MOVSX EAX,word ptr [ESI+0x12]');e('MOV '+m(0xa8)+',EAX');e('CALL @scaled');e('MOV '+m(0x98)+',EAX');e('MOVSX EAX,word ptr [ESI+0x16]');e('CALL @scaled');e('MOV '+m(0xa0)+',EAX');e('RET')
# glPixelZoom handles native glDrawPixels images. AA glyphs already use texture quads.
label('resolve');e('CMP '+data(0)+',0');e('JNZ @resolve_ret');e(f'LEA EAX,[EBX+0x{C+0x7800-0x400000:x}]');e('PUSH EAX');e('CALL '+g(0x9cc194));e('TEST EAX,EAX');e('JZ @resolve_ret');e(f'LEA ECX,[EBX+0x{C+0x7840-0x400000:x}]');e('PUSH ECX');e('PUSH EAX');e('CALL '+g(0x9cc1ec));e('MOV '+data(0)+',EAX')
label('resolve_ret');e('RET')
label('set_zoom');e('CMP '+data(0)+',0');e('JZ @zoom_ret');e('PUSH EAX');e('PUSH EAX');e('CALL '+data(0))
label('zoom_ret');e('RET')
assert len(L)*16<0x7800
asm=HERE/'hud_scale_candidate2_v1.55.asm';binary=HERE/'hud_scale_candidate2_v1.55.bin'
resolved=[]
for i,s in enumerate(L):
 s=re.sub(r'@([a-zA-Z0-9_]+)',lambda q:hex(labels[q[1]]),s);resolved.append((C+16*i,s))
if '--emit' in sys.argv:
 asm.write_text(''.join(f'{va:08x}\t{s}\n' for va,s in resolved),encoding='ascii');print('ASM',len(L),'C',hex(C),'D',hex(D),'ENTRIES',{k:hex(labels[k]) for k in ['viewport','viewport_restore','input','hit','clock','hud_begin','hud_register']});sys.exit()
code=binary.read_bytes();assert len(code)==len(L)*16
b=bytearray(baseline);raw=align(len(b),512);b.extend(bytes(raw-len(b)));payload=bytearray(b'\x90'*0x8000);payload[:len(code)]=code
s='opengl32.dll\0'.encode('utf-16le');payload[0x7800:0x7800+len(s)]=s;s=b'glPixelZoom\0';payload[0x7840:0x7840+len(s)]=s
b.extend(payload);b.extend(bytes(512))
for i,(name,rva,vs,rs,rp,flags) in enumerate([(b'.hudcode',C-0x400000,0x8000,0x8000,raw,0x60000020),(b'.huddata',D-0x400000,0x1000,512,raw+0x8000,0xc0000040)]):
 struct.pack_into('<8sIIIIIIHHI',b,st+(n+i)*40,name,vs,rva,rs,rp,0,0,0,0,flags)
struct.pack_into('<H',b,pe+6,n+2);struct.pack_into('<I',b,opt+56,D-0x400000+4096);struct.pack_into('<I',b,opt+4,u32(b,opt+4)+0x8000);struct.pack_into('<I',b,opt+8,u32(b,opt+8)+512);struct.pack_into('<I',b,opt+64,0)
hooks=[(0x791cf2,'ff1520c39c00','viewport',True),(0x791e86,'ff1520c39c00','viewport_restore',True),(0x6f9d85,'8b742410895c2408','input',False),(0x7919f0,'535556578bf9','hit',False),(0x56047c,'e8ef930a00','clock',True),(0x79ecd0,'558bec6aff','hud_begin',False),(0x79ee6b,'e8c4281b00','hud_register',True)]
allowed=set()
for va,h,target,call in hooks:
 old=bytes.fromhex(h);o=off(va);assert baseline[o:o+len(old)]==old,(hex(va),baseline[o:o+len(old)].hex());b[o:o+len(old)]=(b'\xe8' if call else b'\xe9')+struct.pack('<i',labels[target]-va-5)+b'\x90'*(len(old)-5);allowed.update(range(o,o+len(old)))
# Displaced absolute IAT operands must no longer receive PE base relocations.
rr,sz=struct.unpack_from('<II',baseline,opt+96+5*8);rp=off(0x400000+rr);end=rp+sz;removed=[]
while rp<end:
 page,size=struct.unpack_from('<II',baseline,rp)
 if not size:break
 for q in range(rp+8,rp+size,2):
  v=struct.unpack_from('<H',baseline,q)[0]
  if v>>12==3 and 0x400000+page+(v&4095) in [0x791cf4,0x791e88]:struct.pack_into('<H',b,q,0);allowed.update([q,q+1]);removed.append(q)
 rp+=size
assert len(removed)==2
allowed.update(range(pe+6,pe+8));allowed.update(range(opt+4,opt+12));allowed.update(range(opt+56,opt+60));allowed.update(range(opt+64,opt+68));allowed.update(range(st+n*40,st+(n+2)*40))
diffs=[i for i,(x,y) in enumerate(zip(baseline,b)) if x!=y];assert set(diffs)<=allowed
# Every byte of the two existing camera payload sections remains untouched.
for z,v,s,p in sections[-2:]:assert b[p:p+s]==baseline[p:p+s]
out=HERE/'candidates/SF2_ResponsiveHUD_NativeOrbit_v1.55.exe'
with out.open('xb') as f:f.write(b)
assert out.read_bytes()==b
print('CANDIDATE',out,'SHA256',hashlib.sha256(b).hexdigest(),'DIFF_BYTES',len(diffs),'CAMERA_PAYLOAD_UNCHANGED','RUNTIME_NOT_RUN')
