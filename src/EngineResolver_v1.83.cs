// Camera Control Fix v1.83. Engine patterns and operands, never a shared title address.
using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Web.Script.Serialization;
using CombatMissionControlFix;

public sealed class AlreadyAppliedException:Exception {
 public AlreadyAppliedException():base("Camera Control Fix controls are already active."){}
}

public static class EngineResolver {
 public sealed class Extract {public string kind;public uint key;public int offset,size,end;}
 public sealed class Anchor {public uint key;public string pattern,mask,literal;public int literal_offset;public Extract[] extract;}
 public sealed class Alias {public uint key,source;public int delta;}
 public sealed class Fixup {public string kind;public int offset,end;public uint key;}
 public sealed class Hook {public uint key;public int size,opcode,payload_target;}
 public sealed class Keyboard {public uint key,module_value;public int delta,size,offset,byte_value;}
 public sealed class Existing {public uint rva;public string bytes;}
 public sealed class Spec {public string version;public uint template_base;public int payload_size,writable_offset;public Anchor[] anchors;public Alias[] aliases;public Fixup[] fixups;public Hook[] hooks;public Keyboard[] keyboard;public uint[] required_keys,required_fields;public Existing[] existing;}
 sealed class Pattern {public Anchor Entry;public byte[] Bytes,Mask,Literal;public int[] Skip;}
 struct Span {public int Start,End;public bool Executable;}
 static readonly Spec spec;
 static readonly byte[] template;
 static readonly Pattern[] patterns;
 static EngineResolver() {
  spec=new JavaScriptSerializer{MaxJsonLength=1048576}.Deserialize<Spec>(System.Text.Encoding.UTF8.GetString(Resource("engine_spec")));
  template=Resource("engine_payload");
  if(spec.version!="1.83" || template.Length!=spec.payload_size || spec.writable_offset!=0x11000)throw new InvalidDataException("Engine payload metadata differs.");
  patterns=spec.anchors.Select(a=>{var p=new Pattern{Entry=a,Bytes=Convert.FromBase64String(a.pattern),Mask=Convert.FromBase64String(a.mask),Literal=Convert.FromBase64String(a.literal),Skip=new int[256]};
   if(p.Bytes.Length!=p.Mask.Length || p.Literal.Length<4 || a.literal_offset<0 || a.literal_offset+p.Literal.Length>p.Bytes.Length)throw new InvalidDataException("Engine pattern is invalid.");
   for(int i=0;i<256;i++)p.Skip[i]=p.Literal.Length;
   for(int i=0;i<p.Literal.Length-1;i++)p.Skip[p.Literal[i]]=p.Literal.Length-1-i;
   return p;}).ToArray();
 }
 static byte[] Resource(string name){using(var s=Assembly.GetExecutingAssembly().GetManifestResourceStream(name)){if(s==null)throw new InvalidDataException("Missing "+name);using(var m=new MemoryStream()){s.CopyTo(m);return m.ToArray();}}}
 static uint U32(byte[] b,int p){if(p<0 || p>b.Length-4)throw new InvalidDataException("Truncated image.");return BitConverter.ToUInt32(b,p);}
 static ushort U16(byte[] b,int p){if(p<0 || p>b.Length-2)throw new InvalidDataException("Truncated image.");return BitConverter.ToUInt16(b,p);}
 static void Put(byte[] b,int p,uint value){if(p<0 || p>b.Length-4)throw new InvalidDataException("Invalid fixup.");Buffer.BlockCopy(BitConverter.GetBytes(value),0,b,p,4);}
 static bool Readable(ModuleSnapshot s,int p,int count){if(p<0 || count<0 || p>s.Image.Length-count || s.Readable==null || s.Readable.Length!=s.Image.Length)return false;for(int i=p;i<p+count;i++)if(!s.Readable[i])return false;return true;}
 static List<Span> Sections(ModuleSnapshot s){
  if(!Readable(s,0,64) || U16(s.Image,0)!=0x5a4d)return null;
  int pe=checked((int)U32(s.Image,60));if(!Readable(s,pe,248) || U32(s.Image,pe)!=0x4550 || U16(s.Image,pe+4)!=0x14c || U16(s.Image,pe+24)!=0x10b)return null;
  int count=U16(s.Image,pe+6),table=pe+24+U16(s.Image,pe+20);if(count<1 || count>96 || !Readable(s,table,count*40))return null;
  var spans=new List<Span>();for(int i=0;i<count;i++){int p=table+i*40;long rva=U32(s.Image,p+12),size=Math.Max(U32(s.Image,p+8),U32(s.Image,p+16));if(rva<0 || size<0 || rva+size>s.Image.Length)throw new InvalidDataException("Section is outside the module.");spans.Add(new Span{Start=(int)rva,End=(int)(rva+size),Executable=(U32(s.Image,p+36)&0x20000000)!=0});}return spans;
 }
 static bool Equal(byte[] a,int pos,byte[] b,int offset,int n){if(pos<0 || pos>a.Length-n)return false;for(int i=0;i<n;i++)if(a[pos+i]!=b[offset+i])return false;return true;}
 static void DetectExisting(ModuleSnapshot s){
  int rva=checked((int)(spec.template_base-0x400000));
  if(!Readable(s,rva,0x11000) || !Equal(s.Image,rva,template,0,0x9000) || !Equal(s.Image,rva+0xa000,template,0xa000,0x7000))return;
  foreach(var e in spec.existing){byte[] expected=Convert.FromBase64String(e.bytes);if(!Readable(s,(int)e.rva,expected.Length) || !Equal(s.Image,(int)e.rva,expected,0,expected.Length))return;}
  throw new AlreadyAppliedException();
 }
 static int Find(ModuleSnapshot s,List<Span> spans,Pattern p){
  int found=-1,n=p.Literal.Length;
  foreach(var span in spans){if(!span.Executable)continue;int at=span.Start+p.Entry.literal_offset,last=span.End-p.Bytes.Length+p.Entry.literal_offset;
   while(at<=last){int j=n-1;while(j>=0 && s.Image[at+j]==p.Literal[j])j--;if(j<0){int start=at-p.Entry.literal_offset;bool ok=Readable(s,start,p.Bytes.Length);if(ok)for(int k=0;k<p.Bytes.Length;k++)if(p.Mask[k]!=0 && s.Image[start+k]!=p.Bytes[k]){ok=false;break;}if(ok){if(found>=0)throw new InvalidDataException("Engine function match is ambiguous; game unchanged.");found=start;}at++;}else at+=p.Skip[s.Image[at+n-1]];}
  }return found;
 }
 static void Add(Dictionary<uint,uint> map,uint key,uint value){uint old;if(map.TryGetValue(key,out old) && old!=value)throw new InvalidDataException("Engine operands disagree; game unchanged.");map[key]=value;}
 static uint ResolveValue(Dictionary<uint,uint> map,uint key){uint value;if(!map.TryGetValue(key,out value))throw new InvalidDataException("Required engine operand was not resolved.");return value;}
 static byte[] Slice(ModuleSnapshot s,uint rva,int size){if(!Readable(s,checked((int)rva),size))throw new InvalidDataException("Patch location is unreadable.");var b=new byte[size];Buffer.BlockCopy(s.Image,(int)rva,b,0,size);return b;}
 public static PatchPlan Resolve(ModuleSnapshot snapshot){
  if(snapshot==null || snapshot.Image==null || snapshot.BaseAddress>UInt32.MaxValue || snapshot.BaseAddress+(ulong)snapshot.Image.Length>0x100000000UL)return null;
  var spans=Sections(snapshot);if(spans==null)return null;DetectExisting(snapshot);
  var values=new Dictionary<uint,uint>();var fields=new Dictionary<uint,uint>();
  foreach(var p in patterns){int at=Find(snapshot,spans,p);if(at<0)return null;Add(values,p.Entry.key,(uint)at);
   foreach(var e in p.Entry.extract){int offset=at+e.offset;if(!Readable(snapshot,offset,e.size))return null;long val;
    if(e.kind=="branch")val=at+e.end+(e.size==1?(sbyte)snapshot.Image[offset]:e.size==4?(long)BitConverter.ToInt32(snapshot.Image,offset):throwInvalid());
    else if(e.kind=="module")val=(long)U32(snapshot.Image,offset)-(long)snapshot.BaseAddress;
    else if(e.kind=="field"){uint f=U32(snapshot.Image,offset);if(f<4 || f>0x100000)throw new InvalidDataException("Object layout is outside supported bounds.");Add(fields,e.key,f);continue;}
    else throw new InvalidDataException("Unknown operand kind.");
    if(val<0 || val>=snapshot.Image.Length)throw new InvalidDataException("Engine reference leaves the module.");Add(values,e.key,(uint)val);
   }
  }
  foreach(var a in spec.aliases)Add(values,a.key,checked(ResolveValue(values,a.source)+(uint)a.delta));
  foreach(uint k in spec.required_keys)ResolveValue(values,k);
  foreach(uint k in spec.required_fields)ResolveValue(fields,k);
  // Relationships derive from native layout reads in both representative games.
  if(fields[0xb2c4]!=fields[0xb2c0]+4 || fields[0xb7e8]!=fields[0xb7e0]+8 || fields[0xb7ec]!=fields[0xb7e0]+12 || fields[0xb7f0]!=fields[0xb7e0]+16)throw new InvalidDataException("Camera layout relationships do not match.");
  if(U32(snapshot.Image,(int)values[0xbab5b4])!=0x3f19999a || U32(snapshot.Image,(int)values[0xbad154])!=0xbf19999a)throw new InvalidDataException("Movement constants differ.");
  ulong moduleBase=snapshot.BaseAddress;
  var plan=new PatchPlan{PayloadSize=spec.payload_size,WritablePayloadOffset=spec.writable_offset};
  plan.BuildPayload=allocation=>{
   if(allocation>UInt32.MaxValue || allocation+(ulong)spec.payload_size>0x100000000UL)throw new InvalidDataException("Payload must fit the x86 address space.");
   byte[] result=(byte[])template.Clone();foreach(var f in spec.fixups){uint value;
    if(f.kind=="module")value=ResolveValue(values,f.key);
    else if(f.kind=="private" || f.kind=="base")value=unchecked((uint)(allocation-moduleBase+f.key));
    else if(f.kind=="relative")value=unchecked((uint)(moduleBase+ResolveValue(values,f.key)-allocation-(ulong)f.end));
    else if(f.kind=="field")value=ResolveValue(fields,f.key);
    else throw new InvalidDataException("Unknown payload fixup.");Put(result,f.offset,value);
   }return result;
  };
  foreach(var h in spec.hooks){uint rva=ResolveValue(values,h.key);var expected=Slice(snapshot,rva,h.size);int opcode=h.opcode,target=h.payload_target,size=h.size;
   plan.Patches.Add(new GuardedPatch{Rva=rva,Expected=expected,BuildReplacement=allocation=>{byte[] data=Enumerable.Repeat((byte)0x90,size).ToArray();data[0]=(byte)opcode;Put(data,1,unchecked((uint)(allocation+(ulong)target-moduleBase-rva-5)));return data;}});
  }
  foreach(var k in spec.keyboard){uint rva=checked(ResolveValue(values,k.key)+(uint)k.delta);byte[] expected=Slice(snapshot,rva,k.size),replacement=(byte[])expected.Clone();if(k.module_value!=0)Put(replacement,k.offset,checked((uint)moduleBase+ResolveValue(values,k.module_value)));else{if(expected[k.offset]!=1)throw new InvalidDataException("Keyboard acceleration context differs.");replacement[k.offset]=(byte)k.byte_value;}
   plan.Patches.Add(new GuardedPatch{Rva=rva,Expected=expected,BuildReplacement=allocation=>(byte[])replacement.Clone()});
  }
  var ordered=plan.Patches.OrderBy(x=>x.Rva).ToArray();for(int i=0;i<ordered.Length;i++){if(!spans.Any(s=>s.Executable && ordered[i].Rva>=s.Start && (ulong)ordered[i].Rva+(ulong)ordered[i].Expected.Length<=(ulong)s.End))throw new InvalidDataException("Hook is outside executable code.");if(i>0 && (ulong)ordered[i-1].Rva+(ulong)ordered[i-1].Expected.Length>ordered[i].Rva)throw new InvalidDataException("Hooks overlap.");}
  return plan;
 }
 static long throwInvalid(){throw new InvalidDataException("Unsupported branch displacement.");}
}
