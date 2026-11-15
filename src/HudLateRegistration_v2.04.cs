using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.Reflection;
using System.Web.Script.Serialization;
using CombatMissionControlFix;

// Only initial RW registration data changes. Accepted HUD code stays identical.
public static class HudLateRegistration {
 public static string LastStatus="not_requested";
 static uint U(byte[] b,int p){return BitConverter.ToUInt32(b,p);}
 static byte[] Read(ModuleSnapshot s,uint va,int n){if(s.ReadRemote==null)throw new IOException("No live reader");return s.ReadRemote(va,n);}
 static uint AppSlot(ModuleSnapshot s){
  HudEngineResolver.Spec spec;
  using(var stream=Assembly.GetExecutingAssembly().GetManifestResourceStream("hud_spec"))using(var r=new StreamReader(stream))spec=new JavaScriptSerializer().Deserialize<HudEngineResolver.Spec>(r.ReadToEnd());
  var a=spec.anchors.Single(x=>x.key==0x4d8c8d);var ex=a.extract.Single(x=>x.kind=="module" && x.key==0xe53a94);
  byte[] bytes=Convert.FromBase64String(a.pattern),mask=Convert.FromBase64String(a.mask);int found=-1;
  for(int p=0;p<=s.Image.Length-bytes.Length;p++){
   if(s.Image[p]!=bytes[0])continue;bool ok=true;
   for(int j=0;j<bytes.Length;j++)if(!s.Readable[p+j] || (mask[j]!=0 && s.Image[p+j]!=bytes[j])){ok=false;break;}
   if(!ok)continue;if(found>=0)throw new IOException("Ambiguous app operand");found=p;
  }
  if(found<0)throw new IOException("App operand unavailable");return U(s.Image,found+ex.offset);
 }
 static List<uint[]> Find(ModuleSnapshot s,uint root){
  var found=new List<uint[]>();var work=new Stack<uint[]>();work.Push(new[]{root});var visited=new HashSet<uint>();
  while(work.Count>0){var path=work.Pop();uint va=path[path.Length-1];if(!visited.Add(va))throw new IOException("View tree cycle/shared node");if(visited.Count>4096)throw new IOException("View tree limit");
   byte[] b=Read(s,va,0x44);if(b[0x1b]!=0)continue;
   if(path.Length>1 && U(b,4)!=path[path.Length-2])throw new IOException("Parent relationship changed");
   if(BitConverter.ToInt16(b,0x14)==1024 && BitConverter.ToInt16(b,0x16)==164 && BitConverter.ToInt16(b,0x12)==0 && b[0x1a]==0 && path.Length>1)found.Add(path);
   uint start=U(b,0x3c),end=U(b,0x40);if(end<start || (end-start)%4!=0 || end-start>4096)throw new IOException("Child vector bounds");
   if(end==start)continue;if(path.Length>=33)throw new IOException("View ancestry limit");
   byte[] children=Read(s,start,(int)(end-start));for(int j=0;j<children.Length;j+=4){uint child=U(children,j);if(child==0)continue;work.Push(path.Concat(new[]{child}).ToArray());}
  }return found;
 }
 public static PatchPlan Resolve(ModuleSnapshot s){
  var plan=HudEngineResolver.Resolve(s);if(plan==null)return null;
  uint root=0;uint[] path=null;LastStatus="native_creation_pending";
  try {
   uint slot=AppSlot(s),app=U(Read(s,slot,4),0);if(app==0)throw new IOException("App absent");root=U(Read(s,app+0x34,4),0);if(root==0)throw new IOException("Root absent");
   var first=Find(s,root);if(first.Count!=1)throw new IOException("HUD absent/ambiguous");
   var second=Find(s,root);if(second.Count!=1 || !first[0].SequenceEqual(second[0]) || U(Read(s,slot,4),0)!=app || U(Read(s,app+0x34,4),0)!=root)throw new IOException("View path changed");
   path=first[0].Skip(1).Reverse().ToArray();LastStatus="existing_hud_seeded";
  }catch(IOException){path=null;}catch(System.ComponentModel.Win32Exception){path=null;}
  var build=plan.BuildPayload;var registered=path;
  plan.BuildPayload=address=>{byte[] data=build(address);if(registered!=null){int rw=plan.WritablePayloadOffset;Buffer.BlockCopy(BitConverter.GetBytes((uint)registered.Length),0,data,rw+0x20,4);Buffer.BlockCopy(BitConverter.GetBytes(root),0,data,rw+0x24,4);for(int i=0;i<registered.Length;i++)Buffer.BlockCopy(BitConverter.GetBytes(registered[i]),0,data,rw+0x40+i*4,4);}return data;};
  return plan;
 }
}
