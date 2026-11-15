using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Web.Script.Serialization;
using System.Collections.Generic;
using System.Security.Cryptography;
static class EmbeddedResourceChecks {
 static byte[] Resource(Assembly assembly,string name){using(var stream=assembly.GetManifestResourceStream(name))using(var memory=new MemoryStream()){if(stream==null)throw new Exception("Missing resource: "+name);stream.CopyTo(memory);return memory.ToArray();}}
 static void Equal(byte[] a,byte[] b,string name){if(!a.SequenceEqual(b))throw new Exception("Resource mismatch: "+name);}
 static int Main(string[] args){
  var host=Assembly.ReflectionOnlyLoadFrom(args[0]);var installer=Assembly.ReflectionOnlyLoadFrom(args[1]);
  PortableExecutableKinds kind;ImageFileMachine machine;host.ManifestModule.GetPEKind(out kind,out machine);
  if((kind&PortableExecutableKinds.Required32Bit)==0)throw new Exception("Host must require x86");
  installer.ManifestModule.GetPEKind(out kind,out machine);
  if((kind&PortableExecutableKinds.Required32Bit)!=0 || (kind&PortableExecutableKinds.ILOnly)==0)throw new Exception("Installer must be AnyCPU");
  foreach(var name in new[]{"engine_spec","engine_payload","hud_spec","hud_payload"})Equal(Resource(host,name),File.ReadAllBytes(Path.Combine(args[2],name+(name.EndsWith("spec")?".json":".bin"))),name);
  byte[] embedded=Resource(installer,"host");Equal(embedded,File.ReadAllBytes(args[0]),"host");
  var meta=new JavaScriptSerializer().Deserialize<Dictionary<string,string>>(System.Text.Encoding.UTF8.GetString(Resource(installer,"host_meta")));
  using(var sha=SHA256.Create()){string hash=BitConverter.ToString(sha.ComputeHash(embedded)).Replace("-","").ToLowerInvariant();if(meta["Sha256"]!=hash || meta["Version"]!="2.04" || meta["Name"]!=Path.GetFileName(args[0]))throw new Exception("Host metadata mismatch");}
  Console.WriteLine("PASS: x86 host, AnyCPU installer, four frozen resources, embedded host and metadata");return 0;
 }
}
