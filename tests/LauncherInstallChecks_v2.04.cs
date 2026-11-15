using System;
using System.IO;
using System.Text;
using System.Linq;
using System.Web.Script.Serialization;
using CameraControlFix.LauncherInstall;
static class LauncherInstallChecks {
 static void Assert(bool ok,string message){if(!ok)throw new Exception(message);}
 static void Refuse(Action action){bool refused=false;try{action();}catch(IOException){refused=true;}catch(AggregateException){refused=true;}Assert(refused,"Expected refusal");}
 static int Main(string[] args){
  string root=Path.GetFullPath(args[0]);if(Directory.Exists(root))throw new IOException("Use a new isolated test directory");Directory.CreateDirectory(root);
  byte[] bytes=Encoding.ASCII.GetBytes("fixture host bytes only");var payload=new HostPayload{Bytes=bytes,Sha256=Installer.Hash(bytes)};
  for(int i=1;i<args.Length;i++){
   string folder=Path.Combine(root,"game"+i);Directory.CreateDirectory(folder);byte[] original=File.ReadAllBytes(args[i]);var info=LauncherConfig.Inspect(original);string exe=info.Exe.TrimStart('\\');File.WriteAllBytes(Path.Combine(folder,exe),new byte[]{77,90});string config=Path.Combine(folder,"Launcher.exe.config");File.WriteAllBytes(config,original);
   var installer=new Installer(payload,(p,g)=>{});Assert(installer.Install(folder).Status=="installed","Install failed");byte[] patched=File.ReadAllBytes(config);Assert(LauncherConfig.Inspect(patched).Arguments==info.Arguments,"Arguments changed");Assert(installer.Install(folder).Status=="already_installed","Idempotence failed");
   installer.Restore(folder);Assert(File.ReadAllBytes(config).SequenceEqual(original),"Restore did not preserve exact bytes");
   installer.Install(folder);File.WriteAllBytes(config,original);Assert(installer.Install(folder).Status=="installed","Steam repair reinstall failed");
   File.WriteAllBytes(config,original);installer.Restore(folder);Assert(!Directory.Exists(Path.Combine(folder,"CameraControlFix")),"Original-config restore did not archive owned files");
   installer.Install(folder);patched=File.ReadAllBytes(config);File.AppendAllText(config,"\n<!-- external edit -->");byte[] external=File.ReadAllBytes(config);Refuse(()=>installer.Restore(folder));Assert(File.ReadAllBytes(config).SequenceEqual(external),"Foreign config overwritten");File.WriteAllBytes(config,patched);
   string foreign=Path.Combine(folder,"CameraControlFix","foreign.txt");File.WriteAllText(foreign,"keep");Refuse(()=>installer.Install(folder));Refuse(()=>installer.Restore(folder));File.Move(foreign,Path.Combine(folder,"foreign-preserved.txt"));installer.Restore(folder);
   var locked=new Installer(payload,(p,g)=>{throw new IOException("game running");});Refuse(()=>locked.Install(folder));Assert(File.ReadAllBytes(config).SequenceEqual(original) && !Directory.Exists(Path.Combine(folder,"CameraControlFix")),"Running-game refusal modified files");
   Directory.CreateDirectory(Path.Combine(folder,"bin"));string text=Encoding.UTF8.GetString(original).Replace("key=\"workingSubDirectory\" value=\"\"","key=\"workingSubDirectory\" value=\"\\bin\"");File.WriteAllText(config,text,new UTF8Encoding(false));installer.Install(folder);
   var launch=new JavaScriptSerializer().Deserialize<System.Collections.Generic.Dictionary<string,object>>(File.ReadAllText(Path.Combine(folder,"CameraControlFix","launch.json")));Assert((string)launch["working_subdirectory"]=="bin","Leading-slash normalization failed");Assert(LauncherConfig.Inspect(File.ReadAllBytes(config)).WorkingSubdirectory=="\\bin","Original working config changed");installer.Restore(folder);
   foreach(string relative in new[]{".","bin\\.."}){text=Encoding.UTF8.GetString(original).Replace("key=\"workingSubDirectory\" value=\"\"","key=\"workingSubDirectory\" value=\""+relative+"\"");File.WriteAllText(config,text,new UTF8Encoding(false));installer.Install(folder);launch=new JavaScriptSerializer().Deserialize<System.Collections.Generic.Dictionary<string,object>>(File.ReadAllText(Path.Combine(folder,"CameraControlFix","launch.json")));Assert((string)launch["working_subdirectory"]=="","Root-equivalent working directory was not empty");installer.Restore(folder);}
   text=Encoding.UTF8.GetString(original).Replace("key=\"workingSubDirectory\" value=\"\"","key=\"workingSubDirectory\" value=\"\\missing\"");File.WriteAllText(config,text,new UTF8Encoding(false));Refuse(()=>installer.Install(folder));Assert(!Directory.Exists(Path.Combine(folder,"CameraControlFix")),"Missing working directory installed");
   Console.WriteLine("PASS "+exe+": exact roundtrip, idempotence, Steam repair reinstall/restore, foreign files/config, running refusal, working subdirectory preservation");
  }
  Console.WriteLine("No live game files, registry, Steam settings, or processes changed.");return 0;
 }
}
