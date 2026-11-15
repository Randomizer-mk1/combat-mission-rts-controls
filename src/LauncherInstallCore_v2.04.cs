using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Xml;
using System.Text.RegularExpressions;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Web.Script.Serialization;

namespace CameraControlFix.LauncherInstall {
 public sealed class GameProfile {public string Exe,Folder;}
 public sealed class HostPayload {public string Version="2.04",Name="Camera-Control-Fix-Host-v2.04.exe",Sha256;public byte[] Bytes;}
 public sealed class Receipt {public string Owner="CameraControlFixLauncher",Version,GameExe,HostName,HostHash,LaunchHash,OriginalHash,InstalledHash;}
 public sealed class Result {public string Status,GameFolder,Message;}
 public sealed class ConfigInfo {public string Exe,Arguments,WorkingSubdirectory;}
 public static class LauncherConfig {
  static readonly UTF8Encoding Utf8=new UTF8Encoding(false,true);
  public static ConfigInfo Inspect(byte[] data){
   if(data.Length>1048576)throw new IOException("Launcher configuration is too large");
   var doc=new XmlDocument{XmlResolver=null};using(var stream=new MemoryStream(data))using(var reader=XmlReader.Create(stream,new XmlReaderSettings{DtdProcessing=DtdProcessing.Prohibit,XmlResolver=null}))doc.Load(reader);
   Func<string,string> value=key=>{var nodes=doc.SelectNodes("/configuration/appSettings/add[@key='"+key+"']");if(nodes.Count!=1)throw new IOException("Launcher setting is missing or duplicated: "+key);return nodes[0].Attributes["value"].Value;};
   return new ConfigInfo{Exe=value("EXE"),Arguments=value("Arguments"),WorkingSubdirectory=value("workingSubDirectory")};
  }
  public static byte[] ReplaceExe(byte[] input,string expected,string replacement){
   if(Inspect(input).Exe!=expected)throw new IOException("Launcher EXE setting changed; preserved");
   string text=Utf8.GetString(input);
   var matches=Regex.Matches(text,"<add\\s+key\\s*=\\s*\"EXE\"\\s+value\\s*=\\s*\"(?<value>[^\"]*)\"\\s*/>",RegexOptions.CultureInvariant,TimeSpan.FromSeconds(1));
   if(matches.Count!=1 || matches[0].Groups["value"].Value!=expected)throw new IOException("Launcher EXE syntax is not the verified form; preserved");
   var group=matches[0].Groups["value"];byte[] result=Utf8.GetBytes(text.Substring(0,group.Index)+replacement+text.Substring(group.Index+group.Length));
   var old=Inspect(input);var updated=Inspect(result);if(updated.Exe!=replacement || old.Arguments!=updated.Arguments || old.WorkingSubdirectory!=updated.WorkingSubdirectory)throw new IOException("Configuration preservation check failed");return result;
  }
 }
 public sealed class Installer {
  public static readonly GameProfile[] Games={
   new GameProfile{Exe="CM Shock Force 2.exe",Folder="Combat Mission Shock Force 2"},new GameProfile{Exe="CM Normandy.exe",Folder="Combat Mission - Battle for Normandy"},
   new GameProfile{Exe="CM Cold War.exe",Folder="Combat Mission Cold War"},new GameProfile{Exe="CM Black Sea.exe",Folder="Combat Mission Black Sea"},
   new GameProfile{Exe="CM Red Thunder.exe",Folder="Combat Mission Red Thunder"},new GameProfile{Exe="CM Fortress Italy.exe",Folder="Combat Mission Fortress Italy"},new GameProfile{Exe="CM Final Blitzkrieg.exe",Folder="Combat Mission Final Blitzkrieg"}};
  readonly HostPayload host;readonly Action<string,string> checkNotRunning;readonly JavaScriptSerializer json=new JavaScriptSerializer();
  public Installer(HostPayload payload,Action<string,string> runningGuard){host=payload;checkNotRunning=runningGuard;if(host.Version!="2.04" || host.Name!="Camera-Control-Fix-Host-v2.04.exe" || host.Bytes==null || Hash(host.Bytes)!=host.Sha256)throw new IOException("Embedded host validation failed");}
  public static string Hash(byte[] bytes){using(var sha=SHA256.Create())return BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-","").ToLowerInvariant();}
  static void Require(bool ok,string message){if(!ok)throw new IOException(message);}
  static void NoLinks(string path){for(string p=Path.GetFullPath(path);!String.IsNullOrEmpty(p);p=Path.GetDirectoryName(p))if(File.Exists(p)||Directory.Exists(p))Require((File.GetAttributes(p)&FileAttributes.ReparsePoint)==0,"Linked installation path is not supported; files preserved");}
  static string Root(string path){path=Path.GetFullPath(path);if(File.Exists(path))path=Path.GetDirectoryName(path);Require(Directory.Exists(path),"Select an installed game folder");NoLinks(path);return path;}
  static string Mod(string root){return Path.Combine(root,"CameraControlFix");}
  static string Config(string root){return Path.Combine(root,"Launcher.exe.config");}
  static string Original(string root){return Path.Combine(Mod(root),"Launcher.exe.config.original");}
  static string Record(string root){return Path.Combine(Mod(root),"install.json");}
  static string Hook(string name){return "\\CameraControlFix\\"+name;}
  static void NewFile(string path,byte[] bytes){using(var f=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.None)){f.Write(bytes,0,bytes.Length);f.Flush(true);}Require(Hash(File.ReadAllBytes(path))==Hash(bytes),"File readback failed");}
  Receipt ReadReceipt(string root){Require(File.Exists(Record(root)) && new FileInfo(Record(root)).Length<65536,"Existing CameraControlFix folder has no valid ownership record; preserved");var r=json.Deserialize<Receipt>(File.ReadAllText(Record(root)));Require(r!=null && r.Owner=="CameraControlFixLauncher" && Games.Any(g=>g.Exe==r.GameExe) && Regex.IsMatch(r.Version??"",@"^\d+\.(?:0|\d{2})$") && r.HostName=="Camera-Control-Fix-Host-v"+r.Version+".exe","Installation ownership differs; preserved");return r;}
  bool VerifyOwned(string root,Receipt r,bool allowOriginal=false){
   NoLinks(Mod(root));var allowed=new HashSet<string>(new[]{r.HostName,"launch.json","Launcher.exe.config.original","install.json"},StringComparer.OrdinalIgnoreCase);
   Require(Directory.GetFileSystemEntries(Mod(root)).All(p=>File.Exists(p)&&allowed.Contains(Path.GetFileName(p))),"Installation folder contains foreign files; preserved");
   foreach(var p in Directory.GetFileSystemEntries(Mod(root)))NoLinks(p);
   Require(Hash(File.ReadAllBytes(Path.Combine(Mod(root),r.HostName)))==r.HostHash && Hash(File.ReadAllBytes(Path.Combine(Mod(root),"launch.json")))==r.LaunchHash && Hash(File.ReadAllBytes(Original(root)))==r.OriginalHash,"An owned installation file changed externally; preserved");
   byte[] config=File.ReadAllBytes(Config(root));string hash=Hash(config);
   bool installed=hash==r.InstalledHash && LauncherConfig.Inspect(config).Exe==Hook(r.HostName);
   bool original=hash==r.OriginalHash && LauncherConfig.Inspect(config).Exe=="\\"+r.GameExe;
   Require(installed || allowOriginal && original,"Launcher configuration changed after installation; preserved");return installed;
  }
  static string Archive(string root){string dir=Path.Combine(root,"CameraControlFixBackups");NoLinks(dir);Directory.CreateDirectory(dir);return Path.Combine(dir,DateTime.UtcNow.ToString("yyyyMMddTHHmmssfff")+"_"+Guid.NewGuid().ToString("N"));}
  public Result Install(string input){
   string root=Root(input),config=Config(root);Require(File.Exists(config),"Launcher.exe.config is missing");NoLinks(config);
   if(Directory.Exists(Mod(root))){var prior=ReadReceipt(root);bool installed=VerifyOwned(root,prior,true);checkNotRunning(root,prior.GameExe);
    if(!installed){Directory.Move(Mod(root),Archive(root));return Install(root);}
    Require(prior.Version==host.Version && prior.HostHash==host.Sha256,"Another owned release is installed. Restore it before installing this release.");return new Result{Status="already_installed",GameFolder=root,Message="Launcher integration is already installed."};}
   byte[] original=File.ReadAllBytes(config);var info=LauncherConfig.Inspect(original);var game=Games.SingleOrDefault(g=>info.Exe=="\\"+g.Exe);
   Require(game!=null && File.Exists(Path.Combine(root,game.Exe)),"Launcher EXE does not match a recognized installed game; unchanged");
   string relative=info.WorkingSubdirectory;
   if(relative.StartsWith("\\") || relative.StartsWith("/"))relative=relative.Substring(1);
   Require(!Path.IsPathRooted(relative),"Working directory is not a safe relative path; unchanged");
   string working=Path.GetFullPath(Path.Combine(root,relative));Require(String.Equals(working,root,StringComparison.OrdinalIgnoreCase) || working.StartsWith(root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase),"Working directory leaves the game folder; unchanged");
   Require(Directory.Exists(working),"Working directory does not exist; unchanged");NoLinks(working);
   relative=String.Equals(working,root,StringComparison.OrdinalIgnoreCase)?"":working.Substring(root.Length+1);
   checkNotRunning(root,game.Exe);
   byte[] patched=LauncherConfig.ReplaceExe(original,info.Exe,Hook(host.Name));
   byte[] launch=Encoding.UTF8.GetBytes(json.Serialize(new {version=host.Version,game_exe=game.Exe,working_subdirectory=relative}));
   var record=new Receipt{Version=host.Version,GameExe=game.Exe,HostName=host.Name,HostHash=host.Sha256,LaunchHash=Hash(launch),OriginalHash=Hash(original),InstalledHash=Hash(patched)};
   string staging=Path.Combine(root,".CameraControlFix-stage-"+Guid.NewGuid().ToString("N")),temp=config+"."+Guid.NewGuid().ToString("N")+".tmp";bool folderPlaced=false,configChanged=false;
   Directory.CreateDirectory(staging);
   try{
    NewFile(Path.Combine(staging,host.Name),host.Bytes);NewFile(Path.Combine(staging,"launch.json"),launch);NewFile(Path.Combine(staging,"Launcher.exe.config.original"),original);NewFile(Path.Combine(staging,"install.json"),Encoding.UTF8.GetBytes(json.Serialize(record)));
    Require(Hash(File.ReadAllBytes(config))==record.OriginalHash,"Launcher configuration changed during installation; preserved");checkNotRunning(root,game.Exe);
    Directory.Move(staging,Mod(root));folderPlaced=true;NewFile(temp,patched);Require(Hash(File.ReadAllBytes(config))==record.OriginalHash,"Launcher configuration changed before replacement; preserved");File.Replace(temp,config,null);configChanged=true;
    VerifyOwned(root,record);return new Result{Status="installed",GameFolder=root,Message="Installed. Start through Steam and press Play normally. Choose RTS camera mode. Game EXE and launcher EXE were not changed."};
   }catch(Exception failure){
    var errors=new List<Exception>{failure};
    if(configChanged)try{Require(Hash(File.ReadAllBytes(config))==record.InstalledHash,"Config changed externally during recovery; preserved");string recovery=config+"."+Guid.NewGuid().ToString("N")+".restore";NewFile(recovery,original);File.Replace(recovery,config,null);Require(Hash(File.ReadAllBytes(config))==record.OriginalHash,"Config rollback readback failed");}catch(Exception ex){errors.Add(ex);}
    // Retain the host if any current configuration still points to it.
    if(folderPlaced)try{if(Hash(File.ReadAllBytes(config))==record.OriginalHash)Directory.Move(Mod(root),Archive(root));}catch(Exception ex){errors.Add(ex);}
    if(Directory.Exists(staging))try{Directory.Move(staging,Archive(root));}catch(Exception ex){errors.Add(ex);}
    throw new AggregateException("Launcher installation failed; recovery details follow.",errors);
   }finally{if(File.Exists(temp)){string dir=Archive(root);Directory.CreateDirectory(dir);File.Move(temp,Path.Combine(dir,Path.GetFileName(temp)));}}
  }
  public Result Restore(string input){
   string root=Root(input);if(!Directory.Exists(Mod(root)))return new Result{Status="not_installed",GameFolder=root,Message="No launcher integration is installed."};
   var r=ReadReceipt(root);bool installed=VerifyOwned(root,r,true);checkNotRunning(root,r.GameExe);
   if(!installed){Directory.Move(Mod(root),Archive(root));return new Result{Status="restored",GameFolder=root,Message="Launcher configuration was already original. Owned integration files were archived."};}
   byte[] original=File.ReadAllBytes(Original(root));string config=Config(root),temp=config+"."+Guid.NewGuid().ToString("N")+".restore";
   NewFile(temp,original);Require(Hash(File.ReadAllBytes(config))==r.InstalledHash,"Launcher configuration changed before restore; preserved");File.Replace(temp,config,null);Require(Hash(File.ReadAllBytes(config))==r.OriginalHash,"Original configuration readback failed");
   Directory.Move(Mod(root),Archive(root));return new Result{Status="restored",GameFolder=root,Message="Original launcher configuration restored. Integration files were archived. Restart running games to remove runtime changes."};
  }
 }
}
