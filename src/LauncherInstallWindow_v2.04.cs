using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Threading;
using System.Threading.Tasks;
using System.Security.Principal;
using System.Reflection;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using Microsoft.Win32;
using CameraControlFix.LauncherInstall;
[assembly:AssemblyTitle("Camera Control Fix Installer")]
[assembly:AssemblyProduct("Camera Control Fix Installer v2.04")]
[assembly:AssemblyVersion("2.4.0.0")]
static class LauncherInstallation {
 public static HostPayload Payload(){using(var s=Assembly.GetExecutingAssembly().GetManifestResourceStream("host_meta"))using(var reader=new StreamReader(s)){var payload=new JavaScriptSerializer().Deserialize<HostPayload>(reader.ReadToEnd());using(var h=Assembly.GetExecutingAssembly().GetManifestResourceStream("host"))using(var m=new MemoryStream()){h.CopyTo(m);payload.Bytes=m.ToArray();}return payload;}}
 public static void Guard(string root,string exe){foreach(string name in new[]{"Launcher",Path.GetFileNameWithoutExtension(exe)})foreach(var process in Process.GetProcessesByName(name))using(process){try{if(!process.HasExited && String.Equals(Path.GetDirectoryName(process.MainModule.FileName),root,StringComparison.OrdinalIgnoreCase))throw new IOException("Close the game and its Slitherine launcher before changing this installation.");}catch(System.ComponentModel.Win32Exception){throw new IOException("Cannot verify whether a game or launcher is running. Close it and retry.");}catch(InvalidOperationException){if(!process.HasExited)throw;}}}
 static void Optional(Action a){try{a();}catch(IOException){}catch(UnauthorizedAccessException){}catch(System.Security.SecurityException){}catch(ArgumentException){}catch(NotSupportedException){}catch(RegexMatchTimeoutException){}}
 public static List<string> Discover(){
  var roots=new HashSet<string>(StringComparer.OrdinalIgnoreCase);roots.Add(AppDomain.CurrentDomain.BaseDirectory);
  foreach(var key in new[]{@"HKEY_CURRENT_USER\Software\Valve\Steam",@"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Valve\Steam"})foreach(var name in new[]{"SteamPath","InstallPath"})Optional(()=>{var value=Registry.GetValue(key,name,null) as string;if(!String.IsNullOrEmpty(value))roots.Add(value);});
  DriveInfo[] drives=new DriveInfo[0];Optional(()=>drives=DriveInfo.GetDrives());foreach(var drive in drives)Optional(()=>{if(drive.IsReady && drive.DriveType==DriveType.Fixed)roots.Add(Path.Combine(drive.RootDirectory.FullName,"SteamLibrary"));});
  foreach(var root in roots.ToArray())Optional(()=>{string file=Path.Combine(root,"steamapps","libraryfolders.vdf");if(File.Exists(file) && new FileInfo(file).Length<=2097152)foreach(Match match in Regex.Matches(File.ReadAllText(file),"\"path\"\\s*\"([^\"]+)\"",RegexOptions.None,TimeSpan.FromSeconds(1)))roots.Add(match.Groups[1].Value.Replace("\\\\","\\"));});
  var found=new HashSet<string>(StringComparer.OrdinalIgnoreCase);foreach(var root in roots)foreach(var game in Installer.Games)Optional(()=>{foreach(string folder in new[]{root,Path.Combine(root,"steamapps","common",game.Folder)})if(File.Exists(Path.Combine(folder,game.Exe)) && File.Exists(Path.Combine(folder,"Launcher.exe.config")))found.Add(Path.GetFullPath(folder));});return found.OrderBy(x=>x).ToList();
 }
 public static Result Execute(string folder,bool restore){string name="Local\\CameraControlFix.LauncherInstaller."+WindowsIdentity.GetCurrent().User.Value;using(var mutex=new Mutex(false,name)){bool held=false;try{try{held=mutex.WaitOne(0);}catch(AbandonedMutexException){held=true;}if(!held)throw new IOException("Another installation is in progress");var installer=new Installer(Payload(),Guard);return restore?installer.Restore(folder):installer.Install(folder);}finally{if(held)mutex.ReleaseMutex();}}}
 public static string[] DroppedFolders(string[] inputs){
  if(inputs.Length==0)throw new ArgumentException("No game paths supplied");var result=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
  foreach(string input in inputs){if(input.StartsWith("--"))throw new ArgumentException("Options cannot be mixed with dropped game paths");string path=Path.GetFullPath(input);
   if(File.Exists(path)){if(!Installer.Games.Any(g=>String.Equals(g.Exe,Path.GetFileName(path),StringComparison.OrdinalIgnoreCase)))throw new IOException("Drop a recognized game executable or its folder");path=Path.GetDirectoryName(path);}
   if(!Directory.Exists(path) || !File.Exists(Path.Combine(path,"Launcher.exe.config")) || !Installer.Games.Any(g=>File.Exists(Path.Combine(path,g.Exe))))throw new IOException("Dropped path is not a recognized game folder");result.Add(path);
  }return result.ToArray();
 }
}
sealed class LauncherInstallWindow:Form {
 readonly ListBox folders=new ListBox();readonly Label status=new Label();readonly Button install=new Button(),restore=new Button(),browse=new Button();bool busy;
 public LauncherInstallWindow(bool preview,string[] requested=null,bool applyRequested=false){Text="Camera Control Fix Installer v2.04";ClientSize=new Size(760,430);MinimumSize=Size;MaximumSize=Size;MaximizeBox=false;StartPosition=FormStartPosition.CenterScreen;Font=new Font("Segoe UI",10);AutoScaleMode=AutoScaleMode.Dpi;AllowDrop=true;
  Controls.Add(new Label{Text="Camera Control Fix",Font=new Font("Segoe UI",23,FontStyle.Bold),Location=new Point(26,18),Size=new Size(708,47)});
  Controls.Add(new Label{Text="Install once, then use Steam and the normal Play button. Choose RTS camera mode.",Location=new Point(29,78),Size=new Size(705,46)});
  folders.SetBounds(29,125,705,120);folders.HorizontalScrollbar=true;folders.AccessibleName="Detected game folders";
  status.SetBounds(29,262,705,78);status.Text="Install applies to every listed game. You can also drop game folders or EXEs here.\nClose games and Slitherine launchers before installing or restoring.";
  install.Text="Install listed games";install.SetBounds(29,365,194,40);install.Click+=(s,e)=>Run(false);
  restore.Text="Restore listed games";restore.SetBounds(235,365,194,40);restore.Click+=(s,e)=>Run(true);
  browse.Text="Add game...";browse.SetBounds(441,365,150,40);browse.Click+=(s,e)=>{using(var dialog=new OpenFileDialog{Filter="Game executable|*.exe",Title="Select a Combat Mission game"})if(dialog.ShowDialog(this)==DialogResult.OK)Add(dialog.FileName);};
  var close=new Button{Text="Close",Location=new Point(603,365),Size=new Size(131,40)};close.Click+=(s,e)=>Close();Controls.AddRange(new Control[]{folders,status,install,restore,browse,close});
  if(!preview)foreach(var folder in requested??LauncherInstallation.Discover().ToArray())folders.Items.Add(folder);
  if(!preview && requested!=null && applyRequested)Shown+=(s,e)=>BeginInvoke(new Action(()=>Run(false)));
  DragEnter+=(s,e)=>{if(!busy && e.Data.GetDataPresent(DataFormats.FileDrop))e.Effect=DragDropEffects.Copy;};
  DragDrop+=(s,e)=>{if(busy)return;try{var targets=LauncherInstallation.DroppedFolders((string[])e.Data.GetData(DataFormats.FileDrop));foreach(var item in targets)Add(item);Run(false,targets);}catch(Exception ex){status.Text=ex.Message;}};
  FormClosing+=(s,e)=>{if(busy)e.Cancel=true;};
 }
 void Add(string input){try{string folder=Path.GetFullPath(File.Exists(input)?Path.GetDirectoryName(input):input);if(!File.Exists(Path.Combine(folder,"Launcher.exe.config")))throw new IOException("Select a game folder containing Launcher.exe.config");if(!folders.Items.Cast<string>().Any(s=>String.Equals(s,folder,StringComparison.OrdinalIgnoreCase)))folders.Items.Add(folder);}catch(Exception ex){status.Text=ex.Message;}}
 async void Run(bool undo,string[] requested=null){if(busy)return;var targets=requested??folders.Items.Cast<string>().ToArray();if(targets.Length==0){status.Text="Add or drop an installed game first.";return;}busy=true;install.Enabled=restore.Enabled=browse.Enabled=false;UseWaitCursor=true;status.Text=undo?"Restoring original launcher configurations...":"Backing up and connecting the normal Play buttons...";
  try{var results=await Task.Run(()=>targets.Select(folder=>{try{return LauncherInstallation.Execute(folder,undo);}catch(Exception ex){return new Result{Status="failed",GameFolder=folder,Message=ex.GetBaseException().Message};}}).ToArray());int failed=results.Count(r=>r.Status=="failed");status.Text=failed==0?(undo?"Original launcher configurations restored.":"Installed for selected games. Use Steam and Play normally."):failed+" game(s) need attention: "+String.Join("; ",results.Where(r=>r.Status=="failed").Select(r=>Path.GetFileName(r.GameFolder)+": "+r.Message));}
  finally{busy=false;install.Enabled=restore.Enabled=browse.Enabled=true;UseWaitCursor=false;}
 }
}
static class LauncherInstallProgram {
 [STAThread]static int Main(string[] args){
  if(args.Length==0){Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);Application.Run(new LauncherInstallWindow(false));return 0;}
  if(args.All(a=>!a.StartsWith("--"))){try{string[] requested=LauncherInstallation.DroppedFolders(args);Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);Application.Run(new LauncherInstallWindow(false,requested,true));return 0;}catch(Exception ex){MessageBox.Show(ex.Message,"Camera Control Fix Installer",MessageBoxButtons.OK,MessageBoxIcon.Error);return 1;}}
  if(args.Length==2 && args[0]=="--preview"){Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);using(var form=new LauncherInstallWindow(true)){form.ShowInTaskbar=false;form.StartPosition=FormStartPosition.Manual;form.Location=new Point(-30000,-30000);form.Show();Application.DoEvents();using(var image=new Bitmap(form.Width,form.Height)){form.DrawToBitmap(image,new Rectangle(0,0,image.Width,image.Height));image.Save(args[1]);}form.Close();}return 0;}
  int code=0;object result;try{if((args.Length!=2 && !(args.Length==4 && args[2]=="--result")) || args[0]!="--install" && args[0]!="--restore")throw new ArgumentException("Use --install <gamefolder> or --restore <gamefolder>, optionally --result <jsonfile>");result=LauncherInstallation.Execute(args[1],args[0]=="--restore");}catch(Exception ex){code=1;result=new Result{Status="failed",Message=ex.ToString()};}
  string output=new JavaScriptSerializer().Serialize(result);
  try{using(var stdout=new StreamWriter(Console.OpenStandardOutput(),new System.Text.UTF8Encoding(false))){stdout.WriteLine(output);}}catch(IOException){}
  if(args.Length==4)try{File.WriteAllText(args[3],output);}catch(Exception ex){try{Console.Error.WriteLine(ex.Message);}catch(IOException){}if(code==0)code=3;}return code;
 }
}
