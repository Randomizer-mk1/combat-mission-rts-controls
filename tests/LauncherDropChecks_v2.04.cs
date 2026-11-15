using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Windows.Forms;
using System.Drawing;
using System.Threading;
static class LauncherDropChecks {
 [STAThread]static int Main(string[] args){
  var assembly=Assembly.LoadFrom(args[0]);var helper=assembly.GetType("LauncherInstallation");var normalize=helper.GetMethod("DroppedFolders",BindingFlags.Public|BindingFlags.Static);
  string one=args[1],other=args[2];byte[] before=File.ReadAllBytes(Path.Combine(other,"Launcher.exe.config"));
  string[] folders=(string[])normalize.Invoke(null,new object[]{new[]{one,Path.Combine(one,"CM Normandy.exe")}});if(folders.Length!=1 || folders[0]!=one)throw new Exception("Dropped path dedup/normalization failed");
  bool rejected=false;try{normalize.Invoke(null,new object[]{new[]{"--unknown",one}});}catch(TargetInvocationException){rejected=true;}if(!rejected)throw new Exception("Unknown option accepted as path");
  Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);
  using(var form=(Form)Activator.CreateInstance(assembly.GetType("LauncherInstallWindow"),new object[]{false,args.Length>3?new[]{other}:folders,args.Length<=3})){
   form.ShowInTaskbar=false;form.StartPosition=FormStartPosition.Manual;form.Location=new Point(-30000,-30000);form.Show();if(args.Length>3){var data=new DataObject(DataFormats.FileDrop,new[]{one});typeof(Control).GetMethod("OnDragDrop",BindingFlags.NonPublic|BindingFlags.Instance).Invoke(form,new object[]{new DragEventArgs(data,0,0,0,DragDropEffects.Copy,DragDropEffects.Copy)});}var timer=System.Diagnostics.Stopwatch.StartNew();
   while(timer.ElapsedMilliseconds<10000){Application.DoEvents();if(File.Exists(Path.Combine(one,"CameraControlFix","install.json")) && !(bool)form.GetType().GetField("busy",BindingFlags.NonPublic|BindingFlags.Instance).GetValue(form))break;Thread.Sleep(30);}
   if(!File.Exists(Path.Combine(one,"CameraControlFix","install.json")))throw new Exception("Explicit dropped target did not install");form.Close();
  }
  if(Directory.Exists(Path.Combine(other,"CameraControlFix")) || !File.ReadAllBytes(Path.Combine(other,"Launcher.exe.config")).SequenceEqual(before))throw new Exception("Unrequested target changed");
  Console.WriteLine("PASS: actual installer form explicit-drop path installed only requested isolated target; duplicate path dedup; unknown option rejected. No game launch.");return 0;
 }
}
