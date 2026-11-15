// Camera Control Fix 2.04: invoked only by the installed game's Play action.
using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Diagnostics;
using System.Threading;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.Web.Script.Serialization;
using CombatMissionControlFix;
[assembly:System.Reflection.AssemblyTitle("Camera Control Fix Game Host")]
[assembly:System.Reflection.AssemblyProduct("Camera Control Fix v2.04")]
[assembly:System.Reflection.AssemblyVersion("2.4.0.0")]
[assembly:System.Reflection.AssemblyFileVersion("2.4.0.0")]
public sealed class LaunchSettings {public string version,game_exe,working_subdirectory;}
public static class LaunchApplyHost {
 const string Version="2.04";
 static readonly JavaScriptSerializer Json=new JavaScriptSerializer();
 static string resultPath,gamePath;
 static int gamePid;static long gameStart;
 static readonly int Session=Process.GetCurrentProcess().SessionId;
 static readonly string Sid=WindowsIdentity.GetCurrent().User.Value;
 static IDisposable recoveryLease;
 [DllImport("kernel32",SetLastError=true)]static extern IntPtr OpenProcess(uint access,bool inherit,int pid);
 [DllImport("kernel32")]static extern bool CloseHandle(IntPtr handle);
 [DllImport("advapi32",SetLastError=true)]static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
 static bool SameOwner(int pid){
  IntPtr handle=OpenProcess(0x1000,false,pid),token=IntPtr.Zero;if(handle==IntPtr.Zero)return false;
  try{if(!OpenProcessToken(handle,8,out token))return false;using(var identity=new WindowsIdentity(token))return identity.User.Value==Sid;}
  finally{if(token!=IntPtr.Zero)CloseHandle(token);CloseHandle(handle);}
 }
 public static string Quote(string value) {
  var b=new StringBuilder("\"");int slashes=0;
  foreach(char c in value){if(c=='\\'){slashes++;continue;}if(c=='\"'){b.Append('\\',slashes*2+1);b.Append(c);}else{b.Append('\\',slashes);b.Append(c);}slashes=0;}
  b.Append('\\',slashes*2);return b.Append('"').ToString();
 }
 public static string WorkingDirectory(string root,string relative) {
  if(String.IsNullOrEmpty(relative))return root;
  if(Path.IsPathRooted(relative))throw new InvalidDataException("Working directory must be relative to the game.");
  string dir=Path.GetFullPath(Path.Combine(root,relative));
  if(!dir.StartsWith(root.TrimEnd('\\')+"\\",StringComparison.OrdinalIgnoreCase) || !Directory.Exists(dir))throw new InvalidDataException("Working directory is outside the installed game or missing.");
  return dir;
 }
 static void Record(string status,string detail) {
  if(resultPath==null)return;
  try{File.WriteAllText(resultPath,Json.Serialize(new{version=Version,host_pid=Process.GetCurrentProcess().Id,game_path=gamePath,pid=gamePid,start_ticks=gameStart,status=status,detail=detail,utc=DateTime.UtcNow.ToString("o")}));}catch(IOException){}catch(UnauthorizedAccessException){}
 }
 static bool Gone(int pid,long ticks) {
  try{using(var p=Process.GetProcessById(pid))return p.HasExited || p.StartTime.ToUniversalTime().Ticks!=ticks;}
  catch(ArgumentException){return true;}
  catch(System.ComponentModel.Win32Exception){return false;}
  catch(InvalidOperationException){return false;}
 }
 static Tuple<int,long>[] Matches() {
  var matches=new System.Collections.Generic.List<Tuple<int,long>>();
  foreach(var p in Process.GetProcessesByName(Path.GetFileNameWithoutExtension(gamePath)))using(p){
   try{
    if(p.HasExited || p.SessionId!=Session || !SameOwner(p.Id))continue;
    long ticks=p.StartTime.ToUniversalTime().Ticks;
    if(String.Equals(Path.GetFullPath(p.MainModule.FileName),gamePath,StringComparison.OrdinalIgnoreCase))matches.Add(Tuple.Create(p.Id,ticks));
   }catch(ArgumentException){if(!RuntimeProcessWait.ConfirmExited(p.Id))throw;}
   catch(InvalidOperationException){if(!RuntimeProcessWait.ConfirmExited(p.Id))throw;}
   catch(System.ComponentModel.Win32Exception){if(!RuntimeProcessWait.ConfirmExited(p.Id))throw;}
  }
  return matches.ToArray();
 }
 static string Apply() {
  var timer=Stopwatch.StartNew();
  while(timer.Elapsed.TotalSeconds<120){
   if(gamePid==0){var matches=Matches();if(matches.Length>1)throw new IOException("Multiple matching game processes; no patch applied.");if(matches.Length==1){gamePid=matches[0].Item1;gameStart=matches[0].Item2;Record("waiting_for_engine",null);}}
   if(gamePid!=0){
    bool transaction=false;
    try{
     using(var session=RuntimeSession.Attach(gamePid)){
      if(session.ProcessStartTicks!=gameStart || !SameOwner(gamePid))throw new IOException("Game process identity or owner changed.");
      var snapshot=session.ReadModule();
      if(!String.Equals(Path.GetFullPath(snapshot.ModulePath),gamePath,StringComparison.OrdinalIgnoreCase))throw new IOException("Game executable path changed.");
      var plan=CombinedRuntime.Resolve(session);
      if(plan!=null){
       if(!SameOwner(gamePid))throw new IOException("Game process owner cannot be verified.");
       if(!plan.Hud.Existing)plan.Hud.Apply=()=>session.Apply(HudLateRegistration.Resolve);
       Record("applying",null);transaction=true;CombinedRuntime.Apply(session,plan);return "applied";
      }
     }
    }catch(CombinedAlreadyAppliedException){return "already_active";}
    catch(PatchFailureException ex){recoveryLease=ex.RetainedSuspension;throw;}
    catch{if(!transaction && Gone(gamePid,gameStart)){gamePid=0;gameStart=0;}else throw;}
   }
   Thread.Sleep(350);
  }
  throw new IOException("No supported engine became ready within 120 seconds. No further patch attempts will be made.");
 }
 static void WaitForGame(){while(gamePid!=0 && !Gone(gamePid,gameStart)){GC.KeepAlive(recoveryLease);Thread.Sleep(750);}GC.KeepAlive(recoveryLease);}
 [STAThread]public static int Main(string[] args){
  try{
   string hostDir=Path.GetFullPath(AppDomain.CurrentDomain.BaseDirectory),root=Path.GetFullPath(Path.Combine(hostDir,".."));
   string logDir=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"CombatMissionControlFix","launches");Directory.CreateDirectory(logDir);
   using(var self=Process.GetCurrentProcess())resultPath=Path.Combine(logDir,self.Id+"_"+self.StartTime.ToUniversalTime().Ticks+".json");
   string config=Path.Combine(hostDir,"launch.json");if(!File.Exists(config) || new FileInfo(config).Length>16384)throw new InvalidDataException("Missing or invalid installed launch settings.");
   var settings=Json.Deserialize<LaunchSettings>(File.ReadAllText(config));
   if(settings==null || settings.version!=Version || !RuntimeLauncher.Games.Any(g=>g.Exe==settings.game_exe))throw new InvalidDataException("Unrecognized installed game settings.");
   gamePath=Path.GetFullPath(Path.Combine(root,settings.game_exe));if(!File.Exists(gamePath))throw new FileNotFoundException("Original game executable is missing.",gamePath);
   string cwd=WorkingDirectory(root,settings.working_subdirectory),key;
   using(var sha=SHA256.Create())key=BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(gamePath.ToUpperInvariant()))).Replace("-","");
   string name="Local\\CameraControlFix.Play."+WindowsIdentity.GetCurrent().User.Value+"."+Session+"."+key;
   using(var mutex=new Mutex(false,name)){
    bool owns=false;try{
     try{owns=mutex.WaitOne(0);}catch(AbandonedMutexException){owns=true;}
     if(!owns){Record("duplicate_launch_ignored",null);return 0;}
     var running=Matches();if(running.Length>1)throw new IOException("Multiple game processes are already running.");
     if(running.Length==0){
      Record("starting_game",null);
      using(var child=Process.Start(new ProcessStartInfo(gamePath,String.Join(" ",args.Select(Quote).ToArray())){WorkingDirectory=cwd,UseShellExecute=false})){}
     }else{gamePid=running[0].Item1;gameStart=running[0].Item2;}
     string result;
     try{result=Apply();Record(result,null);}
     catch(PatchFailureException ex){Record("recovery_required",ex.ToString());WaitForGame();return 2;}
     catch(Exception ex){Record("failed",ex.ToString());WaitForGame();return 1;}
     // Slitherine waits for its Play child. Preserve that lifetime without a
     // global watcher, login entry, polling for other games, or visible UI.
     WaitForGame();Record(result+"_game_exited",null);return 0;
    }finally{if(owns)mutex.ReleaseMutex();}
   }
  }catch(Exception ex){Record("failed",ex.ToString());if(recoveryLease!=null)WaitForGame();return 1;}
 }
}
