// v1.83: x86 process transport. No scanning rules, authentication changes, or automatic game launch.
using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace CombatMissionControlFix {
 public sealed class ModuleSnapshot {
  public ulong BaseAddress; public string ModulePath; public byte[] Image; public bool[] Readable;
  public Func<ulong,int,byte[]> ReadRemote; // Valid only while the owning RuntimeSession is alive.
  public bool CanRead(uint rva,int count) {return count>=0 && (ulong)rva+(ulong)count<=(ulong)Image.Length && Enumerable.Range((int)rva,count).All(i=>Readable[i]);}
 }
 public sealed class GuardedPatch {
  public uint Rva; public byte[] Expected; public Func<ulong,byte[]> BuildReplacement;
 }
 public sealed class PatchPlan {
  public int PayloadSize; public Func<ulong,byte[]> BuildPayload;
  public uint PayloadProtection=0x20; // PAGE_EXECUTE_READ; use 0x40 only for intentionally mutable payload state.
  public int WritablePayloadOffset=-1; // Optional page-aligned RW data tail; preceding pages retain PayloadProtection.
  public List<GuardedPatch> Patches=new List<GuardedPatch>();
 }
 public sealed class AppliedPatch { public ulong Address;public byte[] Original,Replacement; }
 public sealed class PatchReceipt {
  public int ProcessId;public long ProcessStartTicks;public ulong PayloadAddress;public int PayloadSize;public bool RolledBack;
  public ulong ModuleBase;public string ModulePath;public int PayloadCodeLength;public string PayloadCodeSha256;
  public List<AppliedPatch> Patches=new List<AppliedPatch>();
 }
 public sealed class PatchFailureException:IOException {
  // If recovery failed, threads remain stopped. Caller must repair or terminate the target before releasing this lease.
  public IDisposable RetainedSuspension {get;private set;}
  public PatchFailureException(string message,Exception inner,IDisposable lease):base(message,inner){RetainedSuspension=lease;}
 }
 static class Native {
  [StructLayout(LayoutKind.Sequential)]internal struct MemoryInfo {public IntPtr BaseAddress,AllocationBase;public uint AllocationProtect;public UIntPtr RegionSize;public uint State,Protect,Type;}
  [DllImport("kernel32",SetLastError=true)]internal static extern UIntPtr VirtualQueryEx(IntPtr h,IntPtr address,out MemoryInfo info,UIntPtr length);
  [DllImport("kernel32",SetLastError=true)]internal static extern IntPtr OpenProcess(uint rights,bool inherit,int pid);
  [DllImport("kernel32",SetLastError=true)]internal static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32",SetLastError=true)]internal static extern bool ReadProcessMemory(IntPtr h,IntPtr address,byte[] data,UIntPtr size,out UIntPtr read);
  [DllImport("kernel32",SetLastError=true)]internal static extern bool WriteProcessMemory(IntPtr h,IntPtr address,byte[] data,UIntPtr size,out UIntPtr written);
  [DllImport("kernel32",SetLastError=true)]internal static extern IntPtr VirtualAllocEx(IntPtr h,IntPtr address,UIntPtr size,uint kind,uint protection);
  [DllImport("kernel32",SetLastError=true)]internal static extern bool VirtualFreeEx(IntPtr h,IntPtr address,UIntPtr size,uint kind);
  [DllImport("kernel32",SetLastError=true)]internal static extern bool VirtualProtectEx(IntPtr h,IntPtr address,UIntPtr size,uint protection,out uint prior);
  [DllImport("kernel32",SetLastError=true)]internal static extern bool FlushInstructionCache(IntPtr h,IntPtr address,UIntPtr size);
  [DllImport("kernel32",SetLastError=true)]internal static extern IntPtr OpenThread(uint rights,bool inherit,uint tid);
  [DllImport("kernel32",SetLastError=true)]internal static extern uint SuspendThread(IntPtr h);
  [DllImport("kernel32",SetLastError=true)]internal static extern uint ResumeThread(IntPtr h);
  [DllImport("kernel32",SetLastError=true)]internal static extern bool GetThreadContext(IntPtr h,[In,Out] byte[] context);
  [DllImport("kernel32",SetLastError=true)]internal static extern bool IsWow64Process(IntPtr h,out bool wow64);
  internal static IntPtr Ptr(ulong address){if(address>UInt32.MaxValue)throw new IOException("x86 address overflow");return new IntPtr(unchecked((int)(uint)address));}
  internal static ulong Address(IntPtr p){return unchecked((uint)p.ToInt32());}
  internal static void Require(bool ok,string operation){if(!ok)throw new Win32Exception(Marshal.GetLastWin32Error(),operation);}
 }
 sealed class ThreadPause:IDisposable {
  readonly Dictionary<int,IntPtr> threads=new Dictionary<int,IntPtr>();
  public ThreadPause(Process process) {
   try {
    for(int pass=0;pass<8;pass++) {
     process.Refresh();var ids=process.Threads.Cast<ProcessThread>().Select(t=>t.Id).ToArray();
     foreach(int id in ids)if(!threads.ContainsKey(id)) {
      IntPtr h=Native.OpenThread(0x0002|0x0008|0x0040,false,(uint)id);Native.Require(h!=IntPtr.Zero,"OpenThread");
      if(Native.SuspendThread(h)==UInt32.MaxValue){Native.CloseHandle(h);throw new Win32Exception(Marshal.GetLastWin32Error(),"SuspendThread");}
      threads.Add(id,h);
     }
     process.Refresh();if(process.Threads.Cast<ProcessThread>().All(t=>threads.ContainsKey(t.Id)))return;
    }
    throw new IOException("Target thread set did not stabilize");
   }catch(Exception failure){
    try{Dispose();}
    catch(Exception recovery){throw new PatchFailureException("Thread suspension failed and some threads could not resume.",new AggregateException(failure,recovery),this);}
    throw;
   }
  }
  public void RejectInstructionPointers(IEnumerable<Tuple<ulong,ulong>> spans) {
   foreach(var h in threads.Values) {
    byte[] context=new byte[716];Buffer.BlockCopy(BitConverter.GetBytes(0x00010001),0,context,0,4);
    Native.Require(Native.GetThreadContext(h,context),"GetThreadContext");ulong ip=BitConverter.ToUInt32(context,184);
    if(spans.Any(s=>ip>=s.Item1 && ip<s.Item2))throw new IOException("A thread is inside a patch span; retry at a safe game state.");
   }
  }
  public void VerifyStable(Process process) {process.Refresh();if(process.Threads.Cast<ProcessThread>().Any(t=>!threads.ContainsKey(t.Id)))throw new IOException("A new target thread appeared; retry patching.");}
  public void Dispose() {
   var errors=new List<Exception>();
   foreach(var entry in threads.ToArray()) {
    if(Native.ResumeThread(entry.Value)==UInt32.MaxValue)errors.Add(new Win32Exception(Marshal.GetLastWin32Error(),"ResumeThread "+entry.Key));
    else {Native.CloseHandle(entry.Value);threads.Remove(entry.Key);}
   }
   if(errors.Count>0)throw new AggregateException("Some threads could not resume; retry lease disposal or stop target.",errors);
  }
 }
 public sealed class RuntimeSession:IDisposable {
#if TRANSPORT_TESTS
  internal static Action<int> AfterWrite;
#endif
  readonly Process process;readonly IntPtr handle;readonly long startTicks;readonly object gate=new object();bool disposed;
  RuntimeSession(int pid) {
   if(IntPtr.Size!=4)throw new PlatformNotSupportedException("Compile transport caller as x86.");
   if(pid==Process.GetCurrentProcess().Id)throw new IOException("Cannot pause own process.");
   process=Process.GetProcessById(pid);startTicks=process.StartTime.ToUniversalTime().Ticks;
   handle=Native.OpenProcess(0x0400|0x0010|0x0020|0x0008,false,pid);Native.Require(handle!=IntPtr.Zero,"OpenProcess");
   try {bool wow;Native.Require(Native.IsWow64Process(handle,out wow),"IsWow64Process");if(Environment.Is64BitOperatingSystem && !wow)throw new IOException("Only x86 targets supported.");}
   catch{Native.CloseHandle(handle);process.Dispose();throw;}
  }
  public static RuntimeSession Attach(int pid){return new RuntimeSession(pid);}
  public int ProcessId {get{return process.Id;}}
  public long ProcessStartTicks {get{return startTicks;}}
  void Alive(){if(disposed)throw new ObjectDisposedException("RuntimeSession");if(process.HasExited)throw new IOException("Target exited");}
  byte[] Read(ulong address,int length) {
   byte[] bytes=new byte[length];UIntPtr got;Native.Require(Native.ReadProcessMemory(handle,Native.Ptr(address),bytes,(UIntPtr)length,out got) && got.ToUInt64()==(ulong)length,"ReadProcessMemory");return bytes;
  }
  public ModuleSnapshot ReadModule() {lock(gate){Alive();return Snapshot();}}
  public byte[] ReadRemote(ulong address,int length) {
   lock(gate) {
    Alive();if(length<1 || length>1048576 || address>UInt32.MaxValue || address+(ulong)length>0x100000000UL)throw new IOException("Remote read is outside the bounded x86 range");
    ulong cursor=address,end=address+(ulong)length;
    while(cursor<end) {
     Native.MemoryInfo region;Native.Require(Native.VirtualQueryEx(handle,Native.Ptr(cursor),out region,(UIntPtr)Marshal.SizeOf(typeof(Native.MemoryInfo))).ToUInt64()!=0,"VirtualQueryEx");
     uint access=region.Protect&0xff;
     if(region.State!=0x1000 || (region.Protect&0x100)!=0 || !(access==2 || access==4 || access==8 || access==0x20 || access==0x40 || access==0x80))throw new IOException("Remote range is not committed readable memory");
     ulong next=Native.Address(region.BaseAddress)+region.RegionSize.ToUInt64();if(next<=cursor || next>0x100000000UL)throw new IOException("Invalid remote region");cursor=Math.Min(end,next);
    }
    return Read(address,length);
   }
  }
  ModuleSnapshot Snapshot() {
   process.Refresh();var module=process.MainModule;int size=module.ModuleMemorySize;
   if(size<4096 || size>268435456)throw new IOException("Invalid module image size");
   var s=new ModuleSnapshot{BaseAddress=Native.Address(module.BaseAddress),ModulePath=module.FileName,Image=new byte[size],Readable=new bool[size],ReadRemote=ReadRemote};
   for(int offset=0;offset<size;offset+=4096) {
    int count=Math.Min(4096,size-offset);byte[] data=new byte[count];UIntPtr got;
    if(Native.ReadProcessMemory(handle,Native.Ptr(s.BaseAddress+(uint)offset),data,(UIntPtr)count,out got) && got.ToUInt64()==(ulong)count) {
     Buffer.BlockCopy(data,0,s.Image,offset,count);for(int i=offset;i<offset+count;i++)s.Readable[i]=true;
    }
   }
   return s;
  }
  void Flush(ulong address,int size){Native.Require(Native.FlushInstructionCache(handle,Native.Ptr(address),(UIntPtr)size),"FlushInstructionCache");}
  void RawWrite(ulong address,byte[] data) {UIntPtr wrote;Native.Require(Native.WriteProcessMemory(handle,Native.Ptr(address),data,(UIntPtr)data.Length,out wrote) && wrote.ToUInt64()==(ulong)data.Length,"WriteProcessMemory");if(!Read(address,data.Length).SequenceEqual(data))throw new IOException("Remote write readback mismatch");}
  void ProtectedWrite(ulong address,byte[] data,Dictionary<ulong,uint> protections) {
   // Restore each page independently, including heterogeneous original protections.
   var changed=new List<Tuple<ulong,uint>>();Exception failure=null;
   try {
    ulong end=address+(ulong)data.Length;
    for(ulong page=address&~4095UL;page<end;page+=4096) {uint old;Native.Require(Native.VirtualProtectEx(handle,Native.Ptr(page),(UIntPtr)4096,0x40,out old),"VirtualProtectEx patch");if(!protections.ContainsKey(page))protections.Add(page,old);changed.Add(Tuple.Create(page,protections[page]));}
    RawWrite(address,data);Flush(address,data.Length);
   }catch(Exception ex){failure=ex;}
   var errors=new List<Exception>();if(failure!=null)errors.Add(failure);
   foreach(var page in changed.AsEnumerable().Reverse()){uint ignored;if(!Native.VirtualProtectEx(handle,Native.Ptr(page.Item1),(UIntPtr)4096,page.Item2,out ignored))errors.Add(new Win32Exception(Marshal.GetLastWin32Error(),"Restore page protection"));}
   if(errors.Count>0)throw new AggregateException(errors);
  }
  public PatchReceipt Apply(Func<ModuleSnapshot,PatchPlan> resolve) {
   if(resolve==null)throw new ArgumentNullException("resolve");
   lock(gate) {
    Alive();ThreadPause pause=new ThreadPause(process);bool retain=false;ulong allocation=0;
    var receipt=new PatchReceipt{ProcessId=process.Id,ProcessStartTicks=startTicks};var touched=new List<AppliedPatch>();
    var protections=new Dictionary<ulong,uint>();
    try {
     var snapshot=Snapshot();var plan=resolve(snapshot);if(plan==null)throw new IOException("Runtime module is not ready or no supported signature matched.");
     receipt.ModuleBase=snapshot.BaseAddress;receipt.ModulePath=snapshot.ModulePath;
     if(plan.PayloadSize<1 || plan.PayloadSize>16777216 || plan.BuildPayload==null || plan.Patches==null || plan.Patches.Count<1 || plan.Patches.Count>512)throw new IOException("Invalid patch plan");
     if(plan.PayloadProtection!=0x20 && plan.PayloadProtection!=0x40)throw new IOException("Invalid payload protection");
     if(plan.WritablePayloadOffset!=-1 && (plan.WritablePayloadOffset<0 || plan.WritablePayloadOffset>=plan.PayloadSize || plan.WritablePayloadOffset%4096!=0))throw new IOException("Invalid writable payload tail");
     var spans=new List<Tuple<ulong,ulong>>();
     foreach(var p in plan.Patches) {
      if(p.Expected==null || p.Expected.Length==0 || p.Expected.Length>65536 || p.BuildReplacement==null || !snapshot.CanRead(p.Rva,p.Expected.Length))throw new IOException("Invalid/unreadable patch guard");
      ulong a=snapshot.BaseAddress+p.Rva,b=a+(ulong)p.Expected.Length;
      if(spans.Any(s=>a<s.Item2 && b>s.Item1))throw new IOException("Overlapping patches");spans.Add(Tuple.Create(a,b));
      if(!Read(a,p.Expected.Length).SequenceEqual(p.Expected))throw new IOException("Exact-byte guard mismatch; target unchanged");
     }
     pause.RejectInstructionPointers(spans);
     IntPtr ptr=Native.VirtualAllocEx(handle,IntPtr.Zero,(UIntPtr)plan.PayloadSize,0x3000,0x04);Native.Require(ptr!=IntPtr.Zero,"VirtualAllocEx");allocation=Native.Address(ptr);
     receipt.PayloadAddress=allocation;receipt.PayloadSize=plan.PayloadSize;
     byte[] payload=plan.BuildPayload(allocation);if(payload==null || payload.Length!=plan.PayloadSize)throw new IOException("Payload length mismatch");
     receipt.PayloadCodeLength=plan.WritablePayloadOffset>=0?plan.WritablePayloadOffset:plan.PayloadSize;
     using(var sha=System.Security.Cryptography.SHA256.Create())receipt.PayloadCodeSha256=BitConverter.ToString(sha.ComputeHash(payload,0,receipt.PayloadCodeLength)).Replace("-","").ToLowerInvariant();
     foreach(var p in plan.Patches) {
      byte[] bytes=p.BuildReplacement(allocation);if(bytes==null || bytes.Length!=p.Expected.Length)throw new IOException("Replacement length mismatch");
      receipt.Patches.Add(new AppliedPatch{Address=snapshot.BaseAddress+p.Rva,Original=(byte[])p.Expected.Clone(),Replacement=(byte[])bytes.Clone()});
     }
     RawWrite(allocation,payload);uint old;Native.Require(Native.VirtualProtectEx(handle,Native.Ptr(allocation),(UIntPtr)plan.PayloadSize,plan.PayloadProtection,out old),"Protect payload");Flush(allocation,payload.Length);
     if(plan.WritablePayloadOffset>=0)Native.Require(Native.VirtualProtectEx(handle,Native.Ptr(allocation+(uint)plan.WritablePayloadOffset),(UIntPtr)(plan.PayloadSize-plan.WritablePayloadOffset),0x04,out old),"Protect payload data");
     foreach(var p in receipt.Patches) {
      pause.VerifyStable(process);
      if(!Read(p.Address,p.Original.Length).SequenceEqual(p.Original))throw new IOException("Guard changed before write");
      touched.Add(p);ProtectedWrite(p.Address,p.Replacement,protections);
#if TRANSPORT_TESTS
      if(AfterWrite!=null)AfterWrite(touched.Count);
#endif
     }
     return receipt;
    }catch(Exception failure) {
     var errors=new List<Exception>();
     // Never guess ownership of a partial write or overwrite a third party's newer bytes.
     foreach(var p in touched)try{var current=Read(p.Address,p.Original.Length);if(!current.SequenceEqual(p.Original) && !current.SequenceEqual(p.Replacement))throw new IOException("Recovery guard mismatch; preserve changed/partial bytes at "+p.Address.ToString("x"));}catch(Exception ex){errors.Add(ex);}
     if(errors.Count==0)foreach(var p in touched.AsEnumerable().Reverse())try{
      pause.VerifyStable(process);
      var current=Read(p.Address,p.Original.Length);
      if(!current.SequenceEqual(p.Original) && !current.SequenceEqual(p.Replacement))throw new IOException("Recovery guard changed before write");
      ProtectedWrite(p.Address,p.Original,protections);
     }catch(Exception ex){errors.Add(ex);break;}
     if(errors.Count>0) {retain=true;errors.Insert(0,failure);throw new PatchFailureException("Patch recovery failed; target threads remain paused. Retain payload and repair or terminate target before releasing suspension.",new AggregateException(errors),pause);}
     if(allocation!=0 && !Native.VirtualFreeEx(handle,Native.Ptr(allocation),UIntPtr.Zero,0x8000))throw new IOException("Hooks recovered but unused payload allocation could not be freed",failure);
     throw;
    }finally {if(!retain)ReleasePause(pause);}
   }
  }
  public void Rollback(PatchReceipt receipt) {
   lock(gate) {
    Alive();if(receipt==null || receipt.ProcessId!=process.Id || receipt.ProcessStartTicks!=startTicks || receipt.RolledBack)throw new IOException("Receipt does not match active session");
    ThreadPause pause=new ThreadPause(process);bool retain=false;
    try {
     pause.RejectInstructionPointers(receipt.Patches.Select(p=>Tuple.Create(p.Address,p.Address+(ulong)p.Replacement.Length)));
     foreach(var p in receipt.Patches)if(!Read(p.Address,p.Replacement.Length).SequenceEqual(p.Replacement))throw new IOException("Rollback guard mismatch; no writes made");
     pause.VerifyStable(process);
     var protections=new Dictionary<ulong,uint>();var errors=new List<Exception>();foreach(var p in receipt.Patches.AsEnumerable().Reverse())try{
      pause.VerifyStable(process);
      if(!Read(p.Address,p.Replacement.Length).SequenceEqual(p.Replacement))throw new IOException("Rollback guard changed before write");
      ProtectedWrite(p.Address,p.Original,protections);
     }catch(Exception ex){errors.Add(ex);break;}
     if(errors.Count>0){retain=true;throw new PatchFailureException("Rollback incomplete; target remains paused.",new AggregateException(errors),pause);}
     // Retain executable payload: a paused thread's stack may still return into it after hooks are detached.
     receipt.RolledBack=true;
    }finally{if(!retain)ReleasePause(pause);}
   }
  }
  static void ReleasePause(ThreadPause pause){try{pause.Dispose();}catch(Exception ex){throw new PatchFailureException("Some target threads remain paused; retry disposal or terminate target.",ex,pause);}}
  public void Dispose(){lock(gate){if(!disposed){disposed=true;Native.CloseHandle(handle);process.Dispose();}}}
 }
 public sealed class GameTarget {public string Id,Title,Exe,SteamApp;}
 public static class RuntimeLauncher {
  public static readonly GameTarget[] Games={
   new GameTarget{Id="sf2",Title="Shock Force 2",Exe="CM Shock Force 2.exe",SteamApp="1369370"},
   new GameTarget{Id="normandy",Title="Battle for Normandy",Exe="CM Normandy.exe",SteamApp="2297010"},
   new GameTarget{Id="coldwar",Title="Cold War",Exe="CM Cold War.exe",SteamApp="1551160"},
   new GameTarget{Id="blacksea",Title="Black Sea",Exe="CM Black Sea.exe"},
   new GameTarget{Id="redthunder",Title="Red Thunder",Exe="CM Red Thunder.exe"},
   new GameTarget{Id="fortressitaly",Title="Fortress Italy",Exe="CM Fortress Italy.exe"},
   new GameTarget{Id="finalblitzkrieg",Title="Final Blitzkrieg",Exe="CM Final Blitzkrieg.exe"}};
  public static List<Tuple<GameTarget,int>> DiscoverProcesses(){var result=new List<Tuple<GameTarget,int>>();foreach(var game in Games)foreach(var p in Process.GetProcessesByName(Path.GetFileNameWithoutExtension(game.Exe))){using(p)result.Add(Tuple.Create(game,p.Id));}return result;}
  public static void LaunchSteam(string id){var game=Games.Single(g=>g.Id==id);if(game.SteamApp==null)throw new IOException("No verified Steam app ID; supply executable path.");Process.Start(new ProcessStartInfo("steam://rungameid/"+game.SteamApp){UseShellExecute=true});}
  public static void LaunchExecutable(string path){path=Path.GetFullPath(path);if(!File.Exists(path) || !Games.Any(g=>String.Equals(g.Exe,Path.GetFileName(path),StringComparison.OrdinalIgnoreCase)))throw new IOException("Supply a recognized game executable");Process.Start(new ProcessStartInfo(path){WorkingDirectory=Path.GetDirectoryName(path),UseShellExecute=false});}
 }
}
