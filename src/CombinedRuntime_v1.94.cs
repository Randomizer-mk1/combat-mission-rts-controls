using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using CombatMissionControlFix;

public sealed class CombinedAlreadyAppliedException:Exception {
 public CombinedAlreadyAppliedException():base("Camera controls and HUD are already active."){}
}
public sealed class CombinedFailureException:IOException {
 public bool CameraActive,HudActive;
 public CombinedFailureException(string message,Exception inner,bool camera,bool hud):base(message,inner){CameraActive=camera;HudActive=hud;}
}
public sealed class RuntimeComponent {
 public string Name;public bool Existing;
 public Func<PatchReceipt> Apply;public Action<PatchReceipt> Save,Rollback,Retire;
}
public sealed class CombinedPlan {public RuntimeComponent Camera,Hud;}
public static class CombinedRuntime {
 static RuntimeComponent Component(RuntimeSession session,string name,string directory,bool existing,Func<ModuleSnapshot,PatchPlan> resolver) {
  byte[] saved=null;string file=Path.Combine(directory,session.ProcessId+"_"+session.ProcessStartTicks+".json");
  return new RuntimeComponent {
   Name=name,Existing=existing,Apply=()=>session.Apply(resolver),Rollback=r=>session.Rollback(r),
   Save=r=>{
    bool existedBefore=File.Exists(file);
    // Capture the receipt even if post-save verification fails, so rollback can retire only this operation's record.
    try{RuntimeReceiptStore.SaveVerified(session,session.ReadModule(),r,directory);}
    finally{if(!existedBefore && File.Exists(file)){
     byte[] bytes=File.ReadAllBytes(file),expected=System.Text.Encoding.UTF8.GetBytes(new System.Web.Script.Serialization.JavaScriptSerializer().Serialize(r));
     if(bytes.SequenceEqual(expected))saved=bytes;
    }}
   },
   Retire=r=>{
    if(saved==null)return;
    if(!r.RolledBack)throw new IOException("Cannot retire an active "+name+" receipt");
    if(!File.Exists(file) || !File.ReadAllBytes(file).SequenceEqual(saved))throw new IOException(name+" receipt changed externally; preserved");
    File.Move(file,file+".rolledback_"+Guid.NewGuid().ToString("N"));
   }
  };
 }
 public static CombinedPlan Resolve(RuntimeSession session) {
  var snapshot=session.ReadModule();string cameraDirectory=RuntimeReceiptStore.DefaultDirectory,hudDirectory=Path.Combine(cameraDirectory,"hud");
  bool camera=RuntimeReceiptStore.Check(session,snapshot,cameraDirectory),hud=RuntimeReceiptStore.Check(session,snapshot,hudDirectory);
  PatchPlan cameraPlan=null,hudPlan=null;
  if(!camera)try{cameraPlan=EngineResolver.Resolve(snapshot);}catch(AlreadyAppliedException){camera=true;}
  if(!hud)try{hudPlan=HudEngineResolver.Resolve(snapshot);}catch(HudAlreadyAppliedException){hud=true;}
  if(camera && hud)throw new CombinedAlreadyAppliedException();
  if((!camera && cameraPlan==null) || (!hud && hudPlan==null))return null;
  return new CombinedPlan {Camera=Component(session,"camera",cameraDirectory,camera,EngineResolver.Resolve),Hud=Component(session,"HUD",hudDirectory,hud,HudEngineResolver.Resolve)};
 }
 public static string Apply(RuntimeSession session,CombinedPlan plan){return ApplyPlan(plan);}
 public static string ApplyPlan(CombinedPlan plan) {
  if(plan==null || plan.Camera==null || plan.Hud==null)throw new ArgumentException("Both components must be preflighted");
  if(plan.Camera.Existing && plan.Hud.Existing)throw new CombinedAlreadyAppliedException();
  var added=new List<Tuple<RuntimeComponent,PatchReceipt>>();
  RuntimeComponent inFlight=null;
  try {
   foreach(var component in new[]{plan.Camera,plan.Hud})if(!component.Existing){inFlight=component;added.Add(Tuple.Create(component,component.Apply()));inFlight=null;}
   foreach(var addedComponent in added)addedComponent.Item1.Save(addedComponent.Item2);
   return "Camera controls and HUD are active and verified. The launcher does not change game files.";
  }catch(Exception failure) {
   var errors=new List<Exception>{failure};var leases=new List<IDisposable>();
   var initial=failure as PatchFailureException;if(initial!=null && initial.RetainedSuspension!=null)leases.Add(initial.RetainedSuspension);
   foreach(var entry in added.AsEnumerable().Reverse()) {
    try{entry.Item1.Rollback(entry.Item2);entry.Item1.Retire(entry.Item2);}
    catch(Exception ex){errors.Add(ex);var paused=ex as PatchFailureException;if(paused!=null && paused.RetainedSuspension!=null)leases.Add(paused.RetainedSuspension);}
   }
   bool camera=plan.Camera.Existing || added.Any(a=>a.Item1==plan.Camera && !a.Item2.RolledBack);
   bool hud=plan.Hud.Existing || added.Any(a=>a.Item1==plan.Hud && !a.Item2.RolledBack);
   bool cameraUnknown=initial!=null && inFlight==plan.Camera;
   bool hudUnknown=initial!=null && inFlight==plan.Hud;
   string state="Combined apply failed. Camera controls: "+(cameraUnknown?"unknown; recovery required":camera?"active":"not applied")+". HUD: "+(hudUnknown?"unknown; recovery required":hud?"active":"not applied")+". Existing components were preserved.";
   if(leases.Count>0)throw new PatchFailureException(state+" Recovery is incomplete; target threads remain paused.",new AggregateException(errors),new RecoveryLeases(leases));
   throw new CombinedFailureException(state,new AggregateException(errors),camera,hud);
  }
 }
 sealed class RecoveryLeases:IDisposable {
  readonly List<IDisposable> leases;public RecoveryLeases(List<IDisposable> list){leases=list;}
  public void Dispose(){var errors=new List<Exception>();foreach(var lease in leases.ToArray())try{lease.Dispose();leases.Remove(lease);}catch(Exception ex){errors.Add(ex);}if(errors.Count>0)throw new AggregateException(errors);}
 }
}
