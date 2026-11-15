using System;
using System.IO;
using System.Collections.Generic;
using CombatMissionControlFix;
static class CombinedRuntimeChecks {
 static List<string> events=new List<string>();
 sealed class Lease:IDisposable {public bool Released;public void Dispose(){Released=true;}}
 static void Assert(bool value,string message){if(!value)throw new Exception(message+": "+String.Join(",",events));}
 static RuntimeComponent Part(string name,bool existing,bool failApply=false,bool failSave=false) {
  return new RuntimeComponent{Name=name,Existing=existing,
   Apply=()=>{events.Add(name+" apply");if(failApply)throw new IOException("forced apply failure");return new PatchReceipt();},
   Save=r=>{events.Add(name+" save");if(failSave)throw new IOException("forced save failure");},
   Rollback=r=>{events.Add(name+" rollback");r.RolledBack=true;},Retire=r=>events.Add(name+" retire")};
 }
 static int Main() {
  CombinedRuntime.ApplyPlan(new CombinedPlan{Camera=Part("camera",false),Hud=Part("hud",false)});
  Assert(String.Join(",",events)=="camera apply,hud apply,camera save,hud save","Wrong successful order");events.Clear();
  CombinedRuntime.ApplyPlan(new CombinedPlan{Camera=Part("camera",true),Hud=Part("hud",false)});
  Assert(String.Join(",",events)=="hud apply,hud save","Existing camera touched");events.Clear();
  try{CombinedRuntime.ApplyPlan(new CombinedPlan{Camera=Part("camera",false),Hud=Part("hud",false,true)});throw new Exception("Expected failure");}
  catch(CombinedFailureException ex){Assert(!ex.CameraActive && !ex.HudActive,"new camera not rolled back");}
  Assert(String.Join(",",events)=="camera apply,hud apply,camera rollback,camera retire","HUD failure recovery order");events.Clear();
  try{CombinedRuntime.ApplyPlan(new CombinedPlan{Camera=Part("camera",true),Hud=Part("hud",false,true)});throw new Exception("Expected failure");}
  catch(CombinedFailureException ex){Assert(ex.CameraActive && !ex.HudActive,"Existing camera state lost");}
  Assert(String.Join(",",events)=="hud apply","Existing camera rolled back");events.Clear();
  try{CombinedRuntime.ApplyPlan(new CombinedPlan{Camera=Part("camera",false),Hud=Part("hud",false,false,true)});throw new Exception("Expected failure");}
  catch(CombinedFailureException ex){Assert(!ex.CameraActive && !ex.HudActive,"Save failure did not roll back both");}
  Assert(String.Join(",",events)=="camera apply,hud apply,camera save,hud save,hud rollback,hud retire,camera rollback,camera retire","Save failure recovery order");events.Clear();
  bool already=false;try{CombinedRuntime.ApplyPlan(new CombinedPlan{Camera=Part("camera",true),Hud=Part("hud",true)});}catch(CombinedAlreadyAppliedException){already=true;}
  Assert(already && events.Count==0,"Already-active path mutated state");
  foreach(bool hudFailure in new[]{false,true}) {
   events.Clear();var lease=new Lease();var camera=Part("camera",false);var hud=Part("hud",false);
   (hudFailure?hud:camera).Apply=()=>{throw new PatchFailureException("forced partial write",new IOException(),lease);};
   bool retained=false;try{CombinedRuntime.ApplyPlan(new CombinedPlan{Camera=camera,Hud=hud});}
   catch(PatchFailureException ex){retained=ex.RetainedSuspension!=null;Assert(ex.Message.Contains(hudFailure?"HUD: unknown; recovery required":"Camera controls: unknown; recovery required"),"In-flight recovery state mislabeled");Assert(!lease.Released,"Suspension released automatically");ex.RetainedSuspension.Dispose();}
   Assert(retained && lease.Released,"Recovery lease lost");
   if(hudFailure)Assert(events.Contains("camera rollback"),"New camera was not rolled back after HUD failure");
  }
  Console.WriteLine("PASS: combined success, existing-camera HUD-only, HUD failure new-camera rollback, existing-camera preservation, receipt failure reverse rollback, both-active no-op. Pure component checks; no game access.");return 0;
 }
}
