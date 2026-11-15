using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.Web.Script.Serialization;
using CombatMissionControlFix;

public sealed class ReceiptPersistenceException:IOException {
 public PatchReceipt Receipt;
 public ReceiptPersistenceException(PatchReceipt receipt,Exception inner):base("Controls were applied, but the repeat-detection record could not be saved. Do not apply again; keep the result log.",inner){Receipt=receipt;}
}
public static class RuntimeReceiptStore {
 static string FileFor(RuntimeSession session,string directory){return Path.Combine(directory,session.ProcessId+"_"+session.ProcessStartTicks+".json");}
 public static string DefaultDirectory {get{return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"CombatMissionControlFix","receipts");}}
 static string Hash(byte[] data){using(var sha=SHA256.Create())return BitConverter.ToString(sha.ComputeHash(data)).Replace("-","").ToLowerInvariant();}
 public static bool Check(RuntimeSession session,ModuleSnapshot snapshot,string directory) {
  string file=FileFor(session,directory);if(!File.Exists(file))return false;
  if(new FileInfo(file).Length>2097152)throw new IOException("Runtime receipt is too large; target unchanged.");
  PatchReceipt receipt;
  try{receipt=new JavaScriptSerializer().Deserialize<PatchReceipt>(File.ReadAllText(file));}
  catch(Exception ex){throw new IOException("Runtime receipt is invalid; target unchanged.",ex);}
  Verify(session,snapshot,receipt);return true;
 }
 public static void Verify(RuntimeSession session,ModuleSnapshot snapshot,PatchReceipt receipt) {
  if(receipt==null || receipt.RolledBack || receipt.ProcessId!=session.ProcessId || receipt.ProcessStartTicks!=session.ProcessStartTicks || receipt.ModuleBase!=snapshot.BaseAddress || String.IsNullOrEmpty(receipt.ModulePath) || !String.Equals(Path.GetFullPath(receipt.ModulePath),Path.GetFullPath(snapshot.ModulePath),StringComparison.OrdinalIgnoreCase))throw new IOException("Runtime receipt identity mismatch; target unchanged.");
  if(receipt.PayloadAddress==0 || receipt.PayloadSize<1 || receipt.PayloadSize>16777216 || receipt.PayloadCodeLength<1 || receipt.PayloadCodeLength>receipt.PayloadSize || receipt.PayloadAddress+(ulong)receipt.PayloadSize>0x100000000UL || receipt.Patches==null || receipt.Patches.Count<1 || receipt.Patches.Count>512 || receipt.PayloadCodeSha256==null || receipt.PayloadCodeSha256.Length!=64)throw new IOException("Runtime receipt bounds are invalid; target unchanged.");
  foreach(var patch in receipt.Patches) {
   if(patch==null || patch.Original==null || patch.Replacement==null || patch.Replacement.Length<1 || patch.Replacement.Length>65536 || patch.Original.Length!=patch.Replacement.Length || patch.Address<snapshot.BaseAddress || patch.Address+(ulong)patch.Replacement.Length>snapshot.BaseAddress+(ulong)snapshot.Image.Length)throw new IOException("Runtime receipt hook bounds are invalid; target unchanged.");
   if(!session.ReadRemote(patch.Address,patch.Replacement.Length).SequenceEqual(patch.Replacement))throw new IOException("Runtime hook no longer matches its receipt; target unchanged.");
  }
  using(var sha=SHA256.Create()) {
   int offset=0;
   while(offset<receipt.PayloadCodeLength) {int count=Math.Min(1048576,receipt.PayloadCodeLength-offset);byte[] bytes=session.ReadRemote(receipt.PayloadAddress+(uint)offset,count);sha.TransformBlock(bytes,0,bytes.Length,bytes,0);offset+=count;}
   sha.TransformFinalBlock(new byte[0],0,0);string hash=BitConverter.ToString(sha.Hash).Replace("-","").ToLowerInvariant();
   if(hash!=receipt.PayloadCodeSha256)throw new IOException("Runtime payload no longer matches its receipt; target unchanged.");
  }
 }
 // Also supports importing a coordinator-verified live receipt: all remote evidence is checked before persistence.
 public static void SaveVerified(RuntimeSession session,ModuleSnapshot snapshot,PatchReceipt receipt,string directory) {
  Verify(session,snapshot,receipt);Directory.CreateDirectory(directory);
  string file=FileFor(session,directory),json=new JavaScriptSerializer().Serialize(receipt);
  if(File.Exists(file)){if(Check(session,snapshot,directory))return;throw new IOException("Existing runtime receipt conflicts");}
  string temp=file+"."+Guid.NewGuid().ToString("N")+".tmp";
  try{byte[] bytes=Encoding.UTF8.GetBytes(json);using(var f=new FileStream(temp,FileMode.CreateNew,FileAccess.Write,FileShare.None)){f.Write(bytes,0,bytes.Length);f.Flush(true);}File.Move(temp,file);if(!Check(session,snapshot,directory))throw new IOException("Runtime receipt readback failed");}
  finally{if(File.Exists(temp))File.Delete(temp);}
 }
}
