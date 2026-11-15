// v1.84: retry only a confirmed exited automatically selected process, before any patch transaction.
using System;
using System.Diagnostics;
using System.ComponentModel;
static class RuntimeProcessWait {
 public static bool ConfirmExited(int pid) {
  try{using(var process=Process.GetProcessById(pid))return process.HasExited;}
  catch(ArgumentException){return true;} // GetProcessById reports that the PID no longer exists.
  catch(InvalidOperationException){return false;}
  catch(Win32Exception){return false;}
 }
 public static bool CanRediscover(int pid,bool explicitPid,bool transactionStarted,Func<int,bool> confirmedExited) {
  return pid>0 && !explicitPid && !transactionStarted && confirmedExited(pid);
 }
 public static bool MatchesOrExited(Func<bool> match,int pid,Func<int,bool> confirmedExited) {
  try{return match();}
  catch(ArgumentException){if(confirmedExited(pid))return false;throw;}
  catch(InvalidOperationException){if(confirmedExited(pid))return false;throw;}
  catch(Win32Exception){if(confirmedExited(pid))return false;throw;}
 }
}
