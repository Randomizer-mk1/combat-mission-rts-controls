using System;
using System.Runtime.InteropServices;
static class LaunchHostArgumentChecks {
 [DllImport("shell32.dll",CharSet=CharSet.Unicode)]static extern IntPtr CommandLineToArgvW(string command,out int count);
 [DllImport("kernel32.dll")]static extern IntPtr LocalFree(IntPtr ptr);
 static int Main(){
  string[] cases={"","plain","with spaces","한글 인수","a\"b",@"C:\path with spaces\",@"\\server\folder\","x\\\\\"y"};
  foreach(string value in cases){int count;IntPtr argv=CommandLineToArgvW("dummy.exe "+LaunchApplyHost.Quote(value),out count);
   try{if(count!=2 || Marshal.PtrToStringUni(Marshal.ReadIntPtr(argv,IntPtr.Size))!=value)throw new Exception("Windows argv roundtrip failed");}finally{LocalFree(argv);}}
  Console.WriteLine("Windows argument roundtrip: "+cases.Length+" / "+cases.Length+" passed");return 0;
 }
}
