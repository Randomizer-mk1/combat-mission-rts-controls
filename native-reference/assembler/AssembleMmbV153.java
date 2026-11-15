import java.nio.file.*;
import java.io.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.plugin.assembler.*;
public class AssembleMmbV153 extends GhidraScript {

 static byte[] stackBytes(String instruction) throws IOException {
  String[] p=instruction.trim().toUpperCase(java.util.Locale.ROOT).split("\\s+",2);
  String op=p[0];
  if(op.equals("PUSHFD"))return new byte[]{(byte)0x9c};
  if(op.equals("POPFD"))return new byte[]{(byte)0x9d};
  if(op.equals("PUSHAD"))return new byte[]{(byte)0x60};
  if(op.equals("POPAD"))return new byte[]{(byte)0x61};
  if(!op.equals("PUSH")&&!op.equals("POP"))return null;
  if(p.length!=2)throw new IOException("Missing stack operand");
  String operand=p[1];
  String[] regs={"EAX","ECX","EDX","EBX","ESP","EBP","ESI","EDI"};
  for(int i=0;i<8;i++)if(operand.equals(regs[i]))return new byte[]{(byte)((op.equals("PUSH")?0x50:0x58)+i)};
  if(op.equals("PUSH") && operand.matches("[-+]?(0X[0-9A-F]+|[0-9]+)")) {
   long value=Long.decode(operand);
   if(value< -2147483648L || value>0xffffffffL)throw new IOException("Immediate outside x86 range");
   int v=(int)value;
   if(v>=-128&&v<=127)return new byte[]{(byte)0x6a,(byte)v};
   return new byte[]{(byte)0x68,(byte)v,(byte)(v>>>8),(byte)(v>>>16),(byte)(v>>>24)};
  }
  if(!operand.startsWith("DWORD PTR ["))throw new IOException("Only 32-bit stack operands allowed: "+instruction);
  return null;
 }
 static void checkStack(String instruction,byte[] bytes) throws IOException {
  String op=instruction.trim().split("\\s+",2)[0].toUpperCase(java.util.Locale.ROOT);
  if(op.startsWith("PUSH")||op.startsWith("POP")||op.equals("RET")||op.equals("ENTER")||op.equals("LEAVE")) {
   for(byte raw:bytes) {
    int b=raw&255;
    if(b==0x66)throw new IOException("16-bit stack instruction rejected: "+instruction);
    if(b!=0x67&&b!=0x26&&b!=0x2e&&b!=0x36&&b!=0x3e&&b!=0x64&&b!=0x65&&b!=0xf0&&b!=0xf2&&b!=0xf3)break;
   }
  }
 }
 public void run() throws Exception {
  String[] a=getScriptArgs(); Assembler asm=Assemblers.getAssembler(currentProgram);
  ByteArrayOutputStream out=new ByteArrayOutputStream(); long first=-1;
  for(String line:Files.readAllLines(Path.of(a[0]))) {
   String[] s=line.split("\\t",2); long va=Long.parseLong(s[0],16); if(first<0)first=va; if(out.size()>va-first)throw new IOException("overlap"); while(out.size()<va-first)out.write(0x90);
   byte[] b;
   String[] op=s[1].split(" ",2);
   b=stackBytes(s[1]);
   if(b!=null) {} else if(op[0].equals("HEX")) { b=java.util.HexFormat.of().parseHex(op[1]); } else if(op.length==2 && op[1].startsWith("0x") && (op[0].equals("CALL")||op[0].equals("JMP")||op[0].startsWith("J"))) {
    int cc=switch(op[0]) {case "JNS"->9;case "JC"->2;case "JNC"->3;case "JNP"->11;case "JP"->10;case "JB"->2;case "JBE"->6;case "JA"->7;case "JLE"->14;case "JNE"->5;case "JZ"->4;case "JNZ"->5;case "JS"->8;case "JGE"->13;case "JG"->15;case "JL"->12;default->-1;};
    boolean direct=op[0].equals("CALL")||op[0].equals("JMP");
    if(!direct && cc<0)throw new IOException("Unknown branch "+s[1]);
    b=new byte[direct?5:6]; b[0]=(byte)(direct?(op[0].equals("CALL")?0xe8:0xe9):0x0f);if(!direct)b[1]=(byte)(0x80+cc);
    int d=(int)(Long.parseLong(op[1].substring(2),16)-va-b.length);
    for(int j=0;j<4;j++)b[b.length-4+j]=(byte)(d>>>(j*8));
   } else b=asm.assembleLine(toAddr(va),s[1].replace("+0x0]", "]").replace("+", " + "),asm.getContextAt(toAddr(0x6f9d80)).fillMask());
   checkStack(s[1],b);
   if(b.length>16)throw new IOException("instruction too long");
   out.write(b); for(int i=b.length;i<16;i++)out.write(0x90);
  }
  Files.write(Path.of(a[1]),out.toByteArray()); println("ASSEMBLED bytes="+out.size());
 }
}
