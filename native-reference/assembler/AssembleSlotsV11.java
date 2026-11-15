// Output-only x86 slot assembler v1.1. Does not mutate the analysis program.
// Arguments: input.asm output.bin allowed_start_hex allowed_end_hex (exclusive).
// Rows: hexadecimal VA, TAB, instruction. Required final row: end VA, TAB, END.
import java.nio.file.*;
import java.io.*;
import java.util.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.plugin.assembler.*;
public class AssembleSlotsV11 extends GhidraScript {
 static class Row { long va; String text; int line; Row(long a,String s,int n){va=a;text=s;line=n;} }
 static long address(String s) throws IOException {
  s=s.trim(); if(s.startsWith("0x")||s.startsWith("0X"))s=s.substring(2);
  if(!s.matches("[0-9a-fA-F]{1,8}"))throw new IOException("Invalid x86 address: "+s);
  return Long.parseLong(s,16);
 }

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
 static String syntax(String text) {
  java.util.regex.Matcher m=java.util.regex.Pattern.compile("\\[([^\\]]+)\\]").matcher(text);
  StringBuffer result=new StringBuffer();
  while(m.find()) {
   String memory=m.group(1).replaceAll("\\s*-\\s*(0[xX][0-9a-fA-F]+|[0-9]+)"," + -$1");
   m.appendReplacement(result,java.util.regex.Matcher.quoteReplacement("["+memory+"]"));
  }
  m.appendTail(result);
  return result.toString().replace("+0x0]","]").replace("+"," + ");
 }
 public void run() throws Exception {
  String[] args=getScriptArgs();
  if(args.length!=4)throw new IOException("Expected input output allowed_start_hex allowed_end_hex");
  Path input=Path.of(args[0]),output=Path.of(args[1]);
  if(Files.exists(output))throw new IOException("Refusing to overwrite output: "+output);
  long lower=address(args[2]),upper=address(args[3]);
  if(upper<=lower || upper-lower>0x1000000)throw new IOException("Invalid or excessive allowed range");
  ArrayList<Row> rows=new ArrayList<>(); int number=0;
  for(String raw:Files.readAllLines(input)) {
   number++; String line=raw.trim(); if(line.isEmpty()||line.startsWith("#")||line.startsWith(";"))continue;
   String[] pair=line.split("\\t",2);
   if(pair.length!=2 || pair[1].trim().isEmpty())throw new IOException("Expected VA TAB instruction at line "+number);
   Row row=new Row(address(pair[0]),pair[1].trim(),number);
   if(!rows.isEmpty() && (row.va<=rows.get(rows.size()-1).va || rows.get(rows.size()-1).text.equals("END")))throw new IOException("Non-increasing address or content after END at line "+number);
   rows.add(row);
  }
  if(rows.size()<2 || !rows.get(rows.size()-1).text.equals("END"))throw new IOException("Missing terminal VA TAB END row");
  long first=rows.get(0).va,end=rows.get(rows.size()-1).va;
  if(first<lower || end>upper)throw new IOException("Assembly exceeds allowed address range");
  Assembler asm=Assemblers.getAssembler(currentProgram);
  ByteArrayOutputStream out=new ByteArrayOutputStream((int)(end-first));
  for(int i=0;i<rows.size()-1;i++) {
   monitor.checkCancelled(); Row row=rows.get(i); long next=rows.get(i+1).va;
   String[] op=row.text.split("\\s+",2); String mnemonic=op[0].toUpperCase(Locale.ROOT); byte[] bytes;
   bytes=stackBytes(row.text);
   if(bytes!=null) {} else if(mnemonic.equals("HEX") && op.length==2)bytes=HexFormat.of().parseHex(op[1]);
   else if(op.length==2 && op[1].matches("(?i)0x[0-9a-f]{1,8}") && (mnemonic.equals("CALL")||mnemonic.equals("JMP")||mnemonic.startsWith("J"))) {
    boolean direct=mnemonic.equals("CALL")||mnemonic.equals("JMP");
    int cc=switch(mnemonic) {
     case "JO"->0;case "JNO"->1;case "JB","JC","JNAE"->2;case "JAE","JNB","JNC"->3;
     case "JE","JZ"->4;case "JNE","JNZ"->5;case "JBE","JNA"->6;case "JA","JNBE"->7;
     case "JS"->8;case "JNS"->9;case "JP","JPE"->10;case "JNP","JPO"->11;
     case "JL","JNGE"->12;case "JGE","JNL"->13;case "JLE","JNG"->14;case "JG","JNLE"->15;default->-1;
    };
    if(!direct && cc<0)throw new IOException("Unsupported direct branch at line "+row.line+": "+row.text);
    bytes=new byte[direct?5:6];bytes[0]=(byte)(direct?(mnemonic.equals("CALL")?0xe8:0xe9):0x0f);
    if(!direct)bytes[1]=(byte)(0x80+cc);
    int delta=(int)(address(op[1])-row.va-bytes.length);
    for(int j=0;j<4;j++)bytes[bytes.length-4+j]=(byte)(delta>>>(8*j));
   } else {
    if(op.length==2 && (mnemonic.equals("CALL")||mnemonic.startsWith("J")) && op[1].matches("[0-9].*"))throw new IOException("Direct branch targets require 0x notation at line "+row.line);
    bytes=asm.assembleLine(toAddr(row.va),syntax(row.text),asm.getContextAt(toAddr(0x6f9d80)).fillMask());
   }
   checkStack(row.text,bytes);
   if(bytes.length==0 || bytes.length>next-row.va)throw new IOException("Slot overflow at line "+row.line+": "+bytes.length+" bytes into "+(next-row.va)+" bytes");
   out.write(bytes);while(out.size()<next-first)out.write(0x90);
  }
  monitor.checkCancelled();byte[] result=out.toByteArray();
  if(result.length!=end-first)throw new IOException("Output length mismatch");
  Files.write(output,result,StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE);
  println("ASSEMBLED start="+Long.toHexString(first)+" end="+Long.toHexString(end)+" bytes="+result.length+" instructions="+(rows.size()-1));
 }
}
