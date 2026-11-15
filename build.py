"""Portable Camera Control Fix 2.04 build. Tests never launch games."""
from pathlib import Path
import argparse, hashlib, json, os, subprocess, uuid
ROOT = Path(__file__).resolve().parent
VERSION = '2.04'
HOST = ['RuntimeTransport_v1.83.cs', 'RuntimeReceiptStore_v1.83.cs', 'RuntimeProcessWait_v1.84.cs', 'CombinedRuntime_v1.94.cs', 'EngineResolver_v1.83.cs', 'HudEngineResolver_v1.0.cs', 'HudLateRegistration_v2.04.cs', 'LaunchApplyHost_v2.04.cs']
INSTALLER = ['LauncherInstallCore_v2.04.cs', 'LauncherInstallWindow_v2.04.cs']
RESOURCES = {n: ROOT/'resources'/(n+e) for n,e in [('engine_spec','.json'), ('engine_payload','.bin'), ('hud_spec','.json'), ('hud_payload','.bin')]}
def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--csc',type=Path)
    parser.add_argument('--out',type=Path,default=ROOT/'build')
    parser.add_argument('--test',action='store_true')
    args=parser.parse_args()
    candidates=[Path(os.environ.get('WINDIR','C:/Windows'))/'Microsoft.NET'/f/'v4.0.30319/csc.exe' for f in ('Framework64','Framework')]
    compiler=args.csc or next((p for p in candidates if p.is_file()),candidates[0])
    if not compiler.is_file(): parser.error('Install the .NET Framework compiler or supply --csc')
    for name,expected in json.loads((ROOT/'resources/SHA256.json').read_text()).items():
        if digest(ROOT/name)!=expected: raise ValueError('Frozen resource differs: '+name)
    out=args.out.resolve();out.mkdir(parents=True,exist_ok=True)
    def compile(name,sources,platform='anycpu',resources=None,entry=None,gui=False):
        exe=out/name
        command=[str(compiler),'/nologo','/optimize+','/platform:'+platform,'/target:winexe' if gui else '/target:exe','/out:'+str(exe),'/r:System.Web.Extensions.dll','/r:System.Windows.Forms.dll','/r:System.Drawing.dll']
        if entry: command.append('/main:'+entry)
        command+=['/resource:'+str(p)+','+n for n,p in (resources or {}).items()]
        subprocess.run(command+[str(p) for p in sources],check=True)
        return exe
    sources=[ROOT/'src'/n for n in HOST]
    host=compile('Camera-Control-Fix-Host-v'+VERSION+'.exe',sources,'x86',RESOURCES,gui=True)
    meta=out/'host_meta.json';meta.write_text(json.dumps(dict(Version=VERSION,Name=host.name,Sha256=digest(host))),encoding='utf-8')
    installer=compile('Camera-Control-Fix-Installer-v'+VERSION+'.exe',[ROOT/'src'/n for n in INSTALLER],resources={'host':host,'host_meta':meta},gui=True)
    for exe in (host,installer): print(exe,'SHA256',digest(exe),flush=True)
    if not args.test: return
    for name,file in [('CombinedRuntimeChecks','CombinedRuntimeChecks_v1.94.cs'),('LaunchHostArgumentChecks','LaunchHostArgumentChecks_v2.04.cs')]:
        exe=compile(name+'.exe',sources+[ROOT/'tests'/file],'x86',RESOURCES,name)
        subprocess.run([str(exe)],check=True)
    check=compile('EmbeddedResourceChecks.exe',[ROOT/'tests/EmbeddedResourceChecks.cs'])
    subprocess.run([str(check),str(host),str(installer),str(ROOT/'resources')],check=True)
    fixtures=out/('fixtures-'+uuid.uuid4().hex[:8]);fixtures.mkdir()
    configs=[]
    for i,game in enumerate(('CM Shock Force 2.exe','CM Cold War.exe','CM Normandy.exe')):
        config=fixtures/('config'+str(i)+'.xml')
        config.write_text('<configuration><appSettings><add key="EXE" value="'+chr(92)+game+'"/><add key="Arguments" value=""/><add key="workingSubDirectory" value=""/></appSettings></configuration>',encoding='utf-8')
        configs.append(config)
    check=compile('LauncherInstallChecks.exe',[ROOT/'src/LauncherInstallCore_v2.04.cs',ROOT/'tests/LauncherInstallChecks_v2.04.cs'])
    subprocess.run([str(check),str(fixtures/'core')]+[str(p) for p in configs],check=True)
    drop=compile('LauncherDropChecks.exe',[ROOT/'tests/LauncherDropChecks_v2.04.cs'])
    for mode in ('icon','window'):
        requested,untouched=[fixtures/mode/n for n in ('requested','untouched')]
        for folder in (requested,untouched):
            folder.mkdir(parents=True);(folder/'CM Normandy.exe').write_bytes(b'MZfixture - not executable');(folder/'Launcher.exe.config').write_bytes(configs[2].read_bytes())
        subprocess.run([str(drop),str(installer),str(requested),str(untouched)]+(['window'] if mode=='window' else []),check=True,timeout=30)
        for op,expected in [('--install','already_installed'),('--restore','restored'),('--restore','not_installed')]:
            result=fixtures/'result.json'
            proc=subprocess.run([str(installer),op,str(requested),'--result',str(result)],capture_output=True,check=True,timeout=30)
            data=json.loads(proc.stdout.decode('utf-8-sig'))
            if data!=json.loads(result.read_text(encoding='utf-8-sig')) or data['Status']!=expected: raise ValueError(data)
        if (requested/'Launcher.exe.config').read_bytes()!=configs[2].read_bytes(): raise ValueError('Restore mismatch')
    print('PASS all checks; no games launched or installed game files modified.',flush=True)
if __name__=='__main__': main()
