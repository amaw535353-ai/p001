#!/usr/bin/env python3
import json,os,platform,shutil,socket,subprocess,sys
from pathlib import Path
fail=[]
print('P-001 local-only doctor; no AWS API calls')
for name,args in [('python3',['--version']),('docker',['version','--format','{{.Server.Version}}']),('kind',['version']),('kubectl',['version','--client=true','-o','json']),('tofu',['version'])]:
    if not shutil.which(name):fail.append(name+' missing');continue
    r=subprocess.run([name]+args,capture_output=True,text=True);print(name,r.stdout.strip()[:350]);
    if r.returncode:fail.append(name+' unusable: '+r.stderr[:200])
for name in ['AWS_PROFILE','AWS_WEB_IDENTITY_TOKEN_FILE','AWS_CONTAINER_CREDENTIALS_RELATIVE_URI']:
    if os.environ.get(name):fail.append(name+' is set; launch from a clean shell without real-cloud bindings')
for name in ['AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY','AWS_SESSION_TOKEN']:
    if os.environ.get(name) and os.environ[name]!='test':fail.append(name+' has a non-fixture value; unset it (value not displayed)')
info=subprocess.run(['docker','info','--format','{{json .}}'],capture_output=True,text=True)
if info.returncode==0:
    di=json.loads(info.stdout)
    print('Docker resource report: CPUs',di.get('NCPU'),'memory_GiB',di.get('MemTotal',0)//2**30,'cgroup_driver',di.get('CgroupDriver'))
    if di.get('NCPU',0)<4 or di.get('MemTotal',0)<8*2**30:fail.append('Docker needs estimated 4 CPUs and 8 GiB RAM')
    if any('rootless' in x for x in di.get('SecurityOptions',[])) and di.get('CgroupDriver')=='none':fail.append('BLOCKED: rootless Docker lacks delegated cgroup driver; kind bootstrap is unsupported on this host')
if shutil.disk_usage('.').free<20*2**30:fail.append('less than estimated 20 GiB free disk')
print('host',platform.system(),platform.machine(),'free_disk_GiB',shutil.disk_usage('.').free//2**30)
print('ports: 4566 emulator, 8081 tenant-a, 8082 tenant-b; startup checks exclusivity')
print('Rootless Docker/CNI compatibility requires actual bootstrap; available RAM is host-reported.')
print(json.dumps({'status':'FAIL' if fail else 'PASS','issues':fail}))
sys.exit(bool(fail))
