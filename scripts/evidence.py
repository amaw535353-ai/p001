#!/usr/bin/env python3
import datetime,hashlib,json,os,subprocess
from pathlib import Path
r=Path(__file__).resolve().parents[1];os.chdir(r)
def cmd(a):
    p=subprocess.run(a,capture_output=True,text=True);return p.stdout.strip() if p.returncode==0 else 'unavailable (exit '+str(p.returncode)+')'
now=datetime.datetime.now(datetime.timezone.utc)
results=json.loads((r/'.runtime/results.json').read_text()) if (r/'.runtime/results.json').exists() else []
for extra in ['container-results.json','setup-results.json']:
    if (r/'.runtime'/extra).exists():results += json.loads((r/'.runtime'/extra).read_text())
hashes={str(f.relative_to(r)):hashlib.sha256(f.read_bytes()).hexdigest() for base in ['infra','services','scripts','tests'] for f in (r/base).rglob('*') if f.is_file() and not any(x in f.parts for x in ['.terraform','__pycache__']) and f.suffix not in ['.tfstate','.backup','.tfplan']}
e={'schema_version':1,'utc':now.isoformat(),'commit':cmd(['git','rev-parse','--verify','HEAD']), 'dirty':bool(cmd(['git','status','--porcelain'])), 'verifier':'Codex','classification':'synthetic-only; not a client assessment','versions':{x:cmd(a) for x,a in {'python':['python3','--version'],'docker':['docker','version','--format','{{.Server.Version}}'],'kind':['kind','version'],'tofu':['tofu','version'],'kubectl':['kubectl','version','--client=true','-o','json'],'workload_image':['docker','image','inspect','p001-workload:local','--format','{{.Id}}'],'localstack_image':['docker','image','inspect','localstack/localstack:4.14.0','--format','{{json .RepoDigests}}']}.items()},'config_hashes':hashes,'results':results}
p=r/'evidence'/now.strftime('%Y%m%dT%H%M%SZ');p.mkdir(parents=True,exist_ok=True)
(p/'manifest.json').write_text(json.dumps(e,indent=2)+'\n')
(p/'transcript.txt').write_text('\n'.join(f"{x['utc']} {x['command']} => {x['status']}: {x['observed']}" for x in results)+'\n')
print(p.relative_to(r)/'manifest.json')
