#!/usr/bin/env python3
"""Docker-only fallback: NOT a Kubernetes/CNI/RBAC validation."""
import datetime,json,subprocess,time,os,sys
from pathlib import Path
from urllib.request import Request,urlopen
from urllib.error import HTTPError
R=Path(__file__).resolve().parents[2];os.chdir(R);created=[];nets=[];rows=[]
def d(*a):return subprocess.check_output(['docker',*a],text=True).strip()
def test(id,command,expected,fn):
 r=dict(id=id,command=command,expected=expected,utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),verifier='Codex',scope='Docker fallback')
 try:r.update(status='PASS',observed=str(fn()))
 except Exception as e:r.update(status='FAIL',observed=str(e)[:500])
 rows.append(r);print(json.dumps(r),flush=True)
def start(n,net,*args):
 d('run','-d','--name',n,'--label','owner=p001-smoke-v1','--network',net,*args);created.append(n)
def wait(name,path):
 for _ in range(60):
  if d('inspect','--format','{{.State.Running}}',name)!='true':raise RuntimeError(name+' exited; inspect container startup logs')
  try:
   result=d('exec',name,'python','-c',"import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:"+('4566' if name.endswith('s3') else '8080')+"'+"+repr(path)+",timeout=2).status)")
   if result=='200':return
  except Exception:time.sleep(1)
 raise RuntimeError('readiness timeout')
def req(p,path,method='GET',body=None,t='tenant-a',status=200):
 name='p001-smoke-api-'+str(p-8081)
 code="""import json
from urllib.request import Request,urlopen
from urllib.error import HTTPError
q=Request('http://127.0.0.1:8080'+PATH,DATA,{'Authorization':'Bearer p001-fixture-'+TENANT,'Content-Type':'application/json','X-Correlation-ID':'p001-smoke'},method=METHOD)
try:r=urlopen(q,timeout=8)
except HTTPError as e:r=e
print(json.dumps({'status':r.status,'correlation':r.headers.get('X-Correlation-ID'),'body':json.load(r)}))
"""
 prefix='PATH='+repr(path)+';DATA='+repr(json.dumps(body).encode() if body is not None else None)+';TENANT='+repr(t)+';METHOD='+repr(method)+'\n'
 r=json.loads(d('exec',name,'python','-c',prefix+code))
 assert r['status']==status,f"expected {status}, got {r['status']}"
 assert r['correlation']=='p001-smoke';return r['body']

try:
 for n in ['p001-smoke-a','p001-smoke-b']:
  d('network','create','--internal','--label','owner=p001-smoke-v1',n);nets.append(n)
 image=json.load(open('infra/images.lock.json'))['localstack']
 start('p001-smoke-s3',nets[0],'--network-alias','localstack.emulator.svc.cluster.local','-e','SERVICES=s3','-e','DEBUG=0','-e','DNS_ADDRESS=0','-e','DISABLE_EVENTS=1','-e','SKIP_SSL_CERT_DOWNLOAD=1',image)
 d('network','connect','--alias','localstack.emulator.svc.cluster.local',nets[1],'p001-smoke-s3');wait('p001-smoke-s3','/_localstack/health')
 code="import boto3;from botocore.config import Config;s=boto3.client('s3',endpoint_url='http://localstack.emulator.svc.cluster.local:4566',aws_access_key_id='test',aws_secret_access_key='test',region_name='us-east-1',config=Config(proxies={}));[s.create_bucket(Bucket='p001-'+t) for t in ['tenant-a','tenant-b']];print('two fixture buckets')"
 test('DOCKER-S3-SETUP','docker run --rm SDK create buckets','two emulator buckets',lambda:d('run','--rm','--name','p001-smoke-seed','--label','owner=p001-smoke-v1','--memory','192m','--cpus','0.5','--network',nets[0],'p001-workload:local','python','-c',code))
 for i,t in enumerate(['tenant-a','tenant-b']):
  opts=['--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','192m','--cpus','0.5']
  start('p001-smoke-mock-'+str(i),nets[i],*opts,'--network-alias','mock','-e','P001_MODE=mock','p001-workload:local')
  p=8081+i
  start('p001-smoke-api-'+str(i),nets[i],*opts,'-e','P001_TENANT='+t,'-e','P001_S3_ENDPOINT=http://localstack.emulator.svc.cluster.local:4566','p001-workload:local');wait('p001-smoke-api-'+str(i),'/readyz')
  def inference():
   a=req(p,'/infer','POST',{'prompt':'synthetic'},t);b=req(p,'/infer','POST',{'prompt':'synthetic'},t);assert a==b and a['simulator'];return a
  test('DOCKER-INFERENCE-'+t,f'docker exec API-{i} POST localhost:8080/infer twice','deterministic simulator',inference)
  def objects():
   req(p,'/objects/fixture-smoke','PUT',{'marker':'P001-SYNTHETIC-ONLY'},t,201);a=req(p,'/objects/fixture-smoke',t=t);assert a['tenant']==t and a['object']=={'marker':'P001-SYNTHETIC-ONLY'};return 'marker round trip matched'
  test('DOCKER-OBJECTS-'+t,f'docker exec API-{i} PUT/GET localhost:8080/objects/fixture-smoke','S3 marker round trip',objects)
  test('DOCKER-DENY-'+t,f'docker exec API-{i} POST localhost:8080/infer wrong tenant','403',lambda:req(p,'/infer','POST',{},'tenant-b' if t=='tenant-a' else 'tenant-a',403))
  test('DOCKER-INPUT-'+t,f'docker exec API-{i} PUT localhost:8080/objects/fixture-smoke invalid marker','400',lambda:req(p,'/objects/fixture-smoke','PUT',{'marker':'other'},t,400))
 def logs():
  for n in [n for n in created if 'api-' in n or 'mock-' in n]:
   data=[json.loads(x) for x in d('logs',n).splitlines()];assert data and all(set(x)=={'event','status','tenant','service','correlation_id'} for x in data)
  return 'allowlisted log fields verified; raw values not retained'
 test('DOCKER-LOGS','docker logs owned services (inspect only)','allowlisted fields',logs)
 def exposure():
  for n in created:
   c=json.loads(d('inspect',n))[0]
   for b in c['NetworkSettings']['Ports'].values():
    for x in b or []:assert x['HostIp']=='127.0.0.1'
  return 'no public host bindings; internal networks only'
 test('DOCKER-EXPOSURE','docker inspect owned containers','no public host ports',exposure)
except Exception as e:
 test('DOCKER-BOOTSTRAP','container smoke bootstrap','healthy services',lambda:(_ for _ in ()).throw(e))
finally:
 for n in reversed(created):
  if d('inspect','--format','{{index .Config.Labels "owner"}}',n)=='p001-smoke-v1':d('rm','-f',n)
 for n in reversed(nets):
  if d('network','inspect','--format','{{index .Labels "owner"}}',n)=='p001-smoke-v1':d('network','rm',n)
 (R/'.runtime/container-results.json').write_text(json.dumps(rows,indent=2)+'\n')
sys.exit(any(r['status']!='PASS' for r in rows))
