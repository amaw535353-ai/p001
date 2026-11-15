#!/usr/bin/env python3
import datetime,json,os,subprocess,sys,time
from pathlib import Path
from urllib.request import Request,urlopen
from urllib.error import HTTPError
R=Path(__file__).resolve().parents[1];os.chdir(R)
results=[]
def check(id,command,expected,fn):
    start=datetime.datetime.now(datetime.timezone.utc).isoformat()
    try:observed=fn();status='PASS'
    except Exception as e:observed=str(e)[:1000];status='FAIL'
    row=dict(id=id,command=command,expected=expected,observed=str(observed),status=status,utc=start,verifier='Codex automated baseline')
    results.append(row);print(json.dumps(row),flush=True)
def run(args,ok=0):
    p=subprocess.run(args,text=True,capture_output=True,timeout=180)
    assert p.returncode==ok,f'exit={p.returncode} {p.stderr[-500:]} {p.stdout[-500:]}'
    return (p.stdout + ('\n'+p.stderr if args[0]=='python3' else '')).strip()
def k(*args):return ['kubectl','--context','kind-p001',*args]
def req(port,path,method='GET',body=None,token=None,status=200):
    h={'X-Correlation-ID':'p001-baseline-'+str(port)}
    if token:h['Authorization']='Bearer p001-fixture-'+token
    if body is not None:h['Content-Type']='application/json'
    r=Request(f'http://127.0.0.1:{port}'+path, None if body is None else json.dumps(body).encode(),h,method=method)
    try:response=urlopen(r,timeout=5)
    except HTTPError as e:response=e
    assert response.status==status,f'expected {status}, got {response.status}'
    assert response.headers.get('X-Correlation-ID')==h['X-Correlation-ID']
    return json.load(response)
check('UNIT','python3 -m unittest discover -s tests/unit -v','all unit tests execute',lambda:run(['python3','-m','unittest','discover','-s','tests/unit','-v']))
check('STATIC','python3 scripts/static-check','structural security and narrow secret rules',lambda:run(['python3','scripts/static-check']))
ready=subprocess.run(k('get','nodes'),capture_output=True,text=True).returncode==0
if not ready:
    for id in ['IAC','HEALTH','INFERENCE','OBJECTS','TENANT-DENY','RBAC','NETWORK','RUNTIME-HARDENING','LOGS','DRIFT','REBUILD']:
        results.append(dict(id=id,status='BLOCKED',command='make lab-up && make lab-test',expected='live dedicated cluster',observed='kind-p001 unavailable; see bootstrap evidence',utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),verifier='Codex'))
else:
    check('IAC','tofu init/validate/plan -detailed-exitcode','valid config, zero drift',lambda:(run(['tofu','-chdir=infra/opentofu/local','validate']),run(['tofu','-chdir=infra/opentofu/local','plan','-input=false','-detailed-exitcode'])))
    for port,t in [(8081,'tenant-a'),(8082,'tenant-b')]:
        check('HEALTH-'+t,f'GET :{port}/readyz','200',lambda p=port:req(p,'/readyz'))
        def inference(p=port,t=t):
            a=req(p,'/infer','POST',{'prompt':'P001 synthetic'},t);b=req(p,'/infer','POST',{'prompt':'P001 synthetic'},t)
            assert a==b and a['simulator'] is True;return a
        check('INFERENCE-'+t,f'POST :{port}/infer twice','deterministic simulator response',inference)
        def objects(p=port,t=t):
            req(p,'/objects/fixture-baseline','PUT',{'marker':'P001-SYNTHETIC-ONLY'},t,status=201)
            a=req(p,'/objects/fixture-baseline',token=t);assert a['tenant']==t and a['object']=={'marker':'P001-SYNTHETIC-ONLY'};return 'write/read marker matched'
        check('OBJECTS-'+t,f'PUT/GET :{port}/objects/fixture-baseline','tenant-bound S3 round trip',objects)
        check('TENANT-DENY-'+t,f'POST :{port}/infer with wrong tenant and no token','403 both fixtures',lambda p=port,t=t:(req(p,'/infer','POST',{},'tenant-b' if t=='tenant-a' else 'tenant-a',403),req(p,'/infer','POST',{},None,403)))
        def rbac(t=t):
            sa=f'system:serviceaccount:{t}:lab-api'
            assert run(k('auth','can-i','get','configmap/public-fixtures','-n',t,'--as',sa))=='yes'
            assert run(k('auth','can-i','list','secrets','-n',t,'--as',sa),1)=='no'
            assert run(k('auth','can-i','create','pods','-n',t,'--as',sa),1)=='no'
            return 'named configmap allowed; secrets and pod creation denied by API authorization (admin impersonation)'
        check('RBAC-'+t,'kubectl auth can-i --as tenant service account','allow named configmap; deny secrets and pods',rbac)
    def network():
        def connect(source,target,port,allowed):
            # Numeric Pod IP avoids confusing DNS errors with enforcement.
            ip=run(k('-n',target,'get','pod','-l','app=mock','-o','jsonpath={.items[0].status.podIP}'))
            code='import socket; s=socket.create_connection(("'+ip+'",'+str(port)+'),timeout=3); s.close()'
            p=subprocess.run(k('-n',source,'exec','deploy/api','--','python','-c',code),capture_output=True,text=True,timeout=15)
            if allowed:assert p.returncode==0,p.stderr
            else:assert p.returncode!=0 and 'TimeoutError' in p.stderr,p.stderr
        connect('tenant-a','tenant-a',8080,True);connect('tenant-a','tenant-b',8080,False)
        connect('tenant-b','tenant-b',8080,True);connect('tenant-b','tenant-a',8080,False)
        # A local controlled sink in emulator namespace is forbidden to mock, allowed to API.
        ip=run(k('-n','emulator','get','pod','-l','app=localstack','-o','jsonpath={.items[0].status.podIP}'))
        code=f'import socket;socket.create_connection(("{ip}",4566),timeout=3)'
        p=subprocess.run(k('-n','tenant-a','exec','deploy/mock','--','python','-c',code),capture_output=True,text=True,timeout=15)
        assert p.returncode!=0 and 'TimeoutError' in p.stderr,p.stderr
        return 'permitted same-tenant routes and prohibited cross-tenant/mock-egress routes exercised'
    check('NETWORK','kubectl exec Python socket probes using Pod IPs','allow same tenant; timeout cross tenant and unauthorized egress',network)
    def hardening():
        data=json.loads(run(k('get','pods','-n','tenant-a','-o','json')))
        for pod in data['items']:
            s=pod['spec'];assert not s.get('hostNetwork',False) and not s.get('automountServiceAccountToken',True)
            for c in s['containers']:
                assert c['securityContext']['allowPrivilegeEscalation'] is False
                assert c['resources']['limits']
        services=json.loads(run(k('get','svc','-A','-l','project=p001','-o','json')))
        assert all(s['spec']['type']=='ClusterIP' for s in services['items'])
        bindings=json.loads(run(k('get','clusterrolebindings','-o','json')))
        for b in bindings['items']:
            if b['roleRef']['name']=='cluster-admin':
                assert not any(s.get('namespace') in ['tenant-a','tenant-b','emulator'] for s in b.get('subjects',[]))
        containers=json.loads(run(['docker','inspect','p001-control-plane']))
        for bindings in containers[0]['NetworkSettings']['Ports'].values():
            for b in bindings or []:assert b['HostIp']=='127.0.0.1'
        return 'workload security contexts, cluster-admin bindings, ClusterIP services and node published ports checked'
    check('RUNTIME-HARDENING','kubectl get pods/services/clusterrolebindings; docker inspect p001-control-plane','restricted workload specs and loopback node ports',hardening)
    def logs():
        raw=run(k('-n','tenant-a','logs','deploy/api','--tail=20'));lines=[json.loads(x) for x in raw.splitlines()]
        assert lines and all(set(x)=={'event','status','tenant','service','correlation_id'} for x in lines)
        assert any(x['correlation_id'].startswith('p001-baseline') for x in lines)
        return f'{len(lines)} allowlisted structured log records inspected; values not copied'
    check('LOGS','kubectl logs deploy/api --tail=20 (inspect, do not retain raw)','correlation IDs and only approved fields',logs)
    def drift():
        run(k('-n','tenant-a','scale','deployment/mock','--replicas=2'))
        try:
            run(['tofu','-chdir=infra/opentofu/local','plan','-input=false','-detailed-exitcode'],2)
        finally:run(k('-n','tenant-a','scale','deployment/mock','--replicas=1'))
        run(['tofu','-chdir=infra/opentofu/local','plan','-input=false','-detailed-exitcode'])
        return 'replica drift detected with exit 2; restoration returned exit 0'
    check('DRIFT','scale owned mock to 2; tofu plan; restore to 1; tofu plan','drift detected and then clean',drift)
    results.append(dict(id='REBUILD',status='NOT TESTED',command='make lab-rebuild-verify',expected='double teardown and clean reprovision pass',observed='run separately; this test does not destroy the active cluster',utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),verifier='Codex'))
for id,why in [('AWS-IAM','no real AWS authorization or operation'),('LOCALSTACK-IAM','no verified IAM enforcement in selected free configuration'),('SCANNERS','dedicated vulnerability scanners not installed; narrow secret/structural checks run separately')]:
    results.append(dict(id=id,status='NOT TESTED',command='none',expected='independent validation',observed=why,utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),verifier='Codex'))
(R/'.runtime').mkdir(exist_ok=True)
(R/'.runtime/results.json').write_text(json.dumps(results,indent=2)+'\n')
print('Results saved: .runtime/results.json')
sys.exit(any(x['status'] in ['FAIL','BLOCKED'] for x in results))
