import importlib.util,json,threading,unittest
from pathlib import Path
from urllib.request import Request,urlopen
from urllib.error import HTTPError
spec=importlib.util.spec_from_file_location('httpapp',Path(__file__).parents[2]/'services/common/app.py');a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
class HTTPTests(unittest.TestCase):
 def setUp(self):
  self.server=a.ThreadingHTTPServer(('127.0.0.1',0),a.Handler);self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
 def tearDown(self):self.server.shutdown();self.server.server_close();self.thread.join()
 def request(self,path,body,token=None):
  h={'Content-Type':'application/json','X-Correlation-ID':'p001-http-unit'}
  if token:h['Authorization']=token
  q=Request('http://127.0.0.1:'+str(self.server.server_port)+path,json.dumps(body).encode(),h)
  try:r=urlopen(q,timeout=3)
  except HTTPError as e:r=e
  return r.status,json.load(r),r.headers
 def test_actual_mock_http(self):
  a.MODE='mock';status,result,h=self.request('/infer',{'prompt':'synthetic'})
  self.assertEqual(status,200);self.assertEqual(result,a.infer('synthetic'));self.assertEqual(h['X-Correlation-ID'],'p001-http-unit')
 def test_actual_api_denial(self):
  a.MODE='api';status,result,_=self.request('/infer',{'prompt':'synthetic'},'Bearer p001-fixture-tenant-b');self.assertEqual(status,403)
 def test_actual_body_budget(self):
  a.MODE='api';status,_,_=self.request('/infer',{'prompt':'x'*5000},'Bearer p001-fixture-tenant-a');self.assertEqual(status,413)
