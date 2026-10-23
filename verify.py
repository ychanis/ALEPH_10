"""Verify originals, replay in a new temporary directory, test lock boundaries."""
import json,hashlib,tempfile,shutil,subprocess,sys,csv,importlib.util
from pathlib import Path
p=Path(__file__).resolve().parent
hashes=json.loads((p/'SHA256SUMS.json').read_text())
for name,expected in hashes.items():
 assert hashlib.sha256((p/name).read_bytes()).hexdigest()==expected, 'hash mismatch: '+name
with tempfile.TemporaryDirectory() as td:
 q=Path(td)/'replay';shutil.copytree(p,q)
 subprocess.run([sys.executable,str(q/'run.py'),'--replay'],check=True,capture_output=True)
 for name in ['summary.json','runs.csv','events.csv']:
  assert (q/'results'/name).read_bytes()==(p/'results'/name).read_bytes(), 'replay mismatch: '+name
spec=importlib.util.spec_from_file_location('experiment',p/'run.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
d=json.loads((p/'design.json').read_text());d['scenarios']={'test':1};d['repetitions']=1
# fifth failure at t=4 is checked; t<34 blocked; t=34 released; success resets.
inputs=[]
for i,(t,correct) in enumerate([(0,0),(1,0),(2,0),(3,0),(4,0),(33.999,1),(34,1),(35,0)],1):
 inputs.append(dict(scenario='test',rep=1,seed=1,id=i,time=t,actor='normal',correct=correct))
o,s=m.evaluate(inputs,d);locked=[x for x in o if x['policy']=='lock5_30']
assert [x['outcome'] for x in locked]==['failure']*5+['blocked','success','failure']
assert locked[-1]['failure_count']==1
counts=json.loads((p/'data_counts.json').read_text())
for name,key in [('data/requests.csv','request_rows'),('results/events.csv','policy_event_rows')]:
 with (p/name).open(encoding='utf-8-sig') as f: assert sum(1 for _ in csv.DictReader(f))==counts[key]
print('PASS: hashes, isolated replay, row counts, lock threshold/expiry/success reset')
