"""Python 3.9+, standard library only. No network requests."""
import csv, json, random, statistics, hashlib, platform
from pathlib import Path
from datetime import datetime, timezone
import argparse
ROOT=Path(__file__).resolve().parent

def write_csv(path, rows):
    with path.open('w',encoding='utf-8-sig',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)

def generate(d):
    events=[]
    for scenario,interval in d['scenarios'].items():
        for rep in range(1,d['repetitions']+1):
            seed=d['seed_start']+rep-1
            rng=random.Random(seed) # same normal stream across scenarios
            local=[];t=0.;i=0
            while True:
                t+=interval*rng.uniform(.8,1.2)
                if t>=d['duration_seconds']:break
                i+=1;local.append((round(t,6),'attacker',0,i))
            # independent stream so normal events match across attack rates
            nr=random.Random(seed+100000)
            for j in range(d['normal_requests']):
                local.append((round(nr.uniform(0,d['duration_seconds']),6),'normal',int(nr.random()>=d['normal_error_probability']),j))
            local.sort(key=lambda x:(x[0],0 if x[1]=='attacker' else 1,x[3]))
            for idx,(t,actor,correct,_) in enumerate(local,1):
                events.append(dict(scenario=scenario,rep=rep,seed=seed,id=idx,time=t,actor=actor,correct=correct))
    return events

def evaluate(events,d):
    outputs=[];summary=[]
    for scenario in d['scenarios']:
        for rep in range(1,d['repetitions']+1):
            group=[x for x in events if x['scenario']==scenario and int(x['rep'])==rep]
            for policy in ['none','lock5_30']:
                failures=0;until=None
                counts=dict(attack_offered=0,attack_checked=0,attack_blocked=0,normal_offered=0,normal_checked=0,normal_blocked=0,normal_success=0,normal_correct=0,normal_correct_blocked=0)
                for e in group:
                    t=float(e['time']);actor=e['actor'];correct=int(e['correct']);prefix='attack' if actor=='attacker' else 'normal'
                    counts[prefix+'_offered']+=1
                    if actor=='normal':counts['normal_correct']+=correct
                    if until is not None and t>=until:failures=0;until=None
                    blocked=policy!='none' and until is not None and t<until
                    if blocked:
                        counts[prefix+'_blocked']+=1;result='blocked'
                        if actor=='normal':counts['normal_correct_blocked']+=correct
                    else:
                        counts[prefix+'_checked']+=1
                        if correct:
                            failures=0;result='success'
                            if actor=='normal':counts['normal_success']+=1
                        else:
                            failures+=1;result='failure'
                            if policy!='none' and failures>=d['threshold']:until=t+d['lock_seconds']
                    outputs.append(dict(**e,policy=policy,outcome=result,failure_count=failures,locked_until='' if until is None else round(until,6)))
                summary.append(dict(scenario=scenario,rep=rep,policy=policy,**counts))
    return outputs,summary

def aggregate(summary,d):
    out=[]
    for s in d['scenarios']:
        a=[x for x in summary if x['scenario']==s and x['policy']=='none'];b=[x for x in summary if x['scenario']==s and x['policy']!='none']
        reductions=[100*(x['attack_checked']-y['attack_checked'])/x['attack_checked'] for x,y in zip(a,b)]
        out.append(dict(scenario=s,n=len(a),attack_none_mean=statistics.mean(x['attack_checked'] for x in a),attack_lock_mean=statistics.mean(x['attack_checked'] for x in b),reduction_mean_pct=statistics.mean(reductions),reduction_min_pct=min(reductions),reduction_max_pct=max(reductions),normal_blocked=sum(x['normal_blocked'] for x in b),normal_offered=sum(x['normal_offered'] for x in b),normal_correct_blocked=sum(x['normal_correct_blocked'] for x in b),normal_correct=sum(x['normal_correct'] for x in b),normal_success_none=sum(x['normal_success'] for x in a),normal_success_lock=sum(x['normal_success'] for x in b)))
    return out

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--replay',action='store_true');args=ap.parse_args()
    d=json.loads((ROOT/'design.json').read_text(encoding='utf-8'))
    for p in ['data','results']:(ROOT/p).mkdir(exist_ok=True)
    if args.replay:
        with (ROOT/'data/requests.csv').open(encoding='utf-8-sig') as f:events=list(csv.DictReader(f))
    else:
        events=generate(d);write_csv(ROOT/'data/requests.csv',events)
    outputs,summary=evaluate(events,d);agg=aggregate(summary,d)
    write_csv(ROOT/'results/events.csv',outputs);write_csv(ROOT/'results/runs.csv',summary)
    (ROOT/'results/summary.json').write_text(json.dumps(agg,ensure_ascii=False,indent=2),encoding='utf-8')
    # Invariants check every request is accounted for in both policies.
    assert len(summary)==180 and len(outputs)==2*len(events)
    assert all(x['attack_offered']==x['attack_checked']+x['attack_blocked'] and x['normal_offered']==x['normal_checked']+x['normal_blocked'] for x in summary)
    assert all(x['attack_blocked']==x['normal_blocked']==0 for x in summary if x['policy']=='none')
    print(json.dumps(agg,ensure_ascii=False,indent=2));print('PASS: 90 paired streams / 180 policy runs; all requests accounted for')
if __name__=='__main__':main()
