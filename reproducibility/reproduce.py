"""Offline numeric reproduction. Default: standard library point checks.

--bootstrap adds the unchanged S and matched recording-bootstrap implementations.
This program never imports hardware/model code or reads excluded transcripts.
"""
import argparse
from collections import defaultdict
import csv
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import platform
import sys

ROOT=Path(__file__).resolve().parents[1]


def need(ok, message):
    if not ok: raise ValueError(message)


def js(path):
    return json.loads(path.read_text())


def csvread(path):
    with path.open(newline='') as f: return list(csv.DictReader(f))


def jl(path):
    return [json.loads(v) for v in path.read_text().splitlines() if v.strip()]


def near(a,b):
    need(math.isfinite(float(a)) and math.isfinite(float(b)) and math.isclose(float(a),float(b),rel_tol=1e-10,abs_tol=1e-9),f'numeric mismatch: {a} != {b}')


def compare(actual, expected):
    """Compare all saved numeric fields and exact categorical identities."""
    if isinstance(expected,dict):
        for k,v in expected.items():
            need(k in actual,'missing saved field '+k); compare(actual[k],v)
    elif isinstance(expected,list):
        need(len(actual)==len(expected),'list length mismatch')
        for a,b in zip(actual,expected): compare(a,b)
    elif type(expected) in (int,float):near(actual,expected)
    else:need(actual==expected,'categorical mismatch: '+str(expected))


def integrity():
    manifest=js(ROOT/'reproducibility/SHA256_MANIFEST.json')
    for name, pin in manifest['files'].items():
        p=ROOT/name
        need(not p.is_symlink() and p.resolve().is_relative_to(ROOT),'unsafe static path')
        b=p.read_bytes();need(len(b)==pin['bytes'] and hashlib.sha256(b).hexdigest()==pin['sha256'],'integrity mismatch: '+name)
    # Data inventory must be closed: a forgotten text dump must not go unnoticed.
    for d in ['data','analysis','hardware','conversion','work','licenses']:
        actual={str(p.relative_to(ROOT)) for p in (ROOT/d).rglob('*') if p.is_file() and '__pycache__' not in p.parts}
        need(actual=={n for n in manifest['files'] if n.startswith(d+'/')},'unexpected/missing static file in '+d)
    exports=js(ROOT/'reproducibility/EXPORT_MANIFEST.json')['entries']
    for row in exports:
        b=(ROOT/row['path']).read_bytes()
        need(hashlib.sha256(b).hexdigest()==row['sha256'],'extracted file changed')
        if row['operation']=='byte_identical_copy':need(row['source_sha256']==row['sha256'],'copy differs from source')
    return dict(files=len(manifest['files']),self_consistency_only=True,external_signature=False)


def quality_points(cohort):
    rows=csvread(ROOT/f'data/scores/{cohort}.csv'); seen=set(); groups=defaultdict(list)
    expected_sizes={'A':(600,18,9),'F':(600,18,9),'C':(800,20,5),'EV':(600,18,2)}
    for r in rows:
        key=(r['id'],r['policy'],r['mode']);need(key not in seen,'duplicate score');seen.add(key)
        n,e,s,d,i=[int(r[k]) for k in ['reference_characters','errors','substitutions','deletions','insertions']]
        need(n>0 and min(e,s,d,i)>=0 and e==s+d+i,'invalid edit counts')
        groups[r['mode'],r['policy']].append(r)
    result=[]
    for (mode,policy),rs in sorted(groups.items()):
        byrec=defaultdict(list)
        for r in rs:byrec[r['meeting']].append(r)
        n=sum(int(r['reference_characters']) for r in rs);e=sum(int(r['errors']) for r in rs)
        result.append(dict(mode=mode,policy=policy,source_N=len(rs),recording_N=len(byrec),reference_characters=n,errors=e,
            pooled_CER_pct=100*e/n,macro_CER_pct=100*math.fsum(sum(int(r['errors']) for r in rr)/sum(int(r['reference_characters']) for r in rr) for rr in byrec.values())/len(byrec)))
    # All arms/modes must have exactly the same source roster and reference n.
    signatures=[{(r['id'],r['meeting'],r['reference_characters']) for r in rs} for rs in groups.values()]
    need(all(s==signatures[0] for s in signatures),'score roster drift')
    ns,nr,np=expected_sizes[cohort]
    need(len(signatures[0])==ns and len({r['meeting'] for r in rows})==nr,'cohort census')
    need(len({r['policy'] for r in rows})==np,'policy census')
    expected=csvread(ROOT/f'data/expected/{cohort}_per_policy.csv') if cohort=='C' else js(ROOT/f'data/expected/{cohort}_per_policy.json')
    lookup={(r['mode'],r['policy']):r for r in result}
    for r in expected:
        key=(r.get('mode','primary_casefold'),r['policy']);got=lookup[key]
        near(got['reference_characters'],r['reference_characters']);near(got['errors'],r['errors'])
        near(got['pooled_CER_pct'],100*float(r['cer']))
        macro=r.get('equal_recording_cer',r.get('equal_meeting_cer'))
        near(got['macro_CER_pct'],100*float(macro))
    return dict(rows=len(rows),source_N=ns,recording_N=nr,policies=np,methods=result,
                intervals='A/F/C/EV historical intervals preserved in expected files where available; not recomputed',text_rescored=False)


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m


def save(path,obj):
    path.write_text(json.dumps(obj,indent=2,ensure_ascii=False,allow_nan=False)+'\n')


def csvsave(path,rows):
    with path.open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)


def bootstraps(out):
    import numpy as np
    stat=load('public_frozen_statistics',ROOT/'analysis/formal_statistics.py')
    for scope in ['QUALITY','COST']:
        result=stat.analyze(js(ROOT/f'data/S/{scope}_MANIFEST.json'),jl(ROOT/f'data/S/{scope}_ROWS.jsonl'))
        expected=js(ROOT/f'data/expected/S_{scope}.json')
        # Omitted metadata paths never enter the statistical calculation.
        compare(result,expected)
        save(out/f'S_{scope}.json',result)
    matched=load('public_matched_analysis',ROOT/'analysis/matched_measurement_v2/analyze.py')
    rows=[r for block in ['r1_audit','r1_minimal','r2_minimal','r2_audit'] for r in jl(ROOT/f'data/matched/{block}.jsonl')]
    roster={r['id']:r for r in js(ROOT/'data/matched/roster.json')}
    need(len(rows)==2400 and len(roster)==120,'matched census')
    for r in rows:
        need(r['status']=='ok','failed actual cell')
        near(sum(r[k] for k in matched.STAGES)+r['service_minus_stage_sum_s'],r['service_s'])
        need(r['actual_SV_native_attempts']==r['actual_SV_native_completed'],'incomplete native calls')
        need(r['actual_SDK_calls']==r['actual_teacher_policy_calls'],'SDK count mismatch')
    schedule=js(ROOT/'data/matched/schedule.json')['rows']
    coordinates=lambda x:(x['block_id'],x['cell_index'],x['mode'],x['repeat'],x['source_id'],x['recording_id'],x['policy'])
    need({coordinates(r) for r in rows}=={coordinates(r) for r in schedule},'schedule drift')
    result=matched.summarize(rows,roster);result['components']=matched.component_ledger(rows,roster)
    checked=0
    for name in ['arms','effects','rounds','leave_one_date','mode_associated','components']:
        saved=csvread(ROOT/f'results/matched_measurement/{name}.csv');actual=result[name]
        need(len(saved)==len(actual),'matched output row count')
        for a,b in zip(actual,saved):
            for k,v in b.items():
                if type(a[k]) in (int,float):near(a[k],float(v));checked+=1
                else:need(str(a[k])==v,'matched categorical row mismatch')
        csvsave(out/f'matched_{name}.csv',actual)
    return dict(numpy=np.__version__,seed=stat.SEED,draws=stat.BOOTSTRAPS,
        S_quality_rows=6000,S_cost_rows=2400,matched_rows=len(rows),matched_recordings=result['recordings'],
        matched_numeric_fields_compared=checked,text_parity_reverified=False,physical_replay=False)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--bootstrap',action='store_true')
    ap.add_argument('--output',type=Path,default=ROOT/'reproduced')
    a=ap.parse_args();out=a.output.resolve()
    # Never overwrite evidence, original outputs or source code.
    for d in ['data','analysis','hardware','conversion','work','licenses','results','reproducibility','scripts','docs']:
        need(not out.is_relative_to(ROOT/d),'output overlaps protected evidence/code')
    need(out!=ROOT,'output cannot be repository root')
    out.mkdir(parents=True,exist_ok=True)
    receipt=dict(status='FAIL',python=platform.python_version(),text_rescored=False,hardware_run=False)
    try:
        receipt['integrity']=integrity()
        receipt['points']={c:quality_points(c) for c in ['A','EV','F','C']}
        if a.bootstrap:receipt['bootstrap']=bootstraps(out)
        else:receipt['bootstrap']='not requested; run with --bootstrap and NumPy'
        receipt['status']='PASS'
    except Exception as exc:
        receipt['error']=type(exc).__name__+': '+str(exc)
    save(out/'VERIFICATION.json',receipt)
    print(json.dumps({k:v for k,v in receipt.items() if k not in ('points',)},indent=2))
    return 0 if receipt['status']=='PASS' else 1


if __name__=='__main__':
    raise SystemExit(main())
