"""Post-execution analysis for real four-block measurements; no inference/SSH.

Requires four complete, hash/guard/restoration-verified whole attempts. Never
substitutes historical costs for missing minimal data. Imported functions are
also exercised by explicitly labelled local arithmetic fixtures.
"""
from pathlib import Path
from collections import defaultdict
import argparse,csv,hashlib,importlib.util,json,math,sys,unicodedata
import numpy as np
ROOT=Path(__file__).resolve().parents[2]
M,D,C,L,Q='mean95','distinct_probe_confirmation','cheap_sameview_skip','legacy_conditional90to95','full_qwen'
POLICIES=(Q,M,D,C,L)
STAGES=('frontend_s','first_s','first_confidence_s','probe_s','probe_frontend_s','teacher_s','routing_s')
SEED=2026101622;DRAWS=10000
CONTRASTS=[(D,M,'primary'),(D,C,'key_control'),(M,Q,'key_control'),(L,C,'secondary'),(M,C,'secondary'),(D,L,'secondary')]
_policy_spec=importlib.util.spec_from_file_location('matched_frozen_policy',ROOT/'work/measurement_core/formal_policy_core.py')
POLICY_CORE=importlib.util.module_from_spec(_policy_spec);_policy_spec.loader.exec_module(POLICY_CORE)
def need(v,m):
 if not v:raise ValueError(m)
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def read(p):return json.loads(Path(p).read_text())
def dump(p,v):Path(p).write_text(json.dumps(v,indent=2,ensure_ascii=False,allow_nan=False)+'\n')
def csvout(p,rs):
 with Path(p).open('w',newline='') as f:
  w=csv.DictWriter(f,fieldnames=list(rs[0]));w.writeheader();w.writerows(rs)
def part_signature(x):
 if x is None:return None
 need(isinstance(x.get('text'),str) and isinstance(x.get('parts'),list) and x['parts'],'SV transcript/parts missing')
 names=('start_sample','end_sample','valid_frames','text','token_ids')
 end=0
 for p in x['parts']:
  need(all(n in p for n in names),'SV segmentation/token evidence missing')
  need(type(p['start_sample']) is int and type(p['end_sample']) is int and p['start_sample']==end and p['end_sample']>end,'invalid/noncontiguous SV sample boundaries')
  need(type(p['valid_frames']) is int and 0<p['valid_frames']<=167,'invalid SV valid frames')
  need(isinstance(p['text'],str) and isinstance(p['token_ids'],list) and all(type(t) is int and t>0 for t in p['token_ids']),'invalid SV text/token evidence')
  end=p['end_sample']
 need(x['text']==''.join(p['text'] for p in x['parts']),'SV part/final text inconsistency')
 return {'text':x['text'],'parts':[{n:p[n] for n in names} for p in x['parts']]}
def product_signature(r):
 names=('text','actions','confidence','first_empty','same_waveform','actual_SV_native_attempts','actual_SV_native_completed','actual_SDK_calls','actual_teacher_policy_calls')
 need(all(n in r for n in names),'product/call fields missing')
 s={n:r[n] for n in names};s['first']=part_signature(r.get('first'));s['probe']=part_signature(r.get('probe'))
 front=r.get('frontend');need(isinstance(front,dict),'frontend evidence missing')
 s['selected_channel']=front['selected_channel']
 need(type(s['selected_channel']) is int and 0<=s['selected_channel']<8 and type(r['same_waveform']) is bool and r['same_waveform']==(s['selected_channel']==0),'waveform/channel identity inconsistent')
 need(r['policy'] in POLICIES,'unknown policy')
 if r['policy']==Q:
  need(r.get('first') is None and r.get('probe') is None and r['confidence'] is None and r['first_empty'] is None,'fullQ must not pay SV/confidence')
  expected=['teacher']
 else:
  need(r.get('first') is not None,'required first SV evidence absent')
  need(r['first_empty']==POLICY_CORE.first_is_empty(r['first']),'first empty/token inconsistency')
  kwargs=dict(same_waveform=r['same_waveform'],first_empty=r['first_empty'],confidence=r['confidence'])
  action=POLICY_CORE.next_action(r['policy'],r['first']['text'],**kwargs);expected=[action]
  if action=='probe':
   need(r.get('probe') is not None,'required probe evidence absent')
   expected.append(POLICY_CORE.next_action(r['policy'],r['first']['text'],probe_text=r['probe']['text'],**kwargs))
  else:need(r.get('probe') is None,'unrequested probe evidence')
 need(r['actions']==expected,'actions disagree with frozen current policy')
 count=sum(len(r[k]['parts']) for k in ('first','probe') if r.get(k) is not None)
 need(type(r['actual_SV_native_attempts']) is int and r['actual_SV_native_attempts']==r['actual_SV_native_completed']==count,'SV native counts/parts disagree')
 teacher_needed=expected[-1]=='teacher'
 need(r['actual_teacher_policy_calls']==r['actual_SDK_calls']==int(teacher_needed),'teacher policy/SDK call counts disagree')
 t=r.get('teacher');s['teacher']=None
 need((t is not None)==teacher_needed,'required/unrequested teacher evidence')
 if t is not None:
  need(t['status']=='ok' and t['decoder_error_seen'] is False,'teacher completion/error flag failed')
  a=t['asr'];need(a['second_failure'] is None and not a['sdk_errors'],'SDK error/second failure')
  calls=a['sdk_calls'];need(len(calls)==r['actual_SDK_calls']==1,'required actual teacher invocation')
  fields=('text','ret_code','aborted','finish_seen','error_seen','cache_clear_mode','cache_clear_ret','keep_history','n_tokens_generated')
  for c in calls:
   need(all(k in c for k in fields),'SDK completion/work evidence missing')
   need(type(c['n_tokens_generated']) is int and c['n_tokens_generated']>=0,'invalid SDK generated work')
   need(c['ret_code']==c['cache_clear_ret']==c['cache_clear_mode']==c['keep_history']==0 and c['finish_seen'] is True and c['aborted'] is False and c['error_seen'] is False,'SDK completion/KV contract failed')
  s['teacher']={'text':t['engine_text'],'sdk':[{k:c[k] for k in fields} for c in calls]}
 else:need(r['actual_SDK_calls']==r['actual_teacher_policy_calls']==0,'teacher missing with nonzero calls')
 need(r['text']==(t['engine_text'] if teacher_needed else r['first']['text']),'adopted final text inconsistent with action')
 return s

def compare_products(records):
 need(bool(records),'empty product records')
 groups=defaultdict(dict)
 for r in records:
  key=(r['repeat'],r['source_id'],r['policy']);need(r['mode'] not in groups[key],'duplicate mode coordinate');groups[key][r['mode']]=r
 mismatches=[]
 for key,rs in sorted(groups.items()):
  need(set(rs)=={'audit','minimal'},'missing paired product mode')
  a,b=product_signature(rs['audit']),product_signature(rs['minimal'])
  differences=[k for k in a if a[k]!=b[k]]
  if differences:mismatches.append({'repeat':key[0],'source_id':key[1],'policy':key[2],'differing_fields':differences})
 return {'scope':'text/actions/confidence/input identity/calls/SV segmentation+tokens/SDK completion+KV+generated-token work','pairs':len(groups),'equal':not mismatches,'mismatches':mismatches,'callback_event_arrays_intentionally_not_compared':True}

def require_artifact_coverage(native):
 """Every artifact actually read by the offline gates must be hash-bound."""
 complete=read(native/'COMPLETE.json');hashes=complete['artifact_sha256']
 required={'calls.jsonl','WARMUP.json','THREAD_MASKS.jsonl','CLEANUP.json'}
 need(required<=set(hashes),'required native artifacts missing from completion hash manifest')
 for name in required:need(sha(native/name)==hashes[name],'required native artifact hash mismatch')
 return {name:hashes[name] for name in sorted(required)}

def aggregate(records,roster,field="service_s"):
 """Return mode x recording x policy means, with repeats averaged in source."""
 modes=sorted({r['mode'] for r in records});recs=sorted({s['recording_id'] for s in roster.values()});groups=defaultdict(list);seen=set()
 for r in records:
  key=(r['mode'],r['repeat'],r['source_id'],r['policy']);need(key not in seen,'duplicate execution coordinate');seen.add(key)
  need(r['source_id'] in roster and r['policy'] in POLICIES,'unknown sample/policy')
  need(r['recording_id']==roster[r['source_id']]['recording_id'],'source/recording mismatch')
  value=float(r[field]);need(math.isfinite(value) and (value>0 if field=='service_s' else value>=-1e-6),'invalid service/component value')
  groups[(r['mode'],r['source_id'],r['policy'])].append((r['repeat'],value))
 values={};rounds={};source_rows=[]
 for mode in modes:
  matrix=np.empty((len(recs),len(POLICIES)));rm={n:np.empty_like(matrix) for n in (1,2)}
  for i,rec in enumerate(recs):
   sources=sorted(sid for sid,s in roster.items() if s['recording_id']==rec)
   need(bool(sources),'empty recording')
   for j,policy in enumerate(POLICIES):
    vs=[];rv={1:[],2:[]}
    for sid in sources:
     pair=sorted(groups[mode,sid,policy]);need([n for n,v in pair]==[1,2],'two actual repeats required')
     v=np.mean([v for n,v in pair]);vs.append(v)
     for n,x in pair:rv[n].append(x)
     source_rows.append({'mode':mode,'source_id':sid,'recording_id':rec,'policy':policy,'mean_service_s':float(v)})
    matrix[i,j]=np.mean(vs)
    for n in (1,2):rm[n][i,j]=np.mean(rv[n])
  values[mode]=matrix;rounds[mode]=rm
 need(len(seen)==len(modes)*len(roster)*len(POLICIES)*2,'complete coordinate grid')
 return modes,recs,values,rounds,source_rows

def weights(recs,roster):
 meta={s['recording_id']:(s['date_prefix'],s['filename_R']) for s in roster.values()}
 groups=defaultdict(list)
 for i,r in enumerate(recs):groups[meta[r]].append(i)
 rng=np.random.default_rng(SEED);fixed=np.zeros((DRAWS,len(recs)),dtype=np.int64)
 for k,ids in sorted(groups.items()):fixed[:,ids]=rng.multinomial(len(ids),np.full(len(ids),1/len(ids)),size=DRAWS)
 dates=sorted({meta[r][0] for r in recs});idx={d:i for i,d in enumerate(dates)}
 draws=np.random.default_rng(SEED).multinomial(len(dates),np.full(len(dates),1/len(dates)),size=DRAWS)
 whole=draws[:,[idx[meta[r][0]] for r in recs]]
 return {'fixed_date_R_recording':fixed,'whole_date_sensitivity':whole},meta

def summarize(records,roster):
 modes,recs,values,rounds,source_rows=aggregate(records,roster);ws,meta=weights(recs,roster);effects=[];arms=[];round_rows=[];loo=[];mode_rows=[]
 definitions=[(a+'-'+b,{a:1,b:-1},role,a,b) for a,b,role in CONTRASTS]+[('probe_by_fallback_interaction',{D:1,M:-1,L:-1,C:1},'secondary',None,None)]
 for mode in modes:
  mat=values[mode]
  for sampler,w in ws.items():
   means=w@mat/w.sum(axis=1)[:,None];point=mat.mean(axis=0)
   for j,p in enumerate(POLICIES):
    low,high=np.quantile(means[:,j],[.025,.975],method='linear');arms.append({'mode':mode,'sampler':sampler,'policy':p,'service_s':float(point[j]),'ci95_low_s':float(low),'ci95_high_s':float(high)})
   for name,coeff,role,a,b in definitions:
    c=np.array([coeff.get(p,0) for p in POLICIES]);x=1000*(means@c);low,high=np.quantile(x,[.025,.975],method='linear')
    effects.append({'mode':mode,'sampler':sampler,'contrast':name,'role':role,'metric':'candidate_minus_comparator_ms','estimate':float(1000*(point@c)),'ci95_low':float(low),'ci95_high':float(high)})
    if a:
     aj,bj=POLICIES.index(a),POLICIES.index(b);x=100*(means[:,aj]/means[:,bj]-1);low,high=np.quantile(x,[.025,.975],method='linear')
     effects.append({'mode':mode,'sampler':sampler,'contrast':name,'role':role,'metric':'relative_service_change_percent','estimate':float(100*(point[aj]/point[bj]-1)),'ci95_low':float(low),'ci95_high':float(high)})
  for rep in (1,2):
   for a,b,role in CONTRASTS:
    pm=rounds[mode][rep].mean(axis=0);aj,bj=POLICIES.index(a),POLICIES.index(b)
    round_rows.append({'mode':mode,'repeat':rep,'contrast':a+'-'+b,'difference_ms':float(1000*(pm[aj]-pm[bj])),'relative_change_pct':float(100*(pm[aj]/pm[bj]-1))})
  for date in sorted({meta[r][0] for r in recs}):
   keep=[i for i,r in enumerate(recs) if meta[r][0]!=date]
   for a,b,role in CONTRASTS:
    pm=mat[keep].mean(axis=0);aj,bj=POLICIES.index(a),POLICIES.index(b)
    loo.append({'mode':mode,'omitted_date':date,'contrast':a+'-'+b,'difference_ms':float(1000*(pm[aj]-pm[bj]))})
 if set(modes)=={'audit','minimal'}:
  for sampler,w in ws.items():
   diff=values['minimal']-values['audit'];dm=w@diff/w.sum(axis=1)[:,None]
   for name,c,role,a,b in definitions:
    coeff=np.array([c.get(p,0) for p in POLICIES]);x=1000*(dm@coeff);low,high=np.quantile(x,[.025,.975],method='linear')
    mode_rows.append({'sampler':sampler,'contrast':name,'estimate_ms':float(1000*(diff.mean(axis=0)@coeff)),'ci95_low_ms':float(low),'ci95_high_ms':float(high),'interpretation':'mode-associated difference-in-differences; time blocks/OS cache confounded, not pure overhead'})
 return {'arms':arms,'effects':effects,'rounds':round_rows,'leave_one_date':loo,'mode_associated':mode_rows,'sources':source_rows,'recordings':len(recs)}

def component_ledger(records,roster):
 rows=[]
 for component in STAGES+('service_minus_stage_sum_s','service_s'):
  modes,recs,values,rounds,source_rows=aggregate(records,roster,component);ws,meta=weights(recs,roster)
  for mode in modes:
   for sampler,w in ws.items():
    point=values[mode].mean(axis=0);means=w@values[mode]/w.sum(axis=1)[:,None]
    for j,policy in enumerate(POLICIES):
     lo,hi=np.quantile(means[:,j]*1000,[.025,.975],method='linear')
     rows.append({'mode':mode,'sampler':sampler,'component':component,'estimand':policy,'role':'total' if component=='service_s' else 'disjoint_component','estimate_ms':float(1000*point[j]),'ci95_low_ms':float(lo),'ci95_high_ms':float(hi)})
    for a,b,role in CONTRASTS:
     aj,bj=POLICIES.index(a),POLICIES.index(b);x=1000*(means[:,aj]-means[:,bj]);lo,hi=np.quantile(x,[.025,.975],method='linear')
     rows.append({'mode':mode,'sampler':sampler,'component':component,'estimand':a+'-'+b,'role':'paired_difference','estimate_ms':float(1000*(point[aj]-point[bj])),'ci95_low_ms':float(lo),'ci95_high_ms':float(hi)})
 return rows

def normalize(s):return ''.join(c for c in unicodedata.normalize('NFKC',s).casefold() if c.isalpha() or c.isdigit())
def edits(a,b):
 row=list(range(len(b)+1))
 for i,x in enumerate(a,1):
  new=[i]
  for j,y in enumerate(b,1):new.append(min(row[j]+1,new[-1]+1,row[j-1]+(x!=y)))
  row=new
 return row[-1]
def score_diagnostics(records,refs):
 rows=[]
 for r in records:
  ref=normalize(refs[r['source_id']]['reference']);hyp=normalize(r['text'])
  rows.append({'source_id':r['source_id'],'recording_id':r['recording_id'],'mode':r['mode'],'repeat':r['repeat'],'policy':r['policy'],'n':len(ref),'errors':edits(ref,hyp),'hypothesis':r['text']})
 return rows

def bank_drift(r,score,b):
 return dict(source_id=r['source_id'],mode=r['mode'],repeat=r['repeat'],policy=r['policy'],
  raw_text_equal=r['text']==b['hypothesis'],normalized_equal=normalize(r['text'])==normalize(b['hypothesis']),
  actual_minus_bank_edits=score['errors']-b['errors'],actions_equal=r['actions']==b['actions'],
  SDK_calls_equal=r['actual_SDK_calls']==b['predicted_Q_calls'],
  SV_native_calls_equal=r['actual_SV_native_completed']==b['predicted_SV_native_calls'],
  same_waveform_equal=None if b['same_waveform'] is None else r['same_waveform']==b['same_waveform'],first_empty_equal=r['first_empty']==b['first_empty'])

def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--measurement-root',type=Path,required=True);ap.add_argument('--selection',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
 a.output.mkdir(parents=True,exist_ok=False);out=a.output
 try:
  spec=importlib.util.spec_from_file_location('validated_block_reader',a.measurement_root/'run_native.py');runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(runner)
  selection=read(a.selection);coverage={}
  for block,rep,mode in runner.BLOCKS:coverage[block]=require_artifact_coverage(runner.stage_path(a.measurement_root,block,selection[block])/'native_v1')
  dump(out/'REQUIRED_ARTIFACT_HASH_COVERAGE.json',coverage)
  base=runner.compare_completed_blocks(a.measurement_root,selection);dump(out/'BLOCK_ACCEPTANCE.json',base)
  need(base['mode_parity_equal'],'basic mode parity failed')
  manifest=read(a.measurement_root/'SOURCE_MANIFEST.json');roster={r['id']:r for r in manifest['samples']};records=[];inputs={str(a.selection.resolve()):sha(a.selection)}
  for p in (a.measurement_root/'run_native.py',a.measurement_root/'SOURCE_MANIFEST.json',a.measurement_root/'SCHEDULE.json',a.measurement_root/'MEASUREMENT_PROTOCOL.json',a.measurement_root.parent/'measurement_core/PACKAGE_SHA256.json',ROOT/'work/measurement_core/formal_policy_core.py'):inputs[str(p.resolve())]=sha(p)
  need(sha(a.measurement_root.parent/'measurement_core/formal_policy_core.py')==sha(ROOT/'work/measurement_core/formal_policy_core.py'),'analysis and measured frozen policy code differ')
  for block,rep,mode in runner.BLOCKS:
   stage=runner.stage_path(a.measurement_root,block,selection[block]);f=stage/'native_v1/calls.jsonl';raw=f.read_bytes();h=hashlib.sha256(raw).hexdigest()
   need(h==coverage[block]['calls.jsonl'],'calls changed after completion-bound validation')
   inputs[str(f.resolve())]=h;records += [json.loads(x) for x in raw.decode().splitlines()]
   for name in ('ATTEMPT.json','STAGE_COMPLETE.json','native_v1/COMPLETE.json','guard_v1/GUARD_COMPLETE.json','guard_v1/PAUSED.json','guard_v1/RESTORED.json'):
    p=stage/name;inputs[str(p.resolve())]=sha(p)
  for r in records:
   need(math.isclose(sum(float(r[k]) for k in STAGES)+r['service_minus_stage_sum_s'],r['service_s'],abs_tol=1e-6),'component ledger does not close to service')
  parity=compare_products(records);dump(out/'ENHANCED_PRODUCT_PARITY.json',parity);need(parity['equal'],'segmentation/token/completion parity failed')
  result=summarize(records,roster)
  for name in ('arms','effects','rounds','leave_one_date','mode_associated','sources'):csvout(out/(name+'.csv'),result[name])
  csvout(out/'components.csv',component_ledger(records,roster))
  refpath=ROOT/'reproducibility/data/S/source/DATA_REFERENCES.json';refs={r['id']:r for r in read(refpath)['samples']};inputs[str(refpath.relative_to(ROOT))]=sha(refpath);scores=score_diagnostics(records,refs);csvout(out/'actual120_diagnostic_scores.csv',scores)
  bankpath=ROOT/'reproducibility/data/S/analysis/QUALITY_ROWS.jsonl';bank={(r['source_id'],r['policy']):r for r in (json.loads(x) for x in bankpath.read_text().splitlines())};inputs[str(bankpath.relative_to(ROOT))]=sha(bankpath)
  drift=[]
  for r,score in zip(records,scores):
   b=bank[r['source_id'],r['policy']];drift.append(bank_drift(r,score,b))
  csvout(out/'historical_bank_drift.csv',drift)
  dump(out/'BANK_DRIFT_SUMMARY.json',{'scope':'actual120 versus historical bank; unchanged text alone does not imply unchanged routing/work',
   'unequal_rows':{k:sum(r[k] is False for r in drift) for k in ('raw_text_equal','normalized_equal','actions_equal','SDK_calls_equal','SV_native_calls_equal','same_waveform_equal','first_empty_equal')},
   'identity_comparison_unavailable_rows':sum(r['same_waveform_equal'] is None for r in drift),
   'identity_scope':'Historical fullQ projections do not expose waveform identity; missing comparisons are not drift or evidence of agreement',
   'edit_delta_nonzero_rows':sum(r['actual_minus_bank_edits']!=0 for r in drift)})
  for name,h in inputs.items():need(sha(Path(name) if Path(name).is_absolute() else ROOT/name)==h,'analysis input changed before final acceptance: '+name)
  for block,rep,mode in runner.BLOCKS:
   native=runner.stage_path(a.measurement_root,block,selection[block])/'native_v1'
   need(require_artifact_coverage(native)==coverage[block],'bound native artifacts changed before final acceptance')
  dump(out/'STATUS.json',{'status':'ACTUAL_MODE_BLOCK_ANALYSIS_COMPLETE','actual_cells':len(records),'sources':len(roster),'recordings':result['recordings'],'inputs':inputs,'bank_drift_normalized_rows':sum(not r['normalized_equal'] for r in drift),'bank_edit_delta_nonzero_rows':sum(r['actual_minus_bank_edits']!=0 for r in drift),'bank_scope':'No observed subset drift cannot prove all600 still identical; any observed drift requires claim revision','analysis_sha256':sha(__file__),'seed':SEED,'bootstrap_draws':DRAWS,'intervals':'marginal descriptive95%; repeated recordings within fixed dates; whole-date sensitivity separate','scope':'120 exposed sources; two real blocks per mode; not new independent600-source quality confirmation or arbitrary future-run variance','primary':'within-minimal D-M','key_controls':['within-minimal D-C','within-minimal M-Q'],'not_concluded':['noninferiority','pure instrumentation overhead','paper acceptance','goal completion']})
 except Exception as e:
  dump(out/'STATUS.json',{'status':'FAILED_NOT_SCIENTIFICALLY_ACCEPTED','error':f'{type(e).__name__}: {e}','partial_preserved':True});raise
if __name__=='__main__':main()
