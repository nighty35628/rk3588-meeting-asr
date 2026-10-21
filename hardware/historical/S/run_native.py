"""One guarded formal stage, reusing the verified T runtime/capture functions.

Preparation only until deployed as run_native.py with RUNTIME_CONFIG.json,
SOURCE_MANIFEST.json, SCHEDULE.json, POLICY_PARAMETERS.json, CHEAP_RF.json,
MIXTURE_ASSIGNMENTS.json and the bound local execution modules. Stage mode is
bank/repeat0 or timing/repeat1/2. No references/char counts/speaker labels enter
the source manifest. Each stage initializes both models once in its own process.
The unmodified inherited guard owns pause/restore, and stage guards are separate.

Common study raw_pool stores actual freshly returned tensors by SHA AFTER wall
service. Reuse is storage only, never routing/inference. Archive validation and
source IO are excluded, output copies remain included, every actual call has its
own occurrence/event. Stage receipts are execution-only until physical replay.
"""
from __future__ import annotations
import fcntl
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import shutil
import signal
import sys
import time
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parent
BASE=Path('/path/to/local_host/research/qwen-asr-screening/numeric_fidelity_20261014')
ADAPTER=BASE/'spatial_probe_policy_timing_20261016/attempt_01/run_native.py'
ADAPTER_SHA='b814f1b0b08e8ae23d91b8840302116bbb5c23cf01343841dac54e940a39ad02'
TEACHER=BASE/'spatial_probe_teacher_pilot_20261016/attempt_01/run_native.py'
TEACHER_SHA='c272c633b22e31bd7ad31bc667170bcd9e938a0fdd600077918a36ca26322e95'
SOURCE=BASE/'calibration_independent_test_20261016/timing_01'
METHOD_SHA='5e9d106e456455937c4ecdf59f3f8ca1728b2e7cfb584877fe71a31711d2272f'
LOCK=BASE/'formal_general_v1/TIMING_VS_RAW_CPU.lock'
RAW_BYTES=1*25055*1*171*4
COUNT_KEYS=('actual_SV_native_attempts','actual_SV_native_completed','actual_SDK_calls','actual_teacher_policy_calls')
REQUIRED_FILES={'run_native.py','formal_execution_core.py','formal_policy_core.py','confidence_metrics_v1.py',
 'rf_inference_v1.py','verify_formal_payloads.py','guard_native.py','PROTOCOL.md','SOURCE_MANIFEST.json',
 'SCHEDULE.json','POLICY_PARAMETERS.json','CHEAP_RF.json','MIXTURE_ASSIGNMENTS.json'}
SOURCE_FIELDS={'id','recording_id','meeting','audio','sha256','pcm_sha256','frames','duration_s',
 'channels','sample_rate','encoding','quality_member','cost_member','primary_role','date_prefix','filename_R'}

def require(ok,message):
 if not ok:raise ValueError(message)
def sha(path):
 h=hashlib.sha256()
 with Path(path).open('rb') as f:
  for data in iter(lambda:f.read(1048576),b''):h.update(data)
 return h.hexdigest()
def read(p):return json.loads(Path(p).read_text())
def dump(p,value):
 with Path(p).open('x') as f:f.write(json.dumps(value,ensure_ascii=False,indent=2,allow_nan=False)+'\n');f.flush();os.fsync(f.fileno())
def append(p,value):
 with Path(p).open('a') as f:f.write(json.dumps(value,ensure_ascii=False,allow_nan=False)+'\n');f.flush();os.fsync(f.fileno())
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
def process_start_ticks():return int((Path('/proc')/str(os.getpid())/'stat').read_text().split(') ',1)[1].split()[19])
def error(exc):
 import traceback
 return dict(type=type(exc).__name__,message=str(exc),traceback=traceback.format_exc())

class SharedTensorStore:
 def __init__(self,pool,reserve_bytes):
  self.pool=Path(pool);self.reserve=reserve_bytes;self.index={};self.checked={};self.reuse_errors=[]
  for name in ('raw_sv','inputs'):(self.pool/name).mkdir(parents=True,exist_ok=True)
 def put(self,array,kind='input'):
  import numpy as np
  a=np.ascontiguousarray(array)
  require(a.dtype==np.float32 and a.nbytes>0,'actual float32 array required')
  data=a.astype('<f4',copy=False).tobytes(order='C');h=hashlib.sha256(data).hexdigest()
  p=self.pool/('raw_sv' if kind=='raw' else 'inputs')/(h+'.bin')
  if p.exists():
   s=p.stat();stamp=(s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
   if str(p) not in self.checked:
    require(s.st_size==len(data) and sha(p)==h,'existing pool bytes changed');self.checked[str(p)]=stamp
   require(stamp==self.checked[str(p)],'pool changed after physical verification')
  else:
   require(shutil.disk_usage(self.pool).free>=len(data)+self.reserve,'stop before exhausting storage; retain partial stage')
   with p.open('xb') as f:f.write(data);f.flush();os.fsync(f.fileno())
   s=p.stat();self.checked[str(p)]=(s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
  desc=dict(path=str(p.resolve()),bytes=len(data),sha256=h,dtype='<f4',shape=list(a.shape),order='C',storage='study_content_addressed_pool_after_fresh_inference')
  self.index.setdefault(h,desc);return desc

def validate(root=ROOT):
 import formal_policy_core as policies
 root=Path(root);c=read(root/'RUNTIME_CONFIG.json')
 require(c['schema']=='FORMAL_ASR_STAGE_RUNTIME_v1' and c['mode'] in ('bank','timing'),'stage runtime schema')
 require(REQUIRED_FILES<=set(c['files']),'all deployed execution/scientific protocol inputs must be bound')
 require((c['mode']=='bank' and c['repeat']==0) or (c['mode']=='timing' and c['repeat'] in (1,2)),'stage repeat scope')
 for name,h in c['files'].items():
  p=Path(name);require(not p.is_absolute() and '..' not in p.parts and sha(root/p)==h,'bound stage input changed: '+name)
 require(sha(ADAPTER)==c['adapter_sha256']==ADAPTER_SHA and sha(SOURCE/'METHOD_FREEZE.json')==METHOD_SHA,'verified runtime functions binding')
 require(sha(TEACHER)==TEACHER_SHA,'inherited teacher helper changed')
 for name,h in read(SOURCE/'METHOD_FREEZE.json')['code'].items():require(sha(SOURCE/name)==h,'frozen ASR source changed')
 m=read(root/'SOURCE_MANIFEST.json');schedule=read(root/'SCHEDULE.json')
 require(set(m)=={'schema','samples','source_order'} and m['schema']=='FORMAL_ASR_SOURCE_MANIFEST_v1','reference-free source schema')
 roster={s['id']:s for s in m['samples']}
 require(len(roster)==len(m['samples'])>0 and m['source_order']==[s['id'] for s in m['samples']],'literal source roster/order')
 for s in m['samples']:
  require(set(s)==SOURCE_FIELDS and s['recording_id']==s['meeting'],'native source allowlist excludes references/labels')
  require(s['quality_member'] is True and type(s['cost_member']) is bool and (c['mode']=='bank' or s['cost_member'] is True),'preselected timing subset only')
  require(s['channels']==8 and s['sample_rate']==16000 and s['encoding']=='PCM16' and type(s['frames']) is int and s['frames']>0,'actual source geometry')
  require(math.isclose(s['duration_s'],s['frames']/16000,abs_tol=1e-9),'actual source duration')
 expected=policies.BANK_POLICIES if c['mode']=='bank' else policies.POLICIES
 cells=schedule['cells'];seen=set();counts={sid:set() for sid in roster}
 for index,row in enumerate(cells):
  require(row['repeat']==c['repeat'] and row['id'] in roster and row['policy'] in expected,'stage coordinate')
  key=(row['id'],row['policy']);require(key not in seen,'duplicate stage coordinate');seen.add(key);counts[row['id']].add(row['policy'])
 require(len(cells)==len(roster)*len(expected) and all(v==set(expected) for v in counts.values()),'complete fixed stage roster')
 parameters=read(root/'POLICY_PARAMETERS.json');model=read(root/'CHEAP_RF.json')
 require(sha(root/'CHEAP_RF.json')==parameters['rf']['model_sha256'],'RF model binding')
 assignments=read(root/'MIXTURE_ASSIGNMENTS.json')
 lookup={row['id']:row for row in assignments['rows']};require(len(lookup)==len(assignments['rows']) and set(roster)<=set(lookup),'assignments fixed before model outputs')
 for row in lookup.values():
  for name,rules in parameters['mixtures'].items():
   for rule in rules:policies.validate_rule(rule)
   index=row[name]['component_index'];require(type(index) is int and 0<=index<len(rules),'frozen component index')
 pool=Path(c['shared_pool']).resolve();study=Path(c['study_root']).resolve()
 require(pool==study/'raw_pool' and study.is_relative_to(BASE/'spatial_distinct_probe_confirmation_20261016'),'isolated study pool')
 return SimpleNamespace(config=c,manifest=m,schedule=schedule,context=dict(parameters=parameters,rf_model=model,assignments=lookup))

def archive(adapter,out,store,cell,phases,runtime,matrix):
 # Reuse the proven capture/externalization function. Its internal temporary
 # rms_input tag is renamed before any signed calls record is persisted.
 adapted=[dict(p,phase='rms_input') if p['phase']=='primary_input' else p for p in phases]
 adapter.archive_cell(out,store,cell,adapted,runtime,matrix,RAW_BYTES)
 for phase in cell['raw_phases']:
  if phase['phase']=='rms_input':phase['phase']='primary_input'

def run_stage(root,package,adapter,execution,*,initializer=None,source_reader=None):
 root=Path(root);out=root/'native_v1';out.mkdir(exist_ok=False);(out/'sdk').mkdir()
 c=package.config;guard=adapter.guard_context(root,c['expected_boot'])
 runtime=SimpleNamespace();store=SharedTensorStore(c['shared_pool'],c['reserve_bytes'])
 totals={k:0 for k in COUNT_KEYS};done=0;attempted=0;summary=None
 samples={s['id']:s for s in package.manifest['samples']}
 initializer=initializer or adapter.initialize;source_reader=source_reader or adapter.read_source
 try:
  require(shutil.disk_usage(root).free>=c['estimated_additional_bytes']+c['reserve_bytes'],'insufficient planned stage storage')
  dump(out/'PROVENANCE.json',dict(schema='FORMAL_ASR_STAGE_PROVENANCE_v1',mode=c['mode'],repeat=c['repeat'],pid=os.getpid(),
   start_ticks=process_start_ticks(),boot=c['expected_boot'],
   files=c['files'],runtime_config_sha256=sha(root/'RUNTIME_CONFIG.json'),adapter_sha256=ADAPTER_SHA,guard=guard,
   references_available_to_runner=False,shared_pool=c['shared_pool'],storage_reuse='after each fresh real inference only'))
  initializer(runtime,package,out,execution)
  for i,coordinate in enumerate(package.schedule['cells']):
   sample=samples[coordinate['id']];cell=dict(coordinate,cell_index=i,pid=os.getpid(),meeting=sample['meeting'],recording_id=sample['recording_id'],
    source=sample,status='pre_call_failed',new_router_execution=False)
   runtime.support.reset();runtime.model.encoder.reset();runtime.teacher.last=None
   matrix=None;phases=[];caught=None
   try:
    matrix,evidence=source_reader(sample);cell['source_evidence']=evidence
    cell['gate_before']=runtime.teacher.environment_gate(runtime.core,runtime.support);adapter.check_engine(runtime.engine)
    result,phases=execution.execute_cell(matrix,coordinate['policy'],source_id=sample['id'],context=package.context,
     frontends=runtime.frontends,modules=runtime.modules,front=runtime.front,model=runtime.model,engine=runtime.engine,core=runtime.core,teacher_helper=runtime.teacher)
    cell.update(result);adapter.check_engine(runtime.engine);require(cell['status']=='ok','failed real cell: preserve, no automatic retry')
   except BaseException as exc:caught=exc;cell['pre_or_post_call_exception']=error(exc)
   finally:
    if cell.get('teacher') is None and runtime.teacher.last is not None:
     cell['teacher']=runtime.teacher.last
     for key in ('actual_SDK_calls','actual_teacher_policy_calls'):cell[key]=runtime.teacher.last[key]
    cell.setdefault('native_call_events',list(runtime.model.encoder.events))
    archive(adapter,out,store,cell,phases,runtime,matrix)
    cell.setdefault('actual_SV_native_attempts',runtime.model.encoder.attempts);cell.setdefault('actual_SV_native_completed',runtime.model.encoder.completed)
    for key in COUNT_KEYS:totals[key]+=cell.get(key,0)
    try:cell['environment_after']=runtime.teacher.environment(runtime.support)
    except BaseException as exc:cell['environment_after_exception']=error(exc)
    append(out/'calls.jsonl',cell);attempted+=1
   if caught is not None:raise caught
   require(not cell['archive_errors'] and not cell.get('environment_after_exception'),'archive/environment failure must not be silently scored')
   done+=1;print(json.dumps(dict(mode=c['mode'],repeat=c['repeat'],completed_cells=done,expected_cells=len(package.schedule['cells']))),flush=True)
  for name,h in c['files'].items():require(sha(root/name)==h,'bound input changed during stage')
  require(sha(ADAPTER)==ADAPTER_SHA and sha(TEACHER)==TEACHER_SHA,'inherited runtime helper changed during stage')
  summary=dict(schema='FORMAL_ASR_STAGE_EXECUTION_COMPLETE_v1',mode=c['mode'],repeat=c['repeat'],cells=done,failed_cells=0,**totals,
   physical_replay_complete=False,scientific_validation=False,source_N=len(samples))
 except BaseException as exc:
  dump(out/'FAILED.json',dict(**error(exc),completed_cells=done,attempted_cells=attempted,partial_preserved=True,automatic_retry=False));raise
 finally:
  previous={sig:signal.signal(sig,signal.SIG_IGN) for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP)}
  try:
   cleanup=adapter.cleanup_runtime(runtime);dump(out/'CLEANUP.json',cleanup);dump(out/'RAW_INDEX.json',store.index)
  finally:
   for sig,handler in previous.items():signal.signal(sig,handler)
 require(summary is not None and not cleanup['errors'],'incomplete stage or model cleanup failure')
 summary['artifact_sha256']={str(p.relative_to(out)):sha(p) for p in sorted(out.rglob('*')) if p.is_file() and p.name!='COMPLETE.json'}
 dump(out/'COMPLETE.json',summary);return summary

def main():
 import formal_execution_core as execution
 package=validate();adapter=load('verified_T_functions',ADAPTER)
 for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP):signal.signal(sig,adapter.interrupt)
 with LOCK.open('r') as f:
  fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
  run_stage(ROOT,package,adapter,execution)

if __name__=='__main__':main()
