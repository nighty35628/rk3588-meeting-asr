"""Prepared JAES independent mode-block runner. Import/--check-prepared never loads models.

One invocation executes ONE fixed mode block in a new guarded process. No SSH,
retry, resume, schedule generation, references, or automatic round chaining.
"""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import importlib.util
import io
import json
import math
import os
from pathlib import Path
import signal
import sys
import time
import traceback
import resource
import re
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent
BASE = Path('/path/to/local_host/research/qwen-asr-screening/numeric_fidelity_20261014')
FAMILY = 'spatial_distinct_probe_confirmation_20261016'
FORMAL = BASE/FAMILY/'formal_01/timing_01'
ADAPTER = BASE/'spatial_probe_policy_timing_20261016/attempt_01/run_native.py'
C_SOURCE = BASE/'calibration_independent_test_20261016/timing_01'
POLICIES = ('full_qwen','mean95','distinct_probe_confirmation','cheap_sameview_skip','legacy_conditional90to95')
COUNT_KEYS = ('actual_SV_native_attempts','actual_SV_native_completed','actual_SDK_calls','actual_teacher_policy_calls')
EXPECTED_SOURCE_SHA = '179911ef53056b2f52ed9c3c5dce51cd90f694002935e66abe48088839acba33'
EXPECTED_SCHEDULE_SHA = 'cc85a4b241f7650eafcd36e5a8e4f10d835990fb28c562875a56cce9a56b56d6'
EXPECTED_PROTOCOL_SHA = '4fd713afaa4f037ce40c8a0108e13e389b39f79757ba24a02f23c9cda1be933c'
BLOCKS = (('r1_audit',1,'audit'),('r1_minimal',1,'minimal'),('r2_minimal',2,'minimal'),('r2_audit',2,'audit'))
LOCAL_FILES = {'run_native.py','guard_native.py','recording_idle.py','public_guard_identity.py','idle_rpc.py','SOURCE_MANIFEST.json','SCHEDULE.json','MEASUREMENT_PROTOCOL.json'}
WARMUP = dict(id='n013', recording_id='20200706_L_R001S03C01',
    relative_audio='co_resident_development_v2/audio/n013.wav', frames=112331,
    channels=1,sample_rate=16000,encoding='PCM16',
    sha256='22565dd30a9d9490e1498fa8cf44a463f0711ec4735662a0d4a685d06501c8b5',
    pcm_sha256='6c1169ab3e1046d2ff9e9dc768865d455d899fed80c4250b6d8af2a194ff305a',
    development_manifest_sha256='c1cb7193e71c8f7f5c273de914bce1db375fb5660daa009eead4157619b8ca64')


def require(ok,message):
    if not ok:raise ValueError(message)


def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for data in iter(lambda:f.read(1048576),b''):h.update(data)
    return h.hexdigest()


def read(path):
    def pairs(items):
        out={}
        for key,value in items:
            require(key not in out,'duplicate JSON key: '+key);out[key]=value
        return out
    def invalid(x):raise ValueError('nonfinite JSON: '+x)
    return json.loads(Path(path).read_text(),object_pairs_hook=pairs,parse_constant=invalid)


def dump(path,value):
    with Path(path).open('x') as f:
        f.write(json.dumps(value,ensure_ascii=False,indent=2,allow_nan=False)+'\n');f.flush();os.fsync(f.fileno())


def append(path,value):
    with Path(path).open('a') as f:
        f.write(json.dumps(value,ensure_ascii=False,allow_nan=False)+'\n');f.flush();os.fsync(f.fileno())


def error(exc):
    value=dict(type=type(exc).__name__,message=str(exc),traceback=traceback.format_exc())
    if hasattr(exc,'observed_affinity'):value['observed_affinity']=exc.observed_affinity
    return value


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module
    exec(compile(Path(path).read_bytes(),str(path),'exec'),module.__dict__)
    return module




def validate_runtime(root=ROOT):
    root=Path(root).resolve();package=validate_prepared(root);c=read(root/'RUNTIME_CONFIG.json')
    require(c['schema']=='JAES_MODE_BLOCK_RUNTIME_v2','runtime schema')
    require(c['background_profile']=='cleaned_board_no_miner_restore_v1','post-maintenance clean background profile required')
    require(c['guard_identity_profile']=='public_proc_root_receipt_interpreter_file_v1','explicit cross-UID guard identity profile required')
    require(c['idle_gate_profile']=='root_guard_on_demand_idle_v1','positive root on-demand idle gate required')
    require(set(c['files'])==LOCAL_FILES,'bind all runner/guard/study inputs')
    for name,h in c['files'].items():require(sha(root/name)==h,'bound study file changed: '+name)
    core_root=root.parent/'measurement_core'
    require(sha(core_root/'PACKAGE_SHA256.json')==c['core_manifest_sha256'],'measurement core manifest binding')
    for name,h in read(core_root/'PACKAGE_SHA256.json').items():
        require(Path(name).name==name and sha(core_root/name)==h,'bound core file changed: '+name)
    require(len(c['expected_boot'])==36,'fresh board boot required')
    require(Path(c['lock_path'])==BASE/'formal_general_v1/TIMING_VS_RAW_CPU.lock','reuse historical native lock')
    require(Path(c['shared_pool']).resolve()==root/'raw_pool','isolated per-study shared pool')
    require(type(c['reserve_bytes']) is int and c['reserve_bytes']>=0,'storage reserve')
    require(type(c['estimated_additional_bytes']) is int and c['estimated_additional_bytes']>=0,'storage budget')
    require(c['expected_caller_affinity']==[4],'frozen caller affinity [4] readback required')
    require(c['progress_timeout_s']>0,'positive technical progress watchdog')
    require(c.get('child_timeout_s') is None or c['child_timeout_s']>0,'optional technical child timeout')
    require(c['run_user']=='orangepi' and Path(c['python']).is_absolute(),'fixed board user and explicit interpreter')
    pins=read(core_root/'SOURCE_PINS.json')
    def expected(suffix):
        hits=[h for p,h in pins.items() if p.endswith(suffix)];require(len(hits)==1,'unique source pin');return hits[0]
    formal=Path(c.get('formal_stage',str(FORMAL)))
    dep_paths={ADAPTER:expected('/spatial_probe_policy_timing_20261016/attempt_01/run_native.py'),
               BASE/'spatial_probe_teacher_pilot_20261016/attempt_01/run_native.py':expected('/spatial_probe_teacher_pilot_20261016/attempt_01/run_native.py'),
               formal/'run_native.py':expected('/formal_01/timing_01/run_native.py')}
    for path,h in dep_paths.items():require(sha(path)==h,'frozen dependency changed: '+str(path))
    require(sha(C_SOURCE/'METHOD_FREEZE.json')==c['method_freeze_sha256']=='5e9d106e456455937c4ecdf59f3f8ca1728b2e7cfb584877fe71a31711d2272f','C freeze binding')
    require(sha(C_SOURCE/'MODEL_ASSET_BASELINE.json')==c['model_baseline_sha256']=='8295f12f90a1f6301440c14d064d0ff726524211134eed7ed6c6e7efe23547dd','model baseline binding')
    for name,h in read(C_SOURCE/'METHOD_FREEZE.json')['code'].items():
        path=Path(name);require(not path.is_absolute() and '..' not in path.parts,'safe frozen code path')
        require(sha(C_SOURCE/path)==h,'C source changed: '+name)
    # No source WAV or model contents opened here; actual assets are hashed by original initialize.
    package.config=c;package.formal_stage=formal;package.core_root=core_root
    package.bindings=dict(files=c['files'],core_manifest_sha256=c['core_manifest_sha256'],
        runtime_config_sha256=sha(root/'RUNTIME_CONFIG.json'),dependency_sha256={str(k):v for k,v in dep_paths.items()})
    return package


def load_dependencies(package):
    sys.path.insert(0,str(package.core_root.parent))
    import measurement_core as mc
    require(Path(mc.__file__).resolve()==package.core_root/'__init__.py','measurement core import identity')
    adapter=load('jaes_frozen_adapter',ADAPTER)
    formal=load('jaes_frozen_formal',package.formal_stage/'run_native.py')
    return SimpleNamespace(mc=mc,adapter=adapter,formal=formal,context=mc.load_context(package.formal_stage))


def guard_context(root,block_id,attempt_id,expected_boot):
    guard=load('jaes_guard_identity',Path(root)/'guard_native.py')
    stage=stage_path(root,block_id,attempt_id);g=stage/'guard_v1'
    public=load('jaes_public_guard_identity',Path(root)/'public_guard_identity.py')
    paused,protected_receipt=public.read_verified_receipt(g/'PAUSED.json')
    require(paused['boot']==expected_boot==guard.boot_id(),'current guarded boot')
    require(not (g/'RESTORED.json').exists() and not (g/'CHILD_EXIT.json').exists(),'guard already ended')
    require(paused['block_id']==block_id and paused['attempt_id']==attempt_id,'guard block/attempt identity')
    actual=public.verify(paused['guard'],g/'PAUSED.json')
    require(paused['idle_endpoint']['profile']=='root_guard_on_demand_idle_v1'
            and paused['idle_endpoint']['guard_pid']==actual['pid']
            and paused['idle_endpoint']['server_uid']==0,'idle endpoint must be the verified root guard')
    require(guard.same_identity(actual,paused['guard']),'guard PID/start/uid/binary/command identity')
    require(guard.is_ancestor(paused['guard']['pid'],os.getpid()),'guard must be live ancestor')
    cmd=(Path('/proc')/str(actual['pid'])/'cmdline').read_bytes().split(b'\0')
    require(str((Path(root)/'guard_native.py').resolve()).encode() in cmd,'exact guard script ancestor')
    require(paused['idle_before'] and all(x['running'] is False for x in paused['idle_before']),'explicit idle evidence even with zero actors')
    require(paused['inventory_matches_pins'] is True,'fresh reviewed actor inventory')
    for actor in paused['after']:
        now=guard.identity(actor['pid'])
        require(guard.same_identity(now,actor) and now['state'] in ('T','t'),'paused actor identity/state')
    require(len(paused['after'])==len(paused['original']['processes']),'all/zero paused actors bound')
    require(paused['attempt_sha256']==sha(stage/'ATTEMPT.json'),'guard attempt lineage binding')
    native_lock=guard.verify_native_lock(paused['native_lock']['path'],actual['pid'])
    require(Path(native_lock['path'])==BASE/'formal_general_v1/TIMING_VS_RAW_CPU.lock','historical global native lock')
    return dict(boot=expected_boot,guard=actual,actor_count=len(paused['after']),
                native_lock=native_lock,pause_receipt_sha256=protected_receipt['sha256'],protected_receipt=protected_receipt,
                idle_endpoint=paused['idle_endpoint'],
                attempt_sha256=paused['attempt_sha256'],restoration_owner='live parent guard')


def read_warmup(config):
    import numpy as np
    import wave
    path=Path(config.get('warmup_audio',str(BASE/WARMUP['relative_audio'])))
    if not path.is_file():raise FileNotFoundError('TODO deploy fixed existing development n013 WAV: '+str(path))
    data=path.read_bytes();require(hashlib.sha256(data).hexdigest()==WARMUP['sha256'],'fixed development warmup WAV')
    with wave.open(io.BytesIO(data)) as f:
        require(f.getnchannels()==1 and f.getframerate()==16000 and f.getnframes()==WARMUP['frames']
                and f.getsampwidth()==2 and f.getcomptype()=='NONE','warmup PCM geometry')
        pcm=f.readframes(f.getnframes())
    require(hashlib.sha256(pcm).hexdigest()==WARMUP['pcm_sha256'],'warmup PCM hash')
    mono=np.frombuffer(pcm,dtype='<i2').astype(np.float32)/np.float32(32768)
    return mono,dict(WARMUP,audio=str(path),measured_source=False,excluded_from_service=True)


def process_memory():
    """Actual Linux process observation outside service; never infer tensor RSS."""
    try:
        lines=Path('/proc/self/status').read_text().splitlines()
        keep=('VmRSS:','VmHWM:','RssAnon:','RssFile:','VmSwap:')
        return dict(status='observed',units='KiB',fields={x.split(':',1)[0]:int(x.split()[1])
                    for x in lines if x.startswith(keep)},monotonic=time.monotonic())
    except OSError as exc:return dict(status='unavailable',exception=error(exc))


def audit_carryover(view,phases):
    """Logical retained tensor bytes, not an estimate of physical resident pages.

    Only read ndarray headers/identities. No tensor copies, hashing or tobytes.
    Phase outputs alias capture outputs; count each ndarray object once.
    """
    totals=dict(native_input_bytes=0,native_output_bytes=0,waveform_bytes=0,unique_arrays=0)
    seen=set()
    def add(array,key):
        if id(array) not in seen:
            seen.add(id(array));totals[key]+=array.nbytes;totals['unique_arrays']+=1
    if view is not None:
        for event in view.capture.events:
            for array in event['inputs']:add(array,'native_input_bytes')
            for array in event['outputs']:add(array,'native_output_bytes')
        for phase in phases:
            if 'waveform' in phase:add(phase['waveform'],'waveform_bytes')
            for array in phase.get('arrays',[]):add(array,'native_output_bytes')
    totals['total_logical_bytes']=sum(totals[k] for k in ('native_input_bytes','native_output_bytes','waveform_bytes'))
    totals['scope']='retained audit evidence at service entry; logical bytes, not physical RSS'
    return totals


def block_definition(block_id):
    hits=[dict(block_id=b,repeat=r,mode=m) for b,r,m in BLOCKS if b==block_id]
    require(len(hits)==1,'literal block ID required');return hits[0]


def stage_path(root,block_id,attempt_id):
    block_definition(block_id)
    require(isinstance(attempt_id,str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}',attempt_id)
            and attempt_id not in ('.','..'),'safe explicit attempt_id required')
    return Path(root)/'blocks'/block_id/attempt_id


def validate_prepared(root=ROOT):
    root=Path(root)
    for name,h in [('SOURCE_MANIFEST.json',EXPECTED_SOURCE_SHA),('SCHEDULE.json',EXPECTED_SCHEDULE_SHA),('MEASUREMENT_PROTOCOL.json',EXPECTED_PROTOCOL_SHA)]:
        require(sha(root/name)==h,'frozen v2 input changed: '+name)
    m=read(root/'SOURCE_MANIFEST.json');s=read(root/'SCHEDULE.json');p=read(root/'MEASUREMENT_PROTOCOL.json')
    require(set(m)=={'schema','samples','source_order'},'reference-free source manifest')
    roster={x['id']:x for x in m['samples']}
    require(len(roster)==len(m['samples'])==120 and len({x['recording_id'] for x in roster.values()})==30,'120 sources / 30 recordings')
    require(m['source_order']==[x['id'] for x in m['samples']],'fixed source order')
    for x in roster.values():
        require(x['channels']==8 and x['sample_rate']==16000 and x['encoding']=='PCM16' and x['cost_member'] is True,'frozen PCM geometry/membership')
        require(type(x['frames']) is int and x['frames']>0 and math.isclose(x['duration_s'],x['frames']/16000,abs_tol=1e-9),'frame duration')
    require(s['schema']=='JAES_INDEPENDENT_MODE_BLOCK_SCHEDULE_v2' and len(s['rows'])==2400,'v2 2400-cell schedule')
    require(s['blocks']==[block_definition(b) for b,r,mode in BLOCKS],'fixed four-session order')
    sequences={};seen=set()
    for bi,(block_id,repeat,mode) in enumerate(BLOCKS):
        rows=[r for r in s['rows'] if r['block_id']==block_id]
        require(len(rows)==600,'600 cells per block')
        seq=[]
        for j,row in enumerate(rows):
            require(row['cell_index']==bi*600+j and row['block_index']==bi and row['block_position']==j,'block/global positions')
            require(row['repeat']==repeat and row['mode']==mode and row['source_id'] in roster and row['policy'] in POLICIES,'fixed coordinate')
            require(row['recording_id']==roster[row['source_id']]['recording_id'],'recording coordinate')
            require(row['source_position']==j//5 and row['policy_position']==j%5,'within-source policy position')
            require(row['pair_id']==f"{repeat}:{row['source_id']}:{row['policy']}",'offline pair identity')
            key=(block_id,row['source_id'],row['policy']);require(key not in seen,'duplicate coordinate');seen.add(key)
            seq.append((row['source_id'],row['policy']))
        require(set(seq)=={(sid,policy) for sid in roster for policy in POLICIES},'complete per-block grid')
        sequences[block_id]=seq
    require(sequences['r1_audit']==sequences['r1_minimal'],'round1 coordinate alignment')
    require(sequences['r2_minimal']==sequences['r2_audit']==list(reversed(sequences['r1_audit'])),'round2 reversed source-policy order')
    require(p['schedule_sha256']==EXPECTED_SCHEDULE_SHA and p['source_manifest_sha256']==EXPECTED_SOURCE_SHA,'protocol bindings')
    require(p['caller_affinity']['expected']==[4] and p['caller_affinity']['actively_set'] is False,'frozen affinity readback policy')
    require(WARMUP['recording_id'] not in {x['recording_id'] for x in roster.values()},'development warmup disjoint recordings')
    return SimpleNamespace(manifest=m,schedule=s,protocol=p,roster=roster)


def validate_attempt_parent(root,block_id,attempt_id,parent_failure):
    """Call under study/global lock before creating a new attempt directory."""
    directory=Path(root)/'blocks'/block_id;stage=stage_path(root,block_id,attempt_id)
    require(not stage.exists(),'attempt already exists; never overwrite/resume')
    prior=[x for x in directory.iterdir() if x.is_dir()] if directory.exists() else []
    require(not any((x/'guard_v1/GUARD_COMPLETE.json').exists() for x in prior),'completed block cannot be repeated for a slow value')
    if not prior:
        require(parent_failure is None,'first attempt has no parent_failure');return None
    require(parent_failure is not None,'new whole-block attempt requires explicit technical parent_failure')
    parent=Path(parent_failure).resolve()
    require(parent.is_file() and parent.name=='FAILED.json' and parent.is_relative_to(directory.resolve()),'parent must be retained FAILED.json in same block')
    failure=read(parent)
    require(failure.get('technical_failure') is True and failure.get('block_id')==block_id,'technical same-block failure lineage')
    old_stage=directory/failure['attempt_id']
    require(parent.is_relative_to(old_stage.resolve()),'failure path/attempt identity')
    require(all((x/'ATTEMPT.json').exists() for x in prior),'unresolved prior attempt directory')
    latest=max(prior,key=lambda x:read(x/'ATTEMPT.json')['created_unix'])
    require(old_stage.resolve()==latest.resolve(),'parent_failure must link latest failed attempt; do not skip attempts')
    return dict(path=str(parent),sha256=sha(parent),attempt_id=failure['attempt_id'],technical_failure=True)


def caller_affinity(expected=(4,)):
    actual=sorted(os.sched_getaffinity(0))
    if actual!=list(expected):
        exc=RuntimeError(f'caller affinity readback={actual}; expected {list(expected)}; no mask changed')
        exc.observed_affinity=actual;raise exc
    return actual


def thread_inventory(phase,expected=(4,),strict=None):
    """Read TID masks; SDK threads need not share the Python caller's [4]."""
    if strict is None:strict=phase!='before_initialization'
    caller=caller_affinity(expected) if strict else sorted(os.sched_getaffinity(0))
    threads=[]
    for task in sorted(Path('/proc/self/task').iterdir(),key=lambda p:int(p.name)):
        try:
            fields={x.split(':',1)[0]:x.split(':',1)[1].strip() for x in (task/'status').read_text().splitlines() if ':' in x}
            threads.append(dict(tid=int(task.name),name=fields.get('Name'),
                allowed_list=fields.get('Cpus_allowed_list'),allowed_hex=fields.get('Cpus_allowed'),
                affinity=sorted(os.sched_getaffinity(int(task.name)))))
        except (FileNotFoundError,ProcessLookupError):threads.append(dict(tid=int(task.name),vanished_during_read=True))
    return dict(phase=phase,monotonic=time.monotonic(),caller_affinity=caller,threads=threads,
                sdk_requested_cpu_mask='0xF0',actively_changed_mask=False,
                caller_expected=list(expected),strict_caller_check=strict)


def observation(runtime,expected=(4,)):
    affinity=caller_affinity(expected);memory=process_memory()
    sample_begin=time.monotonic();usage=resource.getrusage(resource.RUSAGE_SELF);sample_end=time.monotonic()
    env=runtime.teacher.environment(runtime.support)
    require(memory['status']=='observed','Linux RSS/Swap observation required')
    require(env['temperatures'] and all(math.isfinite(x) for x in env['temperatures'].values()),'finite after/before-service environment required')
    return dict(monotonic=time.monotonic(),environment=env,memory=memory,caller_affinity=affinity,
        rusage_read_interval_monotonic=[sample_begin,sample_end],
        faults=dict(minor=usage.ru_minflt,major=usage.ru_majflt,swap_ops=usage.ru_nswap))


def observation_envelope_fault_delta(before,after):
    return {k:after['faults'][k]-before['faults'][k] for k in ('minor','major','swap_ops')}


def assert_no_audit_evidence(runtime):
    require(runtime.measurement_mode=='minimal' and not runtime.capture.events
            and not runtime._measurement_original.support.stages,
            'minimal process must never create audit evidence arrays')


def sdk_affinity_request(runtime):
    decoder=runtime.engine.decoder;module=sys.modules[type(decoder).__module__]
    require(decoder._params['enabled_cpus']==4 and module.CPU_MASKS[4]==0xF0,'frozen SDK requested CPU mask 0xF0')
    return dict(enabled_cpus=4,requested_cpu_mask='0xF0',actual_threads='see TID inventories; request is not readback')


def release_owners(runtime,deps,mode):
    deps.mc.configure_mode(runtime,mode)
    if mode=='minimal':assert_no_audit_evidence(runtime)


def archive_cell(deps,out,store,cell,phases,view,matrix,mode):
    if mode=='audit':
        deps.formal.archive(deps.adapter,out,store,cell,phases,view,matrix)
        require(not cell['archive_errors'],'audit archive errors; retain technical failure')
    else:
        require(not phases and view is None,'minimal cannot own audit raw phases/view')
        cell.update(raw_phases=[],native_observations=[],archive_errors=[],raw_evidence_capture=False)


def warmup(runtime,deps,config,out,mode,store,heartbeat):
    """Only this block's mode: n013 SV then Qwen, exactly once each."""
    require(runtime.measurement_mode==mode,'configure block mode BEFORE warmup')
    mono,source=read_warmup(config);phases=[];view=None;arrays=[];caught=None
    warm_dir=Path(out)/'warmup';warm_dir.mkdir();(warm_dir/'sdk').mkdir()
    row=dict(cell_index=-1,mode=mode,source=source,status='in_progress',order=['SV','Qwen'],measured_cell=False)
    try:
        runtime.support.reset();runtime.model.encoder.reset();runtime.teacher.last=None
        row['gate']=runtime.teacher.environment_gate(runtime.core,runtime.support)
        phases=[dict(phase='primary_input',waveform=mono)] if mode=='audit' else []
        heartbeat('warmup_SV_start')
        first,arrays,mapped,seconds,unused=runtime.support.recognize_small(mono,runtime.front,runtime.model,with_confidence=False)
        row.update(first=first,first_s=seconds)
        if mode=='audit':phases.append(dict(phase='first',waveform=mono,parts=first['parts'],arrays=arrays))
        else:arrays.clear();assert_no_audit_evidence(runtime)
        heartbeat('warmup_Qwen_start')
        row['teacher']=runtime.teacher.call_teacher(runtime.core,mono,runtime.front,runtime.model,runtime.engine,runtime.modules)
        require(not mapped and unused==0. and row['teacher']['status']=='ok','fixed same-mode warmup failed')
        deps.adapter.check_engine(runtime.engine);row['status']='ok'
    except BaseException as exc:
        caught=exc;row.update(status='failed',exception=error(exc))
    finally:
        row.update(actual_SV_native_attempts=runtime.model.encoder.attempts,actual_SV_native_completed=runtime.model.encoder.completed)
        if runtime.teacher.last is not None:row.setdefault('teacher',runtime.teacher.last)
        try:
            if mode=='audit':view=deps.mc.audit_archive_view(runtime)
            archive_cell(deps,warm_dir,store,row,phases,view,None,mode)
        except BaseException as exc:
            row['archive_exception']=error(exc)
            if caught is None:caught=exc
        finally:
            dump(Path(out)/'WARMUP.json',dict(mode=mode,source=source,rows=[row],warmup_sequences=1,
                 cross_mode_warmup=False,measured_cells=False))
            phases.clear();arrays.clear();view=None;mono=None
            release_owners(runtime,deps,mode)
    if caught is not None:raise caught
    heartbeat('warmup_complete')


def write_heartbeat(stage,block_id,attempt_id,seq,event,cell_index=None):
    value=dict(block_id=block_id,attempt_id=attempt_id,seq=seq,event=event,
               cell_index=cell_index,pid=os.getpid(),unix=time.time(),monotonic=time.monotonic())
    path=Path(stage)/'HEARTBEAT.json';temporary=path.with_suffix('.tmp')
    with temporary.open('w') as f:f.write(json.dumps(value)+'\n');f.flush();os.fsync(f.fileno())
    temporary.replace(path)


def run_block(root,block_id,attempt_id,package,*,deps=None,initializer=None,source_reader=None,
              environment_gate=None,warmup_fn=None,observe_fn=None,threads_fn=None,
              guard_receipt=None,cleanup_fn=None):
    """One fresh fixed-mode runtime. CLI requires live guard; seams are test-only."""
    import shutil
    definition=block_definition(block_id);mode=definition['mode'];root=Path(root)
    stage=stage_path(root,block_id,attempt_id);attempt=read(stage/'ATTEMPT.json')
    require(attempt['block_id']==block_id and attempt['attempt_id']==attempt_id,'attempt identity')
    out=stage/'native_v1';out.mkdir(exist_ok=False);(out/'sdk').mkdir()
    deps=deps or load_dependencies(package);runtime=SimpleNamespace();c=package.config
    store=deps.formal.SharedTensorStore(c['shared_pool'],c['reserve_bytes']) if mode=='audit' else None
    if initializer is None:
        rpc=load('jaes_positive_idle_rpc',root/'idle_rpc.py')
        initializer=lambda r:rpc.initialize_with_idle(deps.mc,r,package,out,deps.adapter,mode,guard_receipt['idle_endpoint'])
    source_reader=source_reader or deps.adapter.read_source
    environment_gate=environment_gate or (lambda r:r.teacher.environment_gate(r.core,r.support))
    observe_fn=observe_fn or (lambda r:observation(r,c['expected_caller_affinity']))
    threads_fn=threads_fn or (lambda phase:thread_inventory(phase,c['expected_caller_affinity']))
    cleanup_fn=cleanup_fn or deps.adapter.cleanup_runtime
    seq=0
    def heartbeat(event,cell_index=None):
        nonlocal seq
        seq+=1;write_heartbeat(stage,block_id,attempt_id,seq,event,cell_index)
    warmup_fn=warmup_fn or (lambda r:warmup(r,deps,c,out,mode,store,heartbeat))
    rows=[r for r in package.schedule['rows'] if r['block_id']==block_id]
    require(rows,'nonempty fixed block')
    completed=attempted=0;totals={k:0 for k in COUNT_KEYS};summary=None;caught=None;cleanup=None
    try:
        require(shutil.disk_usage(root).free>=c['reserve_bytes']+c['estimated_additional_bytes'],'planned disk reserve')
        dump(out/'PROVENANCE.json',dict(schema='JAES_MODE_BLOCK_PROVENANCE_v2',**definition,attempt=attempt,
            pid=os.getpid(),guard=guard_receipt,bindings=package.bindings,warmup=WARMUP,
            prepared_not_board_verified=True,references_available_to_runner=False,
            mode_difference_has_timeblock_confounding=True))
        heartbeat('before_initialization');append(out/'THREAD_MASKS.jsonl',threads_fn('before_initialization'))
        receipt=initializer(runtime);require(runtime.measurement_mode==mode,'initializer must configure own mode before any inference')
        receipt['sdk_affinity_request']=sdk_affinity_request(runtime)
        if mode=='minimal':assert_no_audit_evidence(runtime)
        dump(out/'MODE_INITIALIZATION.json',receipt)
        warmup_fn(runtime);append(out/'THREAD_MASKS.jsonl',threads_fn('after_warmup'))
        for position,row in enumerate(rows):
            cell=dict(row,attempt_id=attempt_id,parent_failure=attempt['parent_failure'],pid=os.getpid(),
                      status='pre_call_failed',text='',actions=[],first_measured_request=(position==0),
                      mode_difference_has_timeblock_confounding=True)
            cell.update({k:0 for k in COUNT_KEYS})
            phases=[];view=None;matrix=None;cell_error=None;entered=False;returned=False;after=None
            heartbeat('cell_start',row['cell_index'])
            try:
                matrix,evidence=source_reader(package.roster[row['source_id']]);cell['source_evidence']=evidence
                release_owners(runtime,deps,mode)  # always the SAME mode
                cell['gate_before']=environment_gate(runtime);deps.adapter.check_engine(runtime.engine)
                before=observe_fn(runtime);cell['before_service']=before
                if position==0:append(out/'THREAD_MASKS.jsonl',threads_fn('first_cell_before'))
                if position==len(rows)-1:append(out/'THREAD_MASKS.jsonl',threads_fn('last_cell_before'))
                entered=True
                result,phases=deps.mc.execute(runtime,matrix,row['policy'],source_id=row['source_id'],context=deps.context)
                cell.update(result);returned=True
                require(cell['status']=='ok','cell failed; stop entire block without retry')
            except BaseException as exc:
                cell_error=exc;cell['execution_exception']=error(exc)
            finally:
                try:
                    if entered:
                        after=observe_fn(runtime);cell['after_service']=after
                        cell['observation_envelope_fault_delta']=observation_envelope_fault_delta(before,after)
                        cell['observation_envelope_fault_boundary']=dict(
                            before_rusage_read_interval_monotonic=before['rusage_read_interval_monotonic'],
                            after_rusage_read_interval_monotonic=after['rusage_read_interval_monotonic'],
                            scope='before/after rusage read difference; includes residual before-observation, boundary TID reads, ASR service, and initial after-observation work',
                            pure_inference_faults=False,allocated_swap_is_not_active_paging=True)
                        if position==0:append(out/'THREAD_MASKS.jsonl',threads_fn('first_cell_after'))
                        if position==len(rows)-1:append(out/'THREAD_MASKS.jsonl',threads_fn('last_cell_after'))
                except BaseException as exc:
                    cell['after_service_observation_error']=error(exc)
                    if cell_error is None:cell_error=exc
                if entered:
                    if cell.get('teacher') is None and runtime.teacher.last is not None:cell['teacher']=runtime.teacher.last
                    for key in COUNT_KEYS:
                        default=(getattr(runtime.model.encoder,'attempts',0) if key==COUNT_KEYS[0] else
                                 getattr(runtime.model.encoder,'completed',0) if key==COUNT_KEYS[1] else (runtime.teacher.last or {}).get(key,0))
                        if not returned:cell[key]=default
                        totals[key]+=cell[key]
                try:
                    if mode=='audit':view=deps.mc.audit_archive_view(runtime)
                    cell['retained_audit_evidence_before_archive']=audit_carryover(view,phases)
                    heartbeat('cell_archive_start',row['cell_index'])
                    archive_cell(deps,out,store,cell,phases,view,matrix,mode)
                except BaseException as exc:
                    cell['archive_exception']=error(exc)
                    if cell_error is None:cell_error=exc
                finally:
                    if cell_error is not None:cell['technical_failure']=True
                    append(out/'calls.jsonl',cell);attempted+=1
                    phases.clear();view=None;matrix=None
                    release_owners(runtime,deps,mode)
            if cell_error is not None:raise cell_error
            completed+=1;heartbeat('cell_complete',row['cell_index'])
            print(json.dumps(dict(block_id=block_id,attempt_id=attempt_id,completed_cells=completed,expected_cells=len(rows))),flush=True)
        if getattr(package,'verify_end',True):
            end=validate_runtime(root)
            require(end.config==package.config and end.bindings==package.bindings,'code/runtime bindings changed during block')
            require(guard_receipt['attempt_sha256']==sha(stage/'ATTEMPT.json'),'attempt lineage changed during block')
        summary=dict(schema='JAES_MODE_BLOCK_EXECUTION_COMPLETE_v2',**definition,attempt_id=attempt_id,
            parent_failure=attempt['parent_failure'],pid=os.getpid(),cells=completed,failed_cells=0,**totals,
            bindings=package.bindings,physical_replay_complete=False,scientific_validation=False,
            guard_restoration_pending=True,never_audit_inference=(mode=='minimal'))
    except BaseException as exc:
        caught=exc;dump(out/'FAILED.json',dict(**error(exc),block_id=block_id,attempt_id=attempt_id,
            parent_failure=attempt['parent_failure'],technical_failure=True,completed_cells=completed,
            attempted_cells=attempted,automatic_retry=False,partial_preserved=True))
    finally:
        previous={sig:signal.signal(sig,signal.SIG_IGN) for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP)}
        try:
            heartbeat_error=None
            try:heartbeat('model_cleanup_start')
            except BaseException as exc:heartbeat_error=error(exc)
            try:cleanup=cleanup_fn(runtime)
            except BaseException as exc:cleanup=dict(errors=[error(exc)])
            if heartbeat_error is not None:
                cleanup['errors'].append(dict(stage='cleanup_heartbeat',**heartbeat_error))
            dump(out/'CLEANUP.json',cleanup);dump(out/'RAW_INDEX.json',store.index if store else {})
        finally:
            for sig,handler in previous.items():signal.signal(sig,handler)
    if caught is not None:raise caught
    if summary is None or cleanup is None or cleanup['errors']:
        dump(out/'FAILED.json',dict(type='ModelCleanupFailure',cleanup=cleanup,block_id=block_id,
            attempt_id=attempt_id,parent_failure=attempt['parent_failure'],technical_failure=True,
            completed_cells=completed,attempted_cells=attempted,automatic_retry=False))
        raise RuntimeError('model cleanup failed; no COMPLETE')
    summary['artifact_sha256']={str(p.relative_to(out)):sha(p) for p in sorted(out.rglob('*')) if p.is_file() and p.name!='COMPLETE.json'}
    dump(out/'COMPLETE.json',summary)
    dump(stage/'STAGE_COMPLETE.json',dict(block_id=block_id,attempt_id=attempt_id,summary_path='native_v1/COMPLETE.json',
        sha256=sha(out/'COMPLETE.json'),execution_only=True,guard_restoration_pending=True))
    heartbeat('block_complete');return summary


def compare_completed_blocks(root,selection):
    """Offline only, after FOUR whole attempts; never splice individual cells."""
    root=Path(root);package=validate_prepared(root)
    require(set(selection)=={b for b,r,m in BLOCKS},'select exactly four complete block attempts')
    chosen={};common=None;attempts=[]
    for block_id,repeat,mode in BLOCKS:
        attempt_id=selection[block_id];stage=stage_path(root,block_id,attempt_id)
        completed_attempts=list(stage.parent.glob('*/guard_v1/GUARD_COMPLETE.json'))
        require(len(completed_attempts)==1 and completed_attempts[0].parent.parent==stage,'exactly one complete whole-block attempt; no slow-value selection')
        guard=read(stage/'guard_v1/GUARD_COMPLETE.json');complete=read(stage/'native_v1/COMPLETE.json')
        require(guard['block_id']==block_id and guard['attempt_id']==attempt_id,'guard whole-attempt identity')
        require(guard['child_exit_code']==0 and guard['attempt_sha256']==sha(stage/'ATTEMPT.json') and
                guard['paused_sha256']==sha(stage/'guard_v1/PAUSED.json'),'guard attempt/pause receipt binding')
        require(complete['parent_failure']==read(stage/'ATTEMPT.json')['parent_failure'],'attempt parent lineage')
        require(guard['stage_complete_sha256']==sha(stage/'STAGE_COMPLETE.json'),'guard/stage binding')
        stage_receipt=read(stage/'STAGE_COMPLETE.json')
        require(complete['block_id']==stage_receipt['block_id']==block_id and
                complete['attempt_id']==stage_receipt['attempt_id']==attempt_id and
                complete['mode']==mode and complete['repeat']==repeat,'complete block identity')
        require(stage_receipt['sha256']==sha(stage/'native_v1/COMPLETE.json'),'stage/complete binding')
        require(guard['restored_sha256']==sha(stage/'guard_v1/RESTORED.json'),'guard restoration receipt binding')
        for name,h in complete['artifact_sha256'].items():
            rel=Path(name);require(not rel.is_absolute() and '..' not in rel.parts,'safe artifact path')
            require(sha(stage/'native_v1'/rel)==h,'whole-block artifact changed')
        require(complete['cells']==600 and complete['failed_cells']==0 and not read(stage/'native_v1/CLEANUP.json')['errors'],'complete 600-cell cleanup required')
        require(read(stage/'guard_v1/RESTORED.json')['all_restored'],'guard restoration required')
        binding={k:v for k,v in complete['bindings'].items() if k!='runtime_config_sha256'}
        require(binding['files']=={name:sha(root/name) for name in LOCAL_FILES},'current frozen study code/input bindings')
        require(binding['core_manifest_sha256']==sha(root.parent/'measurement_core/PACKAGE_SHA256.json'),'current frozen measurement core binding')
        if common is None:common=binding
        require(common==binding,'four blocks must use common scientific code/protocol bindings')
        calls=[json.loads(line) for line in (stage/'native_v1/calls.jsonl').read_text().splitlines()]
        expected=[r for r in package.schedule['rows'] if r['block_id']==block_id]
        require(len(calls)==len(expected)==600,'whole attempt, no cell-level selection')
        warm=read(stage/'native_v1/WARMUP.json')
        require(warm['mode']==mode and warm['warmup_sequences']==1 and warm['cross_mode_warmup'] is False and
                len(warm['rows'])==1 and warm['rows'][0]['mode']==mode,'own-mode warmup only')
        phases=[read_value['phase'] for read_value in (json.loads(x) for x in (stage/'native_v1/THREAD_MASKS.jsonl').read_text().splitlines())]
        require(phases==['before_initialization','after_warmup','first_cell_before','first_cell_after','last_cell_before','last_cell_after'],'required thread inventories')
        for row,want in zip(calls,expected):
            require(row['attempt_id']==attempt_id and row['status']=='ok' and not row.get('technical_failure'),'valid complete attempt cells')
            require(all(row[k]==want[k] for k in ('block_id','source_id','policy','repeat','mode','cell_index','block_position')),'literal full block order')
            require(row['before_service']['caller_affinity']==row['after_service']['caller_affinity']==[4],'frozen measured caller affinity')
            require(set(row['observation_envelope_fault_delta'])=={'minor','major','swap_ops'},'per-cell observation-envelope fault counts')
            if mode=='minimal':require(row['retained_audit_evidence_before_archive']['total_logical_bytes']==0 and
                not row['raw_phases'] and not row['native_observations'],'minimal must be free of audit evidence')
            chosen[(repeat,mode,row['source_id'],row['policy'])]=row
        attempts.append(dict(block_id=block_id,attempt_id=attempt_id,parent_failure=complete['parent_failure']))
    mismatches=[];fields=('text','actions','confidence','first_empty')+COUNT_KEYS
    for repeat in (1,2):
        for sid in package.roster:
            for policy in POLICIES:
                a=chosen[(repeat,'audit',sid,policy)];b=chosen[(repeat,'minimal',sid,policy)]
                diffs=[key for key in fields if a.get(key)!=b.get(key)]
                if diffs:mismatches.append(dict(repeat=repeat,source_id=sid,policy=policy,differing_fields=diffs))
    return dict(schema='JAES_OFFLINE_MODE_BLOCK_CHECK_v2',selected_whole_attempts=attempts,cells=2400,matched_pairs=1200,
        mode_parity_equal=not mismatches,mismatches=mismatches,primary='within-minimal D-M / D-C / M-Q',
        mode_difference_has_timeblock_confounding=True,pure_audit_overhead_claim=False,scientific_validation=False)


def contract(root=ROOT):
    return dict(schema='JAES_MODE_BLOCK_RUNTIME_v2',expected_boot='FRESH_BOARD_BOOT_REQUIRED',
        files={name:'SHA256_REQUIRED' for name in sorted(LOCAL_FILES)},
        core_manifest_sha256='SHA256_OF_SIBLING_measurement_core/PACKAGE_SHA256.json',
        lock_path=str(BASE/'formal_general_v1/TIMING_VS_RAW_CPU.lock'),formal_stage=str(FORMAL),
        shared_pool=str(Path(root)/'raw_pool'),reserve_bytes=12*1024**3,estimated_additional_bytes=8*1024**3,
        python='/path/to/local_host/meeting-asr-qwen3/.venv/bin/python',run_user='orangepi',
        method_freeze_sha256='5e9d106e456455937c4ecdf59f3f8ca1728b2e7cfb584877fe71a31711d2272f',
        model_baseline_sha256='8295f12f90a1f6301440c14d064d0ff726524211134eed7ed6c6e7efe23547dd',
        warmup_audio=str(BASE/WARMUP['relative_audio']),expected_caller_affinity=[4],
        progress_timeout_s=5400,child_timeout_s=None,background_profile='cleaned_board_no_miner_restore_v1',
        guard_identity_profile='public_proc_root_receipt_interpreter_file_v1',idle_gate_profile='root_guard_on_demand_idle_v1')


def interrupt(signum,frame):raise InterruptedError('runner signal '+str(signum))


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--block',choices=[x[0] for x in BLOCKS])
    ap.add_argument('--attempt');ap.add_argument('--root',type=Path,default=ROOT)
    ap.add_argument('--check-prepared',action='store_true');ap.add_argument('--check',action='store_true')
    ap.add_argument('--check-affinity',action='store_true');ap.add_argument('--contract',action='store_true')
    ap.add_argument('--compare-blocks',type=Path,metavar='SELECTION_JSON')
    a=ap.parse_args();root=a.root.resolve()
    if a.contract:print(json.dumps(contract(root),indent=2));return
    if a.check_prepared:
        p=validate_prepared(root);print(json.dumps(dict(status='PREPARED_NOT_BOARD_EXECUTED',sources=len(p.roster),cells=2400,blocks=p.schedule['blocks'])));return
    if a.check_affinity:print(json.dumps(thread_inventory('readback_only_preflight',strict=False)));return
    if a.compare_blocks:print(json.dumps(compare_completed_blocks(root,read(a.compare_blocks)),indent=2));return
    package=validate_runtime(root)
    if a.check:print(json.dumps(dict(status='metadata_checked_NO_MODELS_LOADED',bindings=package.bindings)));return
    require(a.block is not None and a.attempt is not None,'explicit --block and --attempt required')
    for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP):signal.signal(sig,interrupt)
    context=guard_context(root,a.block,a.attempt,package.config['expected_boot'])
    run_block(root,a.block,a.attempt,package,guard_receipt=context)


if __name__=='__main__':main()
