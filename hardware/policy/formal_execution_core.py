"""Fresh response queries and actual causal policy service. Import never runs NN.

Uses the frozen C support with_confidence=False and computes only each policy's
selected metric from its current arrays. No reference, response bank or prior
model output is an input. Caller initializes models, installs ObservedEncoder,
validates source bytes, resets capture support, and archives AFTER wall service.
"""
import time
import traceback
import formal_policy_core as policies
import confidence_metrics_v1 as metrics
from rf_inference_v1 import plain_predict

class ObservedEncoder:
 def __init__(self,encoder):self.encoder=encoder;self.reset()
 def reset(self):self.events=[];self.attempts=0;self.completed=0
 def inference(self,*args,**kwargs):
  event=dict(index=self.attempts,start_monotonic=time.monotonic(),completed=False,exception=None)
  self.events.append(event);self.attempts+=1
  try:
   outputs=self.encoder.inference(*args,**kwargs)
   event.update(output_shapes=[list(x.shape) for x in outputs],output_dtypes=[x.dtype.str for x in outputs],completed=True)
   self.completed+=1;return outputs
  except BaseException as exc:
   event['exception']=dict(type=type(exc).__name__,message=str(exc),traceback=traceback.format_exc());raise
  finally:event['end_monotonic']=time.monotonic()
 def __getattr__(self,key):return getattr(self.encoder,key)

def execute_cell(matrix,policy,*,source_id,context,frontends,modules,front,model,engine,core,teacher_helper):
 import numpy as np
 if policy not in policies.POLICIES+policies.BANK_POLICIES:raise ValueError('literal formal policy required')
 if not isinstance(model.encoder,ObservedEncoder):raise TypeError('own real native-call observer required')
 if matrix.dtype!=np.float32 or matrix.ndim!=2 or matrix.shape[1]!=8 or not len(matrix) or not np.isfinite(matrix).all():
  raise ValueError('finite current 8ch float32 source required')
 if not isinstance(source_id,str) or not source_id:raise ValueError('literal manifest source ID required')
 bank=policy in policies.BANK_POLICIES
 full=policy in ('full_qwen','bank_rms_qwen')
 model.encoder.reset();support=modules['support'];teacher=None;raw_phases=[];error=None
 record=dict(policy=policy,status='in_progress',text='',first=None,probe=None,teacher=None,
  execution_scope='response_bank_query' if bank else 'actual_causal_policy',new_router_execution=not bank,
  model_response_bank_reused_online=False,confidence=None,confidence_measured=False,mean_posterior=None,
  first_empty=None,actions=[],same_waveform=None,mixture_component=None,rf_features=None,predicted_gain=None,
  frontend_s=0.,first_s=0.,first_confidence_s=0.,probe_s=0.,probe_frontend_s=0.,teacher_s=0.,routing_s=0.)
 start=time.monotonic()
 try:
  t=time.monotonic();method='ch0' if policy=='bank_ch0_first' else 'rmsmax'
  mono,diag=frontends.run_frontend(matrix,method=method);record['frontend_s']=time.monotonic()-t
  if mono.dtype!=np.float32 or mono.shape!=(len(matrix),) or diag['output_normalized'] or diag['output_clipped']:
   raise ValueError('raw frozen frontend contract changed')
  record['frontend']=diag
  record['same_waveform']=diag['selected_channel']==0 if method=='rmsmax' else None
  record['identity_basis']=('Current raw rmsmax with smallest-index argmax ties; selected0 gives exact channel0 input'
   if method=='rmsmax' else 'Fixed channel0 response query; RMS/channel0 identity is not assessed by this query')
  raw_phases.append(dict(phase='primary_input',waveform=mono))
  rule=None
  if not bank and policy.startswith('confidence_mix_'):
   t=time.monotonic();assignment=context['assignments'][source_id][policy]
   index=assignment['component_index'];components=context['parameters']['mixtures'][policy]
   if type(index) is not int or not 0<=index<len(components):raise ValueError('precommitted mixture component')
   rule=components[index];policies.validate_rule(rule)
   record['mixture_component']=dict(index=index,rule=rule,assignment=assignment)
   record['routing_s']+=time.monotonic()-t
  if not full:
   before=model.encoder.attempts
   first,arrays,mapped,first_s,unused=support.recognize_small(mono,front,model,with_confidence=False)
   if mapped or unused!=0.:raise ValueError('unused token-span confidence charged')
   record.update(first=first,first_s=first_s)
   raw_phases.append(dict(phase='first',waveform=mono,parts=first['parts'],arrays=arrays,
    first_native_call_index=before,last_native_call_index=model.encoder.attempts))
   if model.encoder.attempts-before!=len(arrays) or len(arrays)!=len(first['parts']):raise ValueError('first native/part occurrence mismatch')
   t=time.monotonic();empty=policies.first_is_empty(first);record['first_empty']=empty;record['routing_s']+=time.monotonic()-t
   if bank:action='first'
   else:
    recipe=policies.recipe_for(policy,rule=rule)
    if recipe is not None and not empty:
     t=time.monotonic();confidence=metrics.compute_confidence(arrays,first['parts'],recipe=recipe)
     record['first_confidence_s']=time.monotonic()-t
     if confidence['always_escalate']:raise ValueError('empty detection disagrees with actual greedy entries')
     record.update(confidence=confidence,confidence_measured=True)
     if recipe in (policies.MEAN,policies.STATISTICS):record['mean_posterior']=confidence['confidence']
    t=time.monotonic()
    if policy=='gain_rf_dev' and not empty:
     features=policies.rf_features(record['confidence'],first['text'],duration_s=len(matrix)/16000,
      channel_rms=diag['channel_rms'],selected_channel=diag['selected_channel'])
     gain=plain_predict(context['rf_model'],features)
     record.update(rf_features=features,predicted_gain=gain)
    rf=context['parameters']['rf']
    kwargs=dict(same_waveform=record['same_waveform'],first_empty=empty,confidence=record['confidence'],rule=rule,
     predicted_gain=record['predicted_gain'],rf_lambda=rf['lambda_edits_per_s'],training_teacher_s=rf['training_teacher_mean_s'])
    action=policies.next_action(policy,first['text'],**kwargs)
    record['routing_s']+=time.monotonic()-t
  else:action='teacher'
  record['actions'].append(action)
  if action=='probe':
   t=time.monotonic();probe_mono=matrix[:,0].copy();record['probe_frontend_s']=time.monotonic()-t
   before=model.encoder.attempts
   probe,arrays,mapped,probe_s,unused=support.recognize_small(probe_mono,front,model,with_confidence=False)
   if mapped or unused!=0.:raise ValueError('unused probe confidence charged')
   record.update(probe=probe,probe_s=probe_s)
   raw_phases.append(dict(phase='probe',waveform=probe_mono,parts=probe['parts'],arrays=arrays,
    first_native_call_index=before,last_native_call_index=model.encoder.attempts))
   if model.encoder.attempts-before!=len(arrays) or len(arrays)!=len(probe['parts']):raise ValueError('probe native/part occurrence mismatch')
   t=time.monotonic();action=policies.next_action(policy,first['text'],probe_text=probe['text'],**kwargs)
   record['routing_s']+=time.monotonic()-t;record['actions'].append(action)
  if action=='teacher':
   teacher=teacher_helper.call_teacher(core,mono,front,model,engine,modules)
   record['teacher_s']=teacher['teacher_microservice_s']
   if teacher['status']!='ok':raise RuntimeError('actual Qwen failed; preserve complete/partial SDK evidence')
   record['text']=teacher['engine_text']
  elif action=='first':record['text']=record['first']['text']
  else:raise ValueError('uncompleted action')
  record['status']='ok'
 except BaseException as exc:
  error=dict(type=type(exc).__name__,message=str(exc),traceback=traceback.format_exc());record['status']='failed';record['exception']=error
 end=time.monotonic()
 record.update(start_monotonic=start,end_monotonic=end,service_s=end-start,teacher=teacher,
  actual_SV_native_attempts=model.encoder.attempts,actual_SV_native_completed=model.encoder.completed,
  actual_SDK_calls=teacher['actual_SDK_calls'] if teacher else 0,
  actual_teacher_policy_calls=teacher['actual_teacher_policy_calls'] if teacher else 0,
  native_call_events=list(model.encoder.events))
 stage_sum=sum(record[k] for k in ('frontend_s','first_s','first_confidence_s','probe_s','probe_frontend_s','teacher_s','routing_s'))
 record['service_minus_stage_sum_s']=record['service_s']-stage_sum
 if error is None and record['service_minus_stage_sum_s']<-.000001:raise ValueError('stage costs exceed wall service')
 return record,raw_phases
