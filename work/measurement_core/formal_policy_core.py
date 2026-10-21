"""Fixed causal policies for response-bank quality and fresh actual cost runs.

No IO, model, reference or response-bank lookup. Mixture assignments are passed
from a file persisted before any new-source NN. RF predictions use first-pass
features only and an old-development cost constant. This is preparation, not an
executed study. Unknown/missing observations fail; successful all-blank first
passes escalate for dynamic arms before any numeric gate.
"""
import math
import unicodedata

POLICIES=('first_only','full_qwen','mean95','distinct_probe_confirmation',
 'always_probe_disagree','legacy_conditional90to95','cheap_sameview_skip',
 'confidence_mix_low','confidence_mix_matched','gain_rf_dev')
BANK_POLICIES=('bank_rms_first','bank_ch0_first','bank_rms_qwen')
MEAN='mean_entry_maxposterior'
ENTROPY='normalized_shannon_entry'
STATISTICS='entry_maxposterior_statistics'

def normalize(text):
 if not isinstance(text,str):raise TypeError('actual text required')
 return ''.join(c for c in unicodedata.normalize('NFKC',text).casefold() if c.isalpha() or c.isdigit())

def finite(value,label):
 if type(value) not in (int,float) or not math.isfinite(value):raise ValueError('finite '+label+' required')
 return value

def validate_rule(rule):
 if not isinstance(rule,dict) or set(rule)!={'recipe','confidence_lt','weight'}:raise ValueError('frozen mixture rule required')
 if rule['recipe'] not in (MEAN,ENTROPY):raise ValueError('unsupported selected recipe')
 if not 0<=finite(rule['confidence_lt'],'threshold')<=2:raise ValueError('threshold range')
 if not 0<=finite(rule['weight'],'weight')<=1:raise ValueError('weight range')

def recipe_for(policy,*,rule=None):
 if policy not in POLICIES:raise ValueError('literal policy required')
 if policy in ('first_only','full_qwen','always_probe_disagree'):return None
 if policy=='gain_rf_dev':return STATISTICS
 if policy.startswith('confidence_mix_'):
  validate_rule(rule);return rule['recipe']
 return MEAN

def first_is_empty(first):
 if not isinstance(first,dict) or not isinstance(first.get('text'),str) or not first.get('parts'):
  raise ValueError('successful current first output/parts required')
 count=0
 for part in first['parts']:
  ids=part['token_ids']
  if not isinstance(ids,list) or any(type(x) is not int or x<=0 for x in ids):raise ValueError('greedy nonblank IDs required')
  count+=len(ids)
 return count==0

def next_action(policy,first_text=None,*,same_waveform=None,first_empty=False,
                confidence=None,probe_text=None,rule=None,predicted_gain=None,
                rf_lambda=None,training_teacher_s=None):
 if policy not in POLICIES:raise ValueError('unknown policy')
 if type(first_empty) is not bool:raise TypeError('successful blank flag required')
 if policy=='full_qwen':
  if first_text is not None or probe_text is not None:raise ValueError('fullQ must not pay a first SV or probe')
  return 'teacher'
 normalize(first_text)
 if policy=='first_only':
  if probe_text is not None:raise ValueError('unrequested probe')
  return 'first'
 if first_empty:
  if probe_text is not None:raise ValueError('blank-first escalation precedes probe')
  return 'teacher'
 if type(same_waveform) is not bool:raise TypeError('current waveform identity required')
 if policy.startswith('confidence_mix_'):
  validate_rule(rule)
  if probe_text is not None:raise ValueError('cheap mixture has no probe')
  if confidence is None or confidence['recipe']!=rule['recipe'] or confidence['always_escalate']:
   raise ValueError('actual selected nonempty recipe required')
  score=finite(confidence['confidence'],'confidence')
  if not 0<=score<=1:raise ValueError('confidence range')
  return 'teacher' if score<rule['confidence_lt'] else 'first'
 if policy=='gain_rf_dev':
  if probe_text is not None:raise ValueError('cheap RF has no probe')
  gain=finite(predicted_gain,'predicted gain');lam=finite(rf_lambda,'RF lambda');cost=finite(training_teacher_s,'old training cost')
  if lam<0 or cost<=0:raise ValueError('frozen RF price/cost')
  return 'teacher' if gain>lam*cost else 'first'
 if policy!='always_probe_disagree':
  if confidence is None or confidence['recipe']!=MEAN or confidence['always_escalate']:
   raise ValueError('actual nonempty mean confidence required')
  mean=finite(confidence['confidence'],'mean')
  if not 0<=mean<=1:raise ValueError('confidence range')
  if policy=='mean95':
   if probe_text is not None:raise ValueError('mean95 has no probe')
   return 'teacher' if mean<.95 else 'first'
  if mean<.90:
   if probe_text is not None:raise ValueError('low confidence needs no probe')
   return 'teacher'
  if mean>=.95:
   if probe_text is not None:raise ValueError('high confidence needs no probe')
   return 'first'
  if policy=='cheap_sameview_skip':
   if probe_text is not None:raise ValueError('free identity control has no probe')
   return 'first' if same_waveform else 'teacher'
  if same_waveform:
   if probe_text is not None:raise ValueError('alias is not an additional observation')
   return 'teacher' if policy=='distinct_probe_confirmation' else 'first'
 elif same_waveform:
  if probe_text is not None:raise ValueError('same waveform cannot need a paid probe')
  return 'first'
 if probe_text is None:return 'probe'
 return 'teacher' if normalize(first_text)!=normalize(probe_text) else 'first'

def rf_features(confidence,first_text,*,duration_s,channel_rms,selected_channel):
 if confidence['recipe']!=STATISTICS or confidence['always_escalate']:raise ValueError('actual nonempty RF statistics required')
 values=[confidence[k] for k in ('mean_confidence','min_confidence','q10_confidence')]
 if any(not 0<=finite(v,'posterior statistic')<=1 for v in values):raise ValueError('posterior range')
 if finite(duration_s,'duration')<=0:raise ValueError('positive duration')
 if type(selected_channel) is not int or not 0<=selected_channel<8:raise ValueError('selected channel')
 if len(channel_rms)!=8 or any(finite(v,'RMS')<0 for v in channel_rms):raise ValueError('eight free channel powers')
 hi,lo=max(channel_rms),min(channel_rms)
 return values+[len(normalize(first_text)),math.log(duration_s),hi/max(lo,1e-12),channel_rms[0]/max(hi,1e-12),int(selected_channel==0)]
