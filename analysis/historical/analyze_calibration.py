#!/usr/bin/env python3
"""Receipt-gated calibration CPU/text analysis. Imports are inert and stdlib-only.

No native/model imports, subprocesses, network, audio, or tensor reads. Physical
replay is the board auditor's responsibility. This file checks its byte bindings.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import io
import json
import math
from pathlib import Path
import re
import sys
import unicodedata

import calibration_rules as rules

VERSION = 'calibration-text-analysis-v1'
HERE = Path(__file__).resolve().parent
POLICIES = rules.POLICIES
MODES = ('primary_casefold', 'case_preserved_sensitivity')
PRIMARY = tuple(map(tuple, rules.PRIMARY_COMPARISONS))
SECONDARY = (('ch0_sense', 'rms_sense'), ('ch0_sense', 'ev_sense'),
             ('cal_energy_sense', 'ch0_sense'), ('cal_label_sense', 'ch0_sense'))
SCORE_KEYS = ('reference_characters', 'errors', 'substitutions', 'deletions', 'insertions')
EARLY_LATE = ('Test source start compared to midpoint of C1 end and actual original recording end; '
              'not midpoint of selected clips')
PANEL_RULE = 'linear empirical duration quantile q*(n-1); nearest frames, then ID; distinct'
GUARD_EXES = {'9f254b99cff3f0746293056030436599ea5dc24972f92866e78c89b38024084a',
              '20035a10c75fae1ba4bc060f2d9e86a1eca13cab1c6a99462a87a8a79a75928e'}


class Rejected(ValueError):
    pass


def need(ok, message):
    if not ok:
        raise Rejected(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def pin(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def finite(value, nonnegative=True):
    return type(value) in (int, float) and math.isfinite(value) and (not nonnegative or value >= 0)


def close(a, b, tolerance=1e-8):
    return finite(a, False) and finite(b, False) and abs(a-b) <= tolerance


def parse(text):
    def unique(pairs):
        out = {}
        for k, v in pairs:
            need(k not in out, 'duplicate JSON key: '+k)
            out[k] = v
        return out
    def invalid(value):
        raise Rejected('nonfinite JSON: '+value)
    def number(value):
        result = float(value)
        need(math.isfinite(result), 'nonfinite JSON number: '+value)
        return result
    return json.loads(text, object_pairs_hook=unique, parse_constant=invalid, parse_float=number)


class Evidence:
    """Read explicit metadata/code only; never follow source/payload/model paths."""
    def __init__(self):
        self.hashes, self.absent, self.inventories = {}, set(), {}

    def read(self, path, expected=None):
        path = Path(path).absolute()
        need(not path.is_symlink() and path.is_file(), 'regular input required: '+str(path))
        need(path.suffix in ('.json', '.jsonl', '.log', '.py', '.md'), 'payload read refused: '+str(path))
        raw = path.read_bytes()
        value = digest(raw)
        need(expected is None or (pin(expected) and value == expected), 'hash mismatch: '+str(path))
        need(str(path) not in self.hashes or self.hashes[str(path)] == value, 'input changed: '+str(path))
        self.hashes[str(path)] = value
        return raw

    def load(self, path, expected=None):
        return parse(self.read(path, expected).decode('utf-8'))

    def lines(self, path, expected=None):
        text = self.read(path, expected).decode('utf-8')
        need(not text or text.endswith('\n'), 'partial JSONL: '+str(path))
        need(all(x.strip() for x in text.splitlines()), 'blank JSONL row')
        return [parse(x) for x in text.splitlines()]

    def missing(self, path):
        path = Path(path).absolute()
        need(not path.exists() and not path.is_symlink(), 'failed/ambiguous attempt: '+str(path))
        self.absent.add(str(path))

    def inventory(self, root):
        names = metadata_names(root)
        self.inventories[str(root)] = names
        return names

    def stable(self):
        for name, value in list(self.hashes.items()):
            self.read(Path(name), value)
        for name in list(self.absent):
            self.missing(Path(name))
        for root, names in self.inventories.items():
            need(metadata_names(Path(root)) == names, 'metadata inventory changed: '+root)


def member(root, name):
    need(isinstance(name, str) and not Path(name).is_absolute(), 'relative member required')
    path = root / name
    need(path != root and path.resolve().is_relative_to(root.resolve()) and
         all(part not in ('..', '.') for part in Path(name).parts), 'unsafe metadata member: '+name)
    need(not any(p.is_symlink() for p in [path, *path.parents] if p != root.parent), 'symlink input refused')
    return path


def metadata_names(root):
    """Same text inventory as metadata_materials(); no payload directory traversal."""
    names = set()
    for sub in ('native_v1', 'guard_v1', 'native_v1/decisions'):
        directory = root/sub
        need(directory.is_dir() and not directory.is_symlink(), 'missing metadata directory: '+str(directory))
        names.update(str(p.relative_to(root)) for p in directory.iterdir()
                     if p.is_file() and p.suffix in ('.json', '.jsonl', '.log'))
    names.update(n for n in ('LAUNCH.json', 'LAUNCH_CLAIM.json', 'controller.log') if (root/n).exists())
    return names


def normalize(text, casefold=True):
    need(isinstance(text, str), 'text must be a string')
    text = unicodedata.normalize('NFKC', text)
    if casefold:
        text = text.casefold()
    return ''.join(c for c in text if c.isalpha() or c.isdigit())


def edit_counts(reference, hypothesis):
    """Levenshtein alignment, exact K contract: diagonal, deletion, insertion ties."""
    previous = [(j, 0, 0, j) for j in range(len(hypothesis)+1)]
    for i, a in enumerate(reference, 1):
        current = [(i, 0, i, 0)]
        for j, b in enumerate(hypothesis, 1):
            d, s, rem, ins = previous[j-1]
            diagonal = (d+(a != b), s+(a != b), rem, ins)
            d, s, rem, ins = previous[j]
            deletion = (d+1, s, rem+1, ins)
            d, s, rem, ins = current[j-1]
            insertion = (d+1, s, rem, ins+1)
            current.append(min((diagonal, deletion, insertion), key=lambda x: x[0]))
        previous = current
    errors, s, d, i = previous[-1]
    need(errors == s+d+i, 'S/D/I sum')
    return dict(errors=errors, substitutions=s, deletions=d, insertions=i)


def load_package(ev, prepared, repeat):
    freeze = ev.load(prepared/'METHOD_FREEZE.json')
    manifest = ev.load(prepared/'manifest.json', freeze['manifest_sha256'])
    labels = ev.load(prepared/'CALIBRATION_LABELS.json', freeze['calibration_labels_sha256'])
    rules.validate_metadata(manifest, freeze, labels)  # pure metadata; NOT validate_package/audio
    need(manifest['run_repeat'] == repeat, 'wrong run repeat')
    m, t = 20, 800 if repeat == 0 else 40
    expected = dict(meetings=m, calibration_sources=m, test_sources=t,
        test_sources_per_meeting=t//m, source_count=m+t, calibration_cells=8*m,
        test_cells=5*t, expected_cells=8*m+5*t)
    need(manifest['counts'] == expected, 'formal 820/4160 or 60/360 cohort required')
    ev.missing(prepared/'PREPARE_FAILED.json')
    ev.read(prepared/'PROTOCOL.md', freeze['protocol_sha256'])
    required = set(rules.INHERITED_SHA256) | {'run_native.py', 'calibration_rules.py',
                                           'verify_calibration_payloads.py', 'ev_frontend.py'}
    need(required <= set(freeze['code']) and not set(freeze['code']) & set(freeze['evidence']), 'code coverage')
    need(set(freeze['evidence']) == {'SOURCE_CERTIFICATE.json', 'EV_PORT_EQUIVALENCE_v1.json'}, 'evidence scope')
    for name, value in list(freeze['code'].items())+list(freeze['evidence'].items()):
        ev.read(member(prepared, name), value)
    need(all(freeze['code'][n] == v for n, v in rules.INHERITED_SHA256.items()), 'inherited code changed')
    need(freeze['code']['ev_frontend.py'] == rules.EV_SHA256 and
         freeze['evidence']['EV_PORT_EQUIVALENCE_v1.json'] == rules.EV_REPORT_SHA256, 'EV recipe changed')
    # This analyzer executes only its adjacent pure rules, not captured package code.
    ev.read(Path(rules.__file__).resolve(), freeze['code']['calibration_rules.py'])
    baseline = ev.load(prepared/'MODEL_ASSET_BASELINE.json', rules.BASELINE_SHA256)
    receipt = ev.load(prepared/'PREPARE_RECEIPT.json')
    need(receipt == dict(schema='CALIBRATION_PREPARE_v1',
        method_freeze_sha256=ev.hashes[str(prepared/'METHOD_FREEZE.json')],
        manifest_sha256=freeze['manifest_sha256'], calibration_labels_sha256=freeze['calibration_labels_sha256'],
        counts=expected, references_removed_from_execution_manifest=True, test_references_in_package=False),
        'prepare receipt binding')
    cert = ev.load(prepared/'SOURCE_CERTIFICATE.json', freeze['evidence']['SOURCE_CERTIFICATE.json'])
    need(set(cert) == {'schema', 'NN_calls', 'source_only', 'inventory_complete', 'runtime_manifest_sha256',
         'full_source_manifest_sha256', 'source_freeze_sha256', 'archive_sha256', 'meetings'} and
         cert['schema'] == 'CALIBRATION_SOURCE_CERTIFICATE_v1' and cert['NN_calls'] == 0 and
         cert['source_only'] is cert['inventory_complete'] is True and
         cert['runtime_manifest_sha256'] == freeze['manifest_sha256'], 'source certificate schema/binding')
    need(all(pin(cert[k]) for k in ('full_source_manifest_sha256', 'source_freeze_sha256', 'archive_sha256')),
         'external source bindings')
    need(set(cert['meetings']) == {s['meeting'] for s in manifest['samples']}, 'certificate recording coverage')
    for meeting, c in cert['meetings'].items():
        group = [s for s in manifest['samples'] if s['meeting'] == meeting]
        need(set(c) == {'calibration_id', 'first_eligible_id', 'original_frames', 'eligible_intervals'} and
             c['calibration_id'] == c['first_eligible_id'] == group[0]['id'] and
             type(c['original_frames']) is int and c['original_frames'] >= group[-1]['source_end_frame'] and
             type(c['eligible_intervals']) is int and c['eligible_intervals'] >= len(group), 'real C1 bounds')
    return dict(prepared=prepared, manifest=manifest, freeze=freeze, labels=labels,
                baseline=baseline, certificate=cert)


def receipt_header(receipt, package):
    m, f = package['manifest'], package['freeze']
    need(receipt['schema'] == 'CALIBRATION_RAW_AUDIT_v1' and receipt['status'] == 'passed' and
         receipt['actual_completed_run'] is True, 'actual passed completed raw receipt required')
    for key, value in dict(NN_calls_added=0, failed_cells=0, sdk_failed_cells=0,
                          actual_teacher_sdk_calls=0, teacher_policy_calls=0,
                          sources=m['counts']['source_count'], cells=m['counts']['expected_cells'],
                          first_policy_calls=m['counts']['expected_cells'], run_repeat=m['run_repeat']).items():
        need(type(receipt[key]) is int and receipt[key] == value, 'raw receipt '+key)
    need(receipt['quality_run'] is m['quality_run'] and receipt['counts'] == m['counts'] and
         receipt['policies'] == list(POLICIES) and receipt['calibration_policies'] == list(rules.CALIBRATION_POLICIES),
         'raw receipt role/counts/policies')
    for key in ('DSP_decisions_and_waveforms_recomputed', 'own_greedy_raw_replayed',
                'ObservedEncoder_call_output_indices_verified', 'C1_only_E1_L1_recomputed',
                'immutable_decisions_before_suffix_verified', 'all_four_actor_identities_pause_restore_verified',
                'loaded_models_not_physical_residency_claim', 'calibration_reference_used_for_method_replay'):
        need(receipt[key] is True, 'raw receipt '+key)
    need(receipt['test_references_used_for_audit'] is False and receipt['test_scoring_performed'] is False and
         receipt['attempted_failures'] == [] and receipt['operating_point'] == f['operating_point'], 'audit scope/failures')
    need(receipt['verifier_sha256'] == f['code']['verify_calibration_payloads.py'] and
         receipt['frozen_code_sha256'] == f['code'] and receipt['frozen_evidence_sha256'] == f['evidence'],
         'frozen actual verifier/code/evidence')
    need(isinstance(receipt['input_materials_sha256'], dict) and
         all(pin(v) for v in receipt['input_materials_sha256'].values()) and
         pin(receipt['input_calls_sha256']), 'raw material pins')


def validate_guard(pins, paused, restored, prov, child):
    need(type(child['exit_code']) is int and child['exit_code'] == 0, 'child exit must be zero')
    need(pins['boot'] == paused['boot'] == restored['boot'] == prov['boot'] and
         pins['capture_only'] is True and paused['original'] == pins, 'guard capture/boot')
    need(restored['all_restored'] is True and restored['cleanup_errors'] == [], 'restoration incomplete')
    groups = [pins['processes'], paused['after'], restored['after'], restored['signals']]
    need(all(len(g) == len({a['pid'] for a in g}) == 4 for g in groups), 'four distinct guard actors')
    maps = [{a['pid']: a for a in g} for g in groups]
    need(all(set(g) == set(maps[0]) for g in maps), 'guard actor coverage')
    for pid, original in maps[0].items():
        stopped, after, signal = (g[pid] for g in maps[1:])
        need(all(original[k] == stopped[k] == after[k] for k in
             ('pid', 'start_ticks', 'exe_path', 'exe_sha256', 'cmdline_sha256', 'uid')), 'actor identity')
        need(original['exe_sha256'] in GUARD_EXES and original['uid'].split() == ['0']*4, 'allowed actors')
        need(original['state'] not in (None, 'T', 't', 'Z') and stopped['state'] == 'T' and
             after['state'] not in (None, 'T', 't', 'Z') and signal.get('SIGCONT_sent') is True and
             'error' not in signal, 'pause/restore signal evidence')


def gate_run(ev, package, run, receipt_path):
    """All byte/terminal gates precede calls/decision JSON parsing and references."""
    receipt = ev.load(receipt_path)
    receipt_header(receipt, package)
    f, m, prepared = (package[k] for k in ('freeze', 'manifest', 'prepared'))
    for base in (run, run/'native_v1', run/'guard_v1'):
        need(base.is_dir(), 'missing attempt directory')
        for path in base.glob('*FAILED*.json'):
            ev.missing(path)
        ev.missing(base/'RESTORATION_ATTENTION.json')
    ev.missing(run/'guard')
    base_names = {'manifest.json', 'METHOD_FREEZE.json', 'PROTOCOL.md', 'CALIBRATION_LABELS.json',
                  'PREPARE_RECEIPT.json', 'MODEL_ASSET_BASELINE.json', 'BACKGROUND_PINS.json'}
    package_names = base_names | set(f['code']) | set(f['evidence'])
    runtime_names = ev.inventory(run)
    pins = receipt['input_materials_sha256']
    need(set(pins) == package_names | runtime_names, 'auditor complete metadata inventory mismatch')
    required = {'native_v1/'+n for n in ('COMPLETE.json', 'PROVENANCE.json', 'RUNTIME_BINDINGS.json',
                'INITIALIZATION.json', 'SCHEDULE.json', 'calls.jsonl', 'DECISIONS.jsonl', 'SOURCE_IO.jsonl',
                'IDLE_CHECKS.jsonl', 'RAW_INDEX.json', 'PROCESSED_AUDIO_INDEX.json')}
    required |= {'guard_v1/'+n for n in ('CHILD_EXIT.json', 'PAUSED.json', 'RESTORED.json')}
    required |= {'native_v1/decisions/'+s['id']+'.json' for s in m['samples'] if s['role'] == 'calibration'}
    need(required <= runtime_names, 'missing audited runtime metadata')
    need(receipt['input_calls_sha256'] == pins['native_v1/calls.jsonl'], 'calls pin disagreement')
    for name in sorted(package_names):
        source = run if name == 'BACKGROUND_PINS.json' else prepared
        ev.read(member(source, name), pins[name])
        # Captured root may contain its own copies; conflicting copies are refused.
        if source != run and (run/name).exists():
            ev.read(member(run, name), pins[name])
    def bound(name):
        return ev.load(member(run, name), pins[name])
    meta = {n: bound('native_v1/'+n+'.json') for n in
            ('COMPLETE', 'PROVENANCE', 'RUNTIME_BINDINGS', 'INITIALIZATION', 'SCHEDULE')}
    complete, prov, runtime, init = (meta[n] for n in ('COMPLETE', 'PROVENANCE', 'RUNTIME_BINDINGS', 'INITIALIZATION'))
    validate_guard(bound('BACKGROUND_PINS.json'), bound('guard_v1/PAUSED.json'),
                   bound('guard_v1/RESTORED.json'), prov, bound('guard_v1/CHILD_EXIT.json'))
    c = m['counts']
    terminal = dict(samples=c['source_count'], outputs=c['expected_cells'], expected_outputs=c['expected_cells'],
        calibration_cells=c['calibration_cells'], test_cells=c['test_cells'], decisions=c['meetings'],
        policies=5, calibration_policies=8, failed_cells=0, sdk_failed_cells=0,
        actual_teacher_sdk_calls=0, teacher_policy_calls=0, first_policy_calls=c['expected_cells'])
    need(complete['counts'] == c and all(type(complete[k]) is int and complete[k] == v
         for k, v in terminal.items()), 'terminal count/failure contract')
    need(complete['quality_run'] is m['quality_run'] and complete['run_repeat'] == m['run_repeat'] and
         complete['operating_point'] == rules.OPERATING_POINT, 'terminal role')
    need(prov['schema'] == 'CALIBRATION_NATIVE_v1' and prov['shared_lock'] == str(rules.LOCK), 'native provenance')
    for name, key in (('METHOD_FREEZE.json', 'method_freeze_sha256'), ('manifest.json', 'manifest_sha256'),
                      ('PROTOCOL.md', 'protocol_sha256'), ('CALIBRATION_LABELS.json', 'calibration_labels_sha256')):
        need(prov[key] == pins[name], 'runtime/package binding '+name)
    need(prov['code_sha256'] == f['code'] and prov['evidence_sha256'] == f['evidence'] and
         prov['runtime_bindings_sha256'] == pins['native_v1/RUNTIME_BINDINGS.json'] and
         prov['operating_point'] == f['operating_point'] and
         prov['calibration_reference_used_for_method'] is True and
         prov['test_references_used'] is prov['test_scoring_performed'] is False, 'runtime frozen scope')
    need(runtime == receipt['runtime_assets'] and runtime['model_assets'] and runtime['loaded_libraries'] and
         runtime['python'] and runtime['versions'] and runtime['executable'], 'actual runtime metadata')
    for path, value in runtime['model_assets'].items():
        need(value == {k: package['baseline']['assets'][path][k] for k in ('bytes', 'sha256')}, 'model baseline')
    for value in list(runtime['model_assets'].values())+list(runtime['loaded_libraries'].values()):
        need(type(value['bytes']) is int and value['bytes'] > 0 and pin(value['sha256']), 'runtime fingerprint')
    need(all(any(k in p.lower() for p in runtime['loaded_libraries']) for k in ('rknn', 'rkllm')), 'loaded library records')
    need(init['both_loaded'] is init['both_resident'] is init['excluded_from_service'] is True and
         init['physical_residency_verified'] is False and init['qwen_execution_policy'] == 'initialized_loaded_no_calls' and
         init['operating_point'] == rules.OPERATING_POINT and init['encoder_sizes'] == [30] and
         init['prefix_cached'] is False and init['repeat_detection_limit'] == 257 and init['max_new_tokens'] == 256 and
         finite(init['sensevoice_init_s']) and finite(init['qwen_init_s']), 'loaded initialization contract')
    need(meta['SCHEDULE'] == rules.make_schedule(m), 'frozen own-cell schedule')
    for name in ('CELL_FAILURES.jsonl', 'SDK_FAILURES.jsonl'):
        key = 'native_v1/'+name
        if key in pins:
            need(ev.lines(run/key, pins[key]) == [], 'failure ledger nonempty')
        else:
            ev.missing(run/key)
    # Hash every auditor input, including calls, before parsing any recognized text.
    for name in sorted(runtime_names):
        ev.read(member(run, name), pins[name])
    ev.stable()
    package.update(run=run, receipt_path=receipt_path, receipt=receipt, metadata=meta)
    return package


def load_calls(ev, package):
    """Only called after ALL requested runs have passed gate_run."""
    run, m, receipt = (package[k] for k in ('run', 'manifest', 'receipt'))
    pins = receipt['input_materials_sha256']
    calls = ev.lines(run/'native_v1/calls.jsonl', receipt['input_calls_sha256'])
    expected = package['metadata']['SCHEDULE']['rows']
    need(len(calls) == len(expected) == m['counts']['expected_cells'], 'complete owned outcome matrix')
    sources = {s['id']: s for s in m['samples']}
    total_native, raw_occurrences = 0, 0
    for row, cell in zip(calls, expected):
        s, a = sources[cell['id']], row['asr']
        need(all(row[k] == v for k, v in cell.items()), 'missing/duplicate/reordered/foreign outcome')
        need(row['meeting'] == s['meeting'] and row['speaker_cluster'] == s['speaker_cluster'] and
             row['condition_group'] == s.get('condition_group', s.get('room_cluster')) and
             row['audio_sha256'] == s['sha256'] and row['audio_samples'] == s['frames'] and
             row['input_channels'] == 8 and row['input_PCM_bytes'] == 16*s['frames'], 'outcome source binding')
        need(row['quality_run'] is m['quality_run'] and row['run_repeat'] == m['run_repeat'] and
             row['operating_point'] == m['operating_point'] and row['independent_policy_execution'] is True and
             row['fatal'] is False and row['cell_exception'] is None and a['status'] == 'ok' and
             a['second_failure'] is None and row['text'] == a['text'] and isinstance(row['text'], str), 'owned successful text')
        need(a['policy'] == 'sense_only' and a['independent_policy_execution'] is True and
             a['invoked'] is False and a['teacher'] is None and a['sdk_calls'] == a['sdk_errors'] == [] and
             row['actual_teacher_sdk_calls'] == a['actual_teacher_sdk_calls'] == 0, 'zero Qwen calls')
        n = row['actual_first_native_calls']
        need(type(n) is int and n > 0 and n == row['completed_first_native_calls'] == a['actual_first_native_calls'],
             'actual native call counts')
        total_native += n
        raw_occurrences += len(row['raw_tensor'])
        for k in ('service_s', 'frontend_s', 'research_archive_s', 'source_io_s', 'source_integrity_s'):
            need(finite(row[k]), 'measured service '+k)
        need(finite(a['service_s']) and close(row['service_s'], row['final_computed_monotonic']-row['start_monotonic']) and
             close(a['service_s'], a['final_computed_monotonic']-a['start_monotonic']) and
             row['start_monotonic'] <= a['start_monotonic'] <= a['final_computed_monotonic'] <= row['final_computed_monotonic'] and
             close(row['frontend_plus_asr_residual_s'], row['service_s']-row['frontend_s']-a['service_s']) and
             row['frontend_plus_asr_residual_s'] >= -1e-8, 'measured service components')
    complete = package['metadata']['COMPLETE']
    need(total_native == complete['actual_first_native_calls'] == receipt['actual_first_native_calls'] and
         raw_occurrences == receipt['raw_occurrences'] and
         complete['unique_raw_payloads'] == receipt['raw_payloads'] and
         complete['processed_audio_files'] == receipt['processed_waveforms'], 'audited totals')
    decisions = {}
    commits = ev.lines(run/'native_v1/DECISIONS.jsonl', pins['native_v1/DECISIONS.jsonl'])
    need(len(commits) == m['counts']['meetings'] and len({c['meeting'] for c in commits}) == len(commits), 'decision coverage')
    labels = {r['id']: r['reference'] for r in package['labels']['labels']}
    lookup = {(r['id'], r['policy']): r for r in calls}
    for commit in commits:
        s = sources[commit['calibration_id']]
        name = 'native_v1/decisions/'+s['id']+'.json'
        need(commit['path'] == 'decisions/'+s['id']+'.json' and commit['sha256'] == pins[name] and
             commit['meeting'] == s['meeting'] and s['role'] == 'calibration', 'C1 commit identity')
        d = ev.load(run/name, commit['sha256'])
        owned = [lookup[s['id'], p] for p in rules.CALIBRATION_POLICIES]
        channel, errors = rules.choose_label(d['powers'], [r['text'] for r in owned], labels[s['id']])
        need(d['energy_channel'] == rules.choose_energy(d['powers']) and d['label_channel'] == channel and
             d['prefix_errors'] == errors, 'C1-only primary decision metadata replay')
        need(d['owned_prefix'] == [dict(policy=r['policy'], text=r['text'], row_sha256=rules.digest_json(r)) for r in owned],
             'owned prefix digests')
        need(d['schema'] == 'CALIBRATION_DECISION_v1' and d['calibration_id'] == s['id'] and
             d['meeting'] == s['meeting'] and d['calibration_audio_sha256'] == s['sha256'] and
             d['calibration_pcm_sha256'] == s['pcm_sha256'] and
             d['calibration_labels_sha256'] == package['freeze']['calibration_labels_sha256'] and
             all(d[k] == s[k] for k in ('source_start_frame', 'source_end_frame')), 'decision source binding')
        for field, getter in (('prefix_cell_service_s', lambda r: r['service_s']),
                              ('prefix_asr_service_s', lambda r: r['asr']['service_s']),
                              ('prefix_frontend_service_s', lambda r: r['frontend_s']),
                              ('prefix_archive_s', lambda r: r['research_archive_s'])):
            need(close(d[field], sum(getter(r) for r in owned)), 'C1 component sum '+field)
        for k in ('E1_setup_energy_s', 'E1_setup_energy_cpu_s', 'L1_reference_decision_s',
                  'L1_reference_decision_cpu_s', 'L1_component_service_s', 'setup_block_wall_s'):
            need(finite(d[k]), 'nonfinite setup cost')
        need(close(d['L1_component_service_s'], d['prefix_cell_service_s']+d['E1_setup_energy_s']+
                   d['L1_reference_decision_s']) and d['L1_component_service_s'] <= d['setup_block_wall_s']+1e-7,
             'corrected L1 whole-cell component sum')
        need(close(d['C1_speech_duration_s'], s['frames']/16000) and
             close(d['elapsed_recording_to_C1_end_s'], s['source_end_frame']/16000) and
             d['human_label_latency_measured'] is False and d['human_label_latency_s'] is None, 'C1 elapsed/human boundary')
        need(all(r['decision_sha256'] is None for r in owned) and
             max(r['final_computed_monotonic'] for r in owned) <= d['label_start_monotonic'] <=
             d['decision_computed_monotonic'] <= commit['committed_monotonic'], 'C1 causal commit')
        for test in (r for r in calls if r['meeting'] == s['meeting'] and r['role'] == 'test'):
            need(test['decision_sha256'] == commit['sha256'] and
                 commit['committed_monotonic'] <= test['start_monotonic'], 'suffix before committed decision')
            if test['policy'] in ('cal_energy_sense', 'cal_label_sense'):
                key = 'energy_channel' if test['policy'] == 'cal_energy_sense' else 'label_channel'
                need(test['frontend']['selected_channel'] == d[key] and
                     test['frontend']['calibration_id'] == s['id'] and
                     test['frontend']['decision_sha256'] == commit['sha256'], 'constant calibrated channel')
        decisions[s['meeting']] = d
    package.update(calls=calls, decisions=decisions)
    return package


def source_features(sample, c1, original_frames):
    """Exact parent rule: START, integer frame comparison, tie belongs to late."""
    return dict(condition_group=sample['condition_group'], speaker_cluster=sample['speaker_cluster'],
        C1_id=c1['id'], C1_speaker_relation='same' if sample['speaker_cluster'] == c1['speaker_cluster'] else 'different',
        post_C1_half='early' if 2*sample['source_start_frame'] < c1['source_end_frame']+original_frames else 'late',
        post_C1_midpoint_frame=(c1['source_end_frame']+original_frames)/2,
        original_frames=original_frames, source_start_frame=sample['source_start_frame'],
        source_end_frame=sample['source_end_frame'], duration_s=sample['frames']/16000)


def frontend_reporting(call):
    """Preserve actual diagnostics; missing fields are null, never invented success."""
    front = call['frontend']
    return dict(ranking_valid=front.get('ranking_valid'), fallback_used=front.get('fallback_used'),
        fallback_reason=front.get('fallback_reason'), frontend_status=front.get('status'),
        ev_selected_channel=front.get('ev_selected_channel'))


def load_sources(ev, main, repeats, source_path, selection_path, review_path, panel_path):
    cert = main['certificate']
    rows = ev.lines(source_path, cert['full_source_manifest_sha256'])
    selection = ev.load(selection_path, cert['source_freeze_sha256'])
    need(selection['schema'] == 'aishell4-selection-v1' and selection['synthetic'] is False and
         selection['source_only'] is True and selection['calibration_count'] == 20 and selection['test_count'] == 800 and
         selection['sampling']['test_per_meeting'] == 40 and selection['sampling']['quartile_quotas'] == [10]*4,
         'full prospective selection')
    refs = {r['id']: r for r in rows}
    selected = {r['id']: r for r in selection['rows']}
    samples = main['manifest']['samples']
    need(len(refs) == len(rows) == len(selected) == len(selection['rows']) == 820 and
         set(refs) == set(selected) == {s['id'] for s in samples}, 'complete 820 reference/selection coverage')
    c1s = {s['meeting']: s for s in samples if s['role'] == 'calibration'}
    features = {}
    for s in samples:
        r, chosen = refs[s['id']], selected[s['id']]
        need(all(r[k] == v for k, v in chosen.items() if k not in ('audio_prepared', 'audio_verified')),
             'extraction/selection drift '+s['id'])
        need(r['audio_prepared'] is r['audio_verified'] is True and r['eligible_whole_utterance'] is True and
             not r['eligibility_exclusions'] and not r.get('exact_duplicate_rejected', False), 'source not eligible/verified')
        for key in ('id', 'meeting', 'speaker_cluster', 'condition_group', 'role', 'pcm_sha256', 'frames',
                    'channels', 'sample_rate', 'encoding'):
            need(r[key] == s[key], 'source/runtime mismatch '+key)
        need(r['wav_sha256'] == s['sha256'] and r['source_start_sample'] == r['start_sample'] == s['source_start_frame'] and
             r['source_end_sample'] == r['end_sample'] == s['source_end_frame'], 'physical source/coordinate binding')
        # Annotation durations are not PCM durations (Decimal/ROUND_HALF_UP endpoints).
        need(close(r['duration_s'], s['frames']/16000, 1/16000+1e-9), 'annotation/physical duration exceeds one frame')
        need(digest(r['reference'].encode('utf-8')) == r['reference_utf8_sha256'] and
             digest(r['raw_reference'].encode('utf-8')) == r['raw_reference_utf8_sha256'] and
             r['primary_normalized_reference'] == normalize(r['reference']) and
             r['primary_reference_length'] == len(normalize(r['reference'])) > 0, 'reference integrity')
        group = re.fullmatch(r'([LMS]_R\d+)S\d+C\d+', s['meeting'])
        need(group is not None and group[1] == s['condition_group'] and
             s['speaker_cluster'].startswith(s['meeting']+'::'), 'filename condition/within-recording tier')
        c1 = c1s[s['meeting']]
        need(r['calibration_id'] == c1['id'], 'source calibration ID')
        features[s['id']] = source_features(s, c1, cert['meetings'][s['meeting']]['original_frames'])
        features[s['id']].update(annotation_duration_s=r['duration_s'],
                                 annotation_minus_physical_duration_s=r['duration_s']-s['frames']/16000)
    for entry in main['labels']['labels']:
        need(entry['reference'] == refs[entry['id']]['reference'], 'C1 label/full-source disagreement')
    for meeting in c1s:
        need(Counter(refs[s['id']]['quartile'] for s in samples if s['meeting'] == meeting and s['role'] == 'test') ==
             Counter({i: 10 for i in range(1, 5)}), 'quartile coverage')
    review = ev.load(review_path)
    need(review['schema'] == 'CALIBRATION_SOURCE_REVIEW_v1' and review['source_only'] is True and
         review['NN_calls'] == 0 and review['early_late_definition'] == EARLY_LATE and
         review['recordings'] == review['calibration_sources'] == 20 and review['test_sources'] == 800 and
         review['calibration_tiers_are_not_global_people'] is True, 'source review schema/definition')
    reviewed = {r['meeting']: r for r in review['rows']}
    need(len(reviewed) == len(review['rows']) == 20 and set(reviewed) == set(c1s), 'source review coverage')
    for meeting, c1 in c1s.items():
        tests = [s for s in samples if s['meeting'] == meeting and s['role'] == 'test']
        group = [features[s['id']] for s in tests]
        r = reviewed[meeting]
        expected = dict(C1_id=c1['id'], condition_group=c1['condition_group'], test_sources=40,
            same_C1_speaker=sum(x['C1_speaker_relation'] == 'same' for x in group),
            different_C1_speaker=sum(x['C1_speaker_relation'] == 'different' for x in group),
            early=sum(x['post_C1_half'] == 'early' for x in group), late=sum(x['post_C1_half'] == 'late' for x in group),
            test_primary_characters=sum(refs[s['id']]['primary_reference_length'] for s in tests),
            within_recording_tiers_selected=len({s['speaker_cluster'] for s in samples if s['meeting'] == meeting}))
        need(all(r[k] == v for k, v in expected.items()) and
             close(r['recording_seconds'], cert['meetings'][meeting]['original_frames']/16000) and
             close(r['C1_end_seconds'], c1['source_end_frame']/16000) and
             close(r['C1_speech_seconds'], c1['frames']/16000, 1/16000+1e-9), 'source review mismatch '+meeting)
    need(review['test_primary_characters'] == sum(r['primary_reference_length'] for r in rows if r['role'] == 'test') and
         review['condition_group_counts'] == dict(Counter(s['condition_group'] for s in c1s.values())), 'source review totals')
    panel = ev.load(panel_path)
    need(panel['schema'] == 'calibration-duration-panel-v1' and panel['source_only'] is True and panel['NN_calls'] == 0 and
         panel['full_source_manifest_sha256'] == cert['full_source_manifest_sha256'] and panel['rule'] == PANEL_RULE,
         'prospective timing panel binding')
    panel_ids = set()
    for meeting in sorted(c1s):
        tests = [s for s in samples if s['meeting'] == meeting and s['role'] == 'test']
        lengths = sorted(s['frames'] for s in tests)
        available = {s['id']: s for s in tests}
        own = [r for r in panel['rows'] if r['meeting'] == meeting]
        need([r['quantile'] for r in own] == [.25, .75], 'timing quantile order')
        for r in own:
            pos = r['quantile']*(len(lengths)-1)
            lo = math.floor(pos)
            target = lengths[lo]+(lengths[math.ceil(pos)]-lengths[lo])*(pos-lo)
            chosen = min(available.values(), key=lambda s: (abs(s['frames']-target), s['id']))
            need(r['id'] == chosen['id'] and r['frames'] == chosen['frames'] and close(r['target_frames'], target),
                 'timing source-only duration selection')
            panel_ids.add(chosen['id'])
            del available[chosen['id']]
    need(len(panel['rows']) == len(panel_ids) == 40, '40 distinct timing sources')
    main_samples = {s['id']: s for s in samples}
    for p in repeats:
        need(all(p['certificate'][k] == cert[k] for k in
             ('full_source_manifest_sha256', 'source_freeze_sha256', 'archive_sha256', 'meetings')), 'repeat source certificate')
        own = p['manifest']['samples']
        need({s['id'] for s in own if s['role'] == 'test'} == panel_ids and
             {s['id'] for s in own if s['role'] == 'calibration'} == {s['id'] for s in c1s.values()}, 'repeat exact timing panel/C1')
        for s in own:
            need({k: v for k, v in s.items() if k != 'audio'} ==
                 {k: v for k, v in main_samples[s['id']].items() if k != 'audio'}, 'repeat physical source drift')
        need(p['labels'] == main['labels'] and p['freeze']['decoder'] == main['freeze']['decoder'] and
             p['freeze']['code'] == main['freeze']['code'], 'repeat label/method/code drift')
    return refs, features


def score(main, refs, features):
    rows = []
    for line, call in enumerate(main['calls'], 1):
        if call['role'] != 'test':
            continue  # C1 and every timing repetition excluded from quality denominator.
        for mode in MODES:
            ref, hyp = (normalize(t, mode == MODES[0]) for t in (refs[call['id']]['reference'], call['text']))
            need(len(ref) > 0, 'zero normalized Test denominator; never silently drop')
            counts = edit_counts(ref, hyp)
            rows.append(dict(id=call['id'], meeting=call['meeting'], policy=call['policy'], mode=mode,
                **features[call['id']], **frontend_reporting(call),
                reference=refs[call['id']]['reference'], raw_text=call['text'],
                normalized_reference=ref, normalized_text=hyp, reference_characters=len(ref), **counts,
                cer=counts['errors']/len(ref), selected_channel=call['frontend'].get('selected_channel'),
                processed_waveform_sha256=call['processed_audio']['sha256'], calls_jsonl_line=line,
                successful_empty_text=call['text'] == '', decision_sha256=call['decision_sha256']))
    return rows


def aggregate(rows):
    need(bool(rows), 'empty scoring group')
    sums = {k: sum(r[k] for r in rows) for k in SCORE_KEYS}
    need(sums['reference_characters'] > 0, 'zero denominator')
    return dict(n_sources=len(rows), **sums, cer=sums['errors']/sums['reference_characters'])


def cluster_effect(delta, refs, draws):
    """Whole-recording paired percentile bootstrap; raw fractions, NOT pp."""
    import numpy as np
    d, n = np.asarray(delta, dtype=float), np.asarray(refs, dtype=float)
    need(d.ndim == n.ndim == 1 and len(d) == len(n) > 0 and
         np.isfinite(d).all() and np.isfinite(n).all() and (n > 0).all(), 'cluster denominators')
    need(draws.ndim == 2 and draws.shape[1] == len(n), 'whole recording paired draws')
    tail = (1-rules.BOOTSTRAP['marginal_confidence'])/2
    values = dict(equal_recording=(d/n)[draws].mean(axis=1), pooled=d[draws].sum(axis=1)/n[draws].sum(axis=1))
    points = dict(equal_recording=float((d/n).mean()), pooled=float(d.sum()/n.sum()))
    return {k: dict(point=points[k], ci_low=float(np.quantile(v, tail, method='linear')),
                    ci_high=float(np.quantile(v, 1-tail, method='linear'))) for k, v in values.items()}


def band_position(low, high, band):
    if low > band:
        return 'above_positive_band'
    if high < -band:
        return 'below_negative_band'
    if low >= -band and high <= band:
        return 'interval_inside_band_descriptive_only'
    return 'overlaps_band_boundary'


def analyze(rows):
    import numpy as np
    meetings = sorted({r['meeting'] for r in rows})
    draws = np.random.default_rng(rules.BOOTSTRAP['seed']).integers(
        0, len(meetings), (rules.BOOTSTRAP['replicates'], len(meetings)))
    tables = {k: [] for k in ('per_source', 'per_recording', 'per_policy', 'contrasts', 'paired_sources',
        'paired_recordings', 'subgroups', 'leave_one_condition_out', 'disagreement_damage', 'contrary_cases')}
    tables['per_source'] = rows
    for mode in MODES:
        own = [r for r in rows if r['mode'] == mode]
        index = {(r['id'], r['policy']): r for r in own}
        ids = sorted({r['id'] for r in own})
        need(len(index) == len(own) == len(ids)*5, 'full Test denominator for all five policies')
        for policy in POLICIES:
            group = [r for r in own if r['policy'] == policy]
            per_rec = [dict(mode=mode, policy=policy, meeting=m,
                condition_group=next(r['condition_group'] for r in group if r['meeting'] == m),
                **aggregate([r for r in group if r['meeting'] == m])) for m in meetings]
            tables['per_recording'].extend(per_rec)
            tables['per_policy'].append(dict(mode=mode, policy=policy, **aggregate(group),
                n_recordings=len(meetings), equal_recording_cer=sum(r['cer'] for r in per_rec)/len(per_rec)))
        for candidate, baseline in PRIMARY+SECONDARY:
            pairs = []
            for source_id in ids:
                a, b = index[source_id, candidate], index[source_id, baseline]
                need(a['reference_characters'] == b['reference_characters'], 'paired source denominator')
                delta = a['errors']-b['errors']
                pairs.append(dict(mode=mode, candidate=candidate, baseline=baseline, id=source_id, meeting=a['meeting'],
                    condition_group=a['condition_group'], C1_speaker_relation=a['C1_speaker_relation'],
                    post_C1_half=a['post_C1_half'], reference_characters=a['reference_characters'],
                    candidate_errors=a['errors'], baseline_errors=b['errors'], error_delta=delta,
                    cer_delta=delta/a['reference_characters'], candidate_raw_text=a['raw_text'], baseline_raw_text=b['raw_text'],
                    raw_text_disagreement=a['raw_text'] != b['raw_text'], normalized_text_disagreement=a['normalized_text'] != b['normalized_text'],
                    selected_channel_disagreement=a['selected_channel'] != b['selected_channel'],
                    candidate_channel=a['selected_channel'], baseline_channel=b['selected_channel'],
                    baseline_perfect_damage=b['errors'] == 0 and delta > 0,
                    candidate_perfect_baseline_damage=a['errors'] == 0 and delta < 0))
            tables['paired_sources'].extend(pairs)
            mp = paired_recordings(pairs)
            tables['paired_recordings'].extend(mp)
            effects = cluster_effect([r['error_delta'] for r in mp], [r['reference_characters'] for r in mp], draws)
            primary_pair = (candidate, baseline) in PRIMARY
            for estimator, effect in effects.items():
                primary = mode == MODES[0] and estimator == 'equal_recording' and primary_pair
                family = ('primary_equal_recording_casefold' if primary else
                          f'{"sensitivity" if primary_pair else "secondary_default0"}_{mode}_{estimator}')
                tables['contrasts'].append(dict(mode=mode, estimator=estimator, candidate=candidate, baseline=baseline,
                    analysis_role='primary' if primary else ('sensitivity' if primary_pair else 'secondary'),
                    family=family, family_size=4, marginal_confidence=.9875,
                    nominal_family_confidence=.95, family_scope='within this estimator/scoring only; no cross-family joint claim',
                    n_sources=len(ids), n_recordings=len(meetings), **effect,
                    point_pp=100*effect['point'], ci_low_pp=100*effect['ci_low'], ci_high_pp=100*effect['ci_high'],
                    positive_means='candidate higher CER; calibrated/default fixed worse for fixed-minus-dynamic contrasts',
                    decision_band_pp=.5, decision_band_status=band_position(effect['ci_low'], effect['ci_high'], .005),
                    band_validation='prospective study decision; not validated stakeholder requirement',
                    original_reference_pp=1., original_reference_status=band_position(effect['ci_low'], effect['ci_high'], .01),
                    equivalence_inferred=False, scientific_contribution_decision=None))
            tables['disagreement_damage'].append(dict(mode=mode, candidate=candidate, baseline=baseline,
                sources=len(pairs), candidate_worse=sum(r['error_delta'] > 0 for r in pairs),
                baseline_worse=sum(r['error_delta'] < 0 for r in pairs), equal_errors=sum(r['error_delta'] == 0 for r in pairs),
                baseline_perfect_sources=sum(r['baseline_errors'] == 0 for r in pairs),
                candidate_perfect_sources=sum(r['candidate_errors'] == 0 for r in pairs),
                **{k: sum(r[k] for r in pairs) for k in ('raw_text_disagreement', 'normalized_text_disagreement',
                    'selected_channel_disagreement', 'baseline_perfect_damage', 'candidate_perfect_baseline_damage')}))
            # Every nonzero effect retained in both directions; no selected examples/top-k.
            tables['contrary_cases'].extend(dict(r, direction='candidate_worse' if r['error_delta'] > 0 else 'baseline_worse')
                                           for r in pairs if r['error_delta'] != 0 or r['raw_text_disagreement'])
            for key in ('condition_group', 'C1_speaker_relation', 'post_C1_half'):
                for value in sorted({r[key] for r in pairs}):
                    tables['subgroups'].append(dict(mode=mode, candidate=candidate, baseline=baseline,
                        grouping=key, group=value, role='descriptive; no subgroup multiplicity guarantee',
                        **paired_points([r for r in pairs if r[key] == value])))
            for value in sorted({r['condition_group'] for r in pairs}):
                tables['leave_one_condition_out'].append(dict(mode=mode, candidate=candidate, baseline=baseline,
                    excluded_condition=value, role='descriptive; no retuning or joint claim',
                    **paired_points([r for r in pairs if r['condition_group'] != value])))
    return tables, dict(replicates=len(draws), clusters=meetings, seed=rules.BOOTSTRAP['seed'],
        numpy_version=np.__version__, random_generator='default_rng PCG64', quantile_method='linear',
        draw_matrix_little_endian_int64_sha256=digest(draws.astype('<i8').tobytes(order='C')))


def paired_recordings(pairs):
    groups = defaultdict(list)
    for r in pairs:
        groups[r['meeting']].append(r)
    out = []
    for meeting, group in sorted(groups.items()):
        d, n = sum(r['error_delta'] for r in group), sum(r['reference_characters'] for r in group)
        need(n > 0, 'paired recording denominator')
        out.append(dict(mode=group[0]['mode'], candidate=group[0]['candidate'], baseline=group[0]['baseline'],
            meeting=meeting, condition_group=group[0]['condition_group'], n_sources=len(group),
            error_delta=d, reference_characters=n, cer_delta=d/n))
    return out


def paired_points(pairs):
    mp = paired_recordings(pairs)
    need(bool(mp), 'empty subgroup')
    return dict(n_sources=len(pairs), n_recordings=len(mp), error_delta=sum(r['error_delta'] for r in mp),
        reference_characters=sum(r['reference_characters'] for r in mp),
        equal_recording_difference=sum(r['cer_delta'] for r in mp)/len(mp),
        pooled_difference=sum(r['error_delta'] for r in mp)/sum(r['reference_characters'] for r in mp),
        candidate_worse_recordings=sum(r['error_delta'] > 0 for r in mp),
        baseline_worse_recordings=sum(r['error_delta'] < 0 for r in mp))


def cost_tables(packages):
    import numpy as np
    cells, setup, rounds, drifts, shared_io, initialization, fallbacks = [], [], [], [], [], [], []
    for p in packages:
        repeat = p['manifest']['run_repeat']
        samples = {s['id']: s for s in p['manifest']['samples']}
        initialization.append(dict(run_repeat=repeat, **p['metadata']['INITIALIZATION']))
        seen = set()
        for r in p['calls']:
            if r['id'] not in seen:
                shared_io.append(dict(run_repeat=repeat, id=r['id'], meeting=r['meeting'], role=r['role'],
                    source_io_s=r['source_io_s'], source_integrity_s=r['source_integrity_s'],
                    accounting='once per source; excluded from service; never multiply by policy count'))
                seen.add(r['id'])
            cells.append(dict(run_repeat=repeat, scope='main' if repeat == 0 else 'timing',
                id=r['id'], meeting=r['meeting'], role=r['role'], policy=r['policy'],
                duration_s=samples[r['id']]['frames']/16000, service_s=r['service_s'],
                **frontend_reporting(r), selected_channel=r['frontend'].get('selected_channel'),
                frontend_s=r['frontend_s'], asr_service_s=r['asr']['service_s'],
                accounting_residual_s=r['frontend_plus_asr_residual_s'], research_archive_s=r['research_archive_s'],
                rtf=r['service_s']/(samples[r['id']]['frames']/16000)))
        labels = {r['id']: r['reference'] for r in p['labels']['labels']}
        for meeting, d in sorted(p['decisions'].items()):
            keys = ('calibration_id', 'energy_channel', 'label_channel', 'E1_setup_energy_s', 'E1_setup_energy_cpu_s',
                'L1_reference_decision_s', 'L1_reference_decision_cpu_s', 'prefix_cell_service_s', 'prefix_asr_service_s',
                'prefix_frontend_service_s', 'prefix_archive_s', 'L1_component_service_s', 'setup_block_wall_s',
                'C1_speech_duration_s', 'elapsed_recording_to_C1_end_s', 'source_io_s', 'source_integrity_s',
                'human_label_latency_measured', 'human_label_latency_s')
            setup.append(dict(run_repeat=repeat, meeting=meeting, **{k: d[k] for k in keys},
                supplied_label_raw_characters=len(labels[d['calibration_id']]),
                supplied_label_primary_characters=len(normalize(labels[d['calibration_id']])),
                setup_accounting='actual components; not product startup/capture-to-commit/human latency',
                E1_pays_prefix_ASR=False, prefix_executions_are_measured_study_exploration=True))
        for role, policies in (('test', POLICIES), ('calibration', rules.CALIBRATION_POLICIES)):
            for policy in policies:
                own = [r for r in cells if r['run_repeat'] == repeat and r['role'] == role and r['policy'] == policy]
                fallbacks.append(dict(run_repeat=repeat, role=role, policy=policy, cells=len(own),
                    fallback_count=sum(r['fallback_used'] is True for r in own),
                    explicit_no_fallback_count=sum(r['fallback_used'] is False for r in own),
                    fallback_field_unreported_count=sum(r['fallback_used'] is None for r in own),
                    ranking_valid_count=sum(r['ranking_valid'] is True for r in own),
                    ranking_invalid_count=sum(r['ranking_valid'] is False for r in own),
                    policy_interpretation='operational EV including safety fallback' if policy == 'ev_sense' else 'frozen policy',
                    denominator_policy='all cases retained; no exclusion/reselection/new contrast'))
                v = [r['service_s'] for r in own]
                rounds.append(dict(run_repeat=repeat, role=role, policy=policy, sources=len(own),
                    service_total_s=sum(v), service_mean_s=float(np.mean(v)), service_median_s=float(np.median(v)),
                    service_p95_s=float(np.quantile(v, .95)),
                    pooled_rtf=sum(v)/sum(r['duration_s'] for r in own),
                    mean_source_rtf=sum(r['rtf'] for r in own)/len(own),
                    inference='round descriptives; timing is not pooled with main'))
    for left, right in ((packages[0], p) for p in packages[1:]):
        drifts.extend(compare_runs(left, right))
    if len(packages) == 3:
        drifts.extend(compare_runs(packages[1], packages[2]))
    per_recording = []
    for p in packages:
        repeat = p['manifest']['run_repeat']
        for meeting, d in sorted(p['decisions'].items()):
            for policy in POLICIES:
                own = [r for r in cells if r['run_repeat'] == repeat and r['meeting'] == meeting and
                       r['role'] == 'test' and r['policy'] == policy]
                setup_s = d['E1_setup_energy_s'] if policy == 'cal_energy_sense' else (
                    d['L1_component_service_s'] if policy == 'cal_label_sense' else 0.)
                total = sum(r['service_s'] for r in own)
                per_recording.append(dict(run_repeat=repeat, meeting=meeting, policy=policy, test_sources=len(own),
                    test_service_s=total, setup_component_s=setup_s, setup_plus_test_component_s=setup_s+total,
                    test_speech_s=sum(r['duration_s'] for r in own),
                    accounting='measured components only; excludes acquisition/human labeling/init/IO/archive; not observed startup'))
    averaged, timing_effects, setup_averaged, setup_effects = [], [], [], []
    if len(packages) == 3:
        repeated = defaultdict(list)
        for r in cells:
            if r['run_repeat'] and r['role'] == 'test':
                repeated[r['id'], r['policy']].append(r)
        fields = ('service_s', 'frontend_s', 'asr_service_s', 'accounting_residual_s', 'rtf')
        for (source_id, policy), group in sorted(repeated.items()):
            need(len(group) == 2 and {r['run_repeat'] for r in group} == {1, 2}, 'two actual timing rounds')
            averaged.append(dict(id=source_id, policy=policy, meeting=group[0]['meeting'], rounds=2,
                duration_s=group[0]['duration_s'], **{k: sum(r[k] for r in group)/2 for k in fields}))
        meetings = sorted({r['meeting'] for r in averaged})
        draws = np.random.default_rng(rules.BOOTSTRAP['seed']).integers(0, len(meetings), (50000, len(meetings)))
        indexed = {(r['id'], r['policy']): r for r in averaged}
        for candidate, baseline in PRIMARY+SECONDARY:
            for field in ('service_s', 'rtf'):
                deltas = [sum(indexed[r['id'], candidate][field]-indexed[r['id'], baseline][field]
                    for r in averaged if r['meeting'] == m and r['policy'] == candidate)/2 for m in meetings]
                v = np.asarray(deltas)[draws].mean(axis=1)
                timing_effects.append(dict(candidate=candidate, baseline=baseline, metric=field,
                    distinct_sources=40, recording_clusters=20, measured_rounds=2,
                    dependence_caveat='clips within recording are dependent; recording exchangeability/independence assumed, people/rooms unknown; conditional on two rounds',
                    point=float(np.mean(deltas)), ci_low=float(np.quantile(v, .025)), ci_high=float(np.quantile(v, .975)),
                    marginal_confidence=.95, inference='secondary marginal descriptive CI; no primary/joint guarantee',
                    estimator='two rounds averaged within source, then paired mean within recording; recording bootstrap',
                    positive_means='candidate slower / higher RTF'))
        for meeting in meetings:
            group = [r for r in setup if r['run_repeat'] in (1, 2) and r['meeting'] == meeting]
            need(len(group) == 2, 'two measured C1 setups')
            setup_averaged.append(dict(meeting=meeting, rounds=2, **{k: sum(r[k] for r in group)/2 for k in
                ('E1_setup_energy_s', 'L1_component_service_s', 'prefix_asr_service_s', 'prefix_frontend_service_s',
                 'prefix_cell_service_s', 'L1_reference_decision_s', 'setup_block_wall_s')}))
        for metric in ('E1_setup_energy_s', 'L1_component_service_s', 'L1_minus_E1_setup_s'):
            values = np.asarray([r['L1_component_service_s']-r['E1_setup_energy_s'] if metric == 'L1_minus_E1_setup_s'
                                 else r[metric] for r in setup_averaged])
            boot = values[draws].mean(axis=1)
            setup_effects.append(dict(metric=metric, point=float(values.mean()),
                ci_low=float(np.quantile(boot, .025)), ci_high=float(np.quantile(boot, .975)),
                marginal_confidence=.95, recording_clusters=20, distinct_C1_sources=20, actual_rounds=2,
                inference='secondary marginal descriptive CI; two rounds averaged before recording bootstrap'))
    return dict(cost_per_cell=cells, calibration_costs=setup, cost_round_descriptives=rounds,
        timing_averaged_sources=averaged, timing_contrasts=timing_effects,
        timing_averaged_setup=setup_averaged, timing_setup_uncertainty=setup_effects,
        shared_source_io=shared_io, initialization_costs=initialization, cost_per_recording=per_recording,
        frontend_fallback_counts=fallbacks, main_repeat_drift=drifts)


def compare_runs(left, right):
    old = {(r['id'], r['policy']): r for r in left['calls']}
    out = []
    for r in right['calls']:
        previous = old[r['id'], r['policy']]
        a, b = previous['frontend'].get('selected_channel'), r['frontend'].get('selected_channel')
        out.append(dict(id=r['id'], role=r['role'], policy=r['policy'], meeting=r['meeting'],
            left_repeat=left['manifest']['run_repeat'], right_repeat=right['manifest']['run_repeat'],
            left_raw_text=previous['text'], right_raw_text=r['text'], left_channel=a, right_channel=b,
            raw_text_equal=previous['text'] == r['text'], primary_text_equal=normalize(previous['text']) == normalize(r['text']),
            channel_equal=a == b, waveform_hash_equal=previous['processed_audio']['sha256'] == r['processed_audio']['sha256'],
            calibration_energy_channel_equal=left['decisions'][r['meeting']]['energy_channel'] == right['decisions'][r['meeting']]['energy_channel'],
            calibration_label_channel_equal=left['decisions'][r['meeting']]['label_channel'] == right['decisions'][r['meeting']]['label_channel'],
            interpretation='repeat drift diagnostic only; main quality never replaced'))
    return out


def json_text(value):
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False)+'\n'


def csv_text(rows):
    stream = io.StringIO(newline='')
    fields = list(dict.fromkeys(k for row in rows for k in row)) or ['no_rows']
    writer = csv.DictWriter(stream, fieldnames=fields, lineterminator='\n')
    writer.writeheader()
    for row in rows:
        writer.writerow({k: json.dumps(v, ensure_ascii=False, allow_nan=False) if isinstance(v, (dict, list)) else v
                         for k, v in row.items()})
    return stream.getvalue()


def report(tables, timing, summary):
    lines = ['# Calibration CPU/text analysis', '',
        '800 main Test sources in 20 recording clusters; 20 C1 sources excluded from quality. '
        'Timing repetitions are separate measured executions, not extra quality or independent sources.', '',
        'Primary: equal-recording CER differences, fixed minus dynamic. Positive means fixed worse. '
        '50,000 whole-recording paired draws; seed 2026101601; marginal 98.75% percentile intervals '
        '(nominal 95% Bonferroni family of four within the primary estimator/scoring only).', '',
        '| Contrast | Difference (pp) | 98.75% CI (pp) | 0.5pp band relation | Original 1pp relation |',
        '|---|---:|---:|---|---|']
    for r in tables['contrasts']:
        if r['analysis_role'] == 'primary':
            lines.append(f"| {r['candidate']} − {r['baseline']} | {r['point_pp']:.5f} | "
                         f"[{r['ci_low_pp']:.5f}, {r['ci_high_pp']:.5f}] | {r['decision_band_status']} | "
                         f"{r['original_reference_status']} |")
    lines += ['', 'The ±0.5pp band is a prospective, unvalidated study decision. The original ±1pp reference '
        'is also reported for every contrast. Neither nonsignificance, a one-sided bound, nor an interval '
        'inside a band is automatically called equivalence. No scientific contribution or goal-completion decision is made.', '',
        'Pooled and case-preserved results have separately labelled sensitivity families. Calibrated choices remain '
        'the actual primary C1 choices. Default0 comparisons, filename condition groups, leave-one-condition-out, '
        'same/different C1 tiers and early/late are secondary/descriptive. There is no cross-family joint claim.', '',
        'Early/late uses Test START frames: early iff 2*start < C1_end + original_frames; ties are late. '
        'Speakers are recording::tier labels; filename conditions do not establish physical rooms. '
        'Global people, physical rooms and pretraining overlap remain unknown.', '',
        'All paired cases and all nonzero/text-disagreeing cases in both directions are exported without truncation. '
        'Baseline-perfect damage, candidate-perfect damage, errors, channels and raw texts are retained.', '',
        'EV aggregates describe the actual operational policy including its safety fallback. Per-source and '
        'per-cell cost exports retain ranking validity, fallback flag/reason and actual frontend status. '
        'Per-run/policy fallback counts explicitly include zero; every fallback remains in the frozen '
        'primary denominator and is not treated as a native/SDK failure.', '',
        'Cost tables retain actual full-cell, frontend, ASR and residual service components. L1 setup = '
        'sum of eight complete prefix cell services + E1 energy setup + reference decision. '
        'ASR/frontend sums are separately reported. E1 setup is its actual power/selection computation; '
        'the study’s eight prefix ASR calls are not charged as E1 deployment requirements. '
        'C1 speech, recording elapsed to C1 end, supplied label characters, initialization, shared source I/O '
        'and archive costs are separate. Human labeling latency is unknown; component sums are not observed product startup.', '',
        f"Timing repeats supplied: {summary['timing_repeats']}. When present, 40 distinct Test sources each have two "
        'actual rounds. Source services are averaged across rounds before pairing and recording-cluster uncertainty; '
        '80 observations are not 80 independent sources. Main/repeat text, channel, selection and waveform-hash '
        'drift is exported and never overwrites main quality. Timing inference assumes recording-cluster '
        'exchangeability/independence, conditional on two measured rounds; it does not quantify arbitrary '
        'future-run variability or the full 800-source duration distribution.', '',
        'Passed receipts bind completed/restored inputs, actual code and runtime metadata. This analyzer performs '
        'no physical raw replay, inference or model imports. Receipts and these outputs are not acceptance, '
        'novelty or readiness certificates. Parent owns execution, formal freeze and paper adoption.', '']
    return '\n'.join(lines)


def run_analysis(args):
    ev = Evidence()
    triples = [(args.prepared, args.run, args.raw_receipt)] + list(args.timing_repeat or [])
    need(len(triples) in (1, 3), 'supply both separate timing repeats or neither')
    triples = [tuple(Path(x).absolute() for x in row) for row in triples]
    need(len({str(x[1].resolve()) for x in triples}) == len(triples) and
         len({str(x[2].resolve()) for x in triples}) == len(triples), 'separate attempts and actual receipts required')
    packages = []
    for repeat, (prepared, run, receipt) in enumerate(triples):
        packages.append(gate_run(ev, load_package(ev, prepared, repeat), run, receipt))
    # All run gates must pass before any calls/reference parsing.
    for p in packages:
        load_calls(ev, p)
    refs, features = load_sources(ev, packages[0], packages[1:], args.source_manifest.absolute(),
        args.selection.absolute(), args.source_review.absolute(), args.timing_panel.absolute())
    ev.read(Path(__file__).resolve())
    scored = score(packages[0], refs, features)
    tables, bootstrap = analyze(scored)
    timing = cost_tables(packages)
    failures = [dict(run_repeat=p['manifest']['run_repeat'], planned_cells=p['manifest']['counts']['expected_cells'],
        attempted_cells=len(p['calls']), failed_cells=0, unattempted_cells=0,
        successful_empty_test_cells=sum(r['text'] == '' for r in p['calls'] if r['role'] == 'test'),
        selector_fallback_cells=sum(r['frontend'].get('fallback_used') is True for r in p['calls']),
        interpretation='completed/raw-passed only; failed attempts cannot enter scoring') for p in packages]
    summary = dict(schema='CALIBRATION_TEXT_ANALYSIS_v1', analysis_version=VERSION,
        analysis_python=sys.version, unicode_database_version=unicodedata.unidata_version,
        quality_sources=800, excluded_C1_sources=20, quality_recording_clusters=20, timing_repeats=len(packages)-1,
        primary_estimator='equal_recording_CER_difference', primary_normalization=rules.PRIMARY_NORMALIZATION,
        alignment_tie_order=['diagonal', 'deletion', 'insertion'], case_sensitivity_reselects_channels=False,
        bootstrap=bootstrap, timing_distinct_sources=40 if len(packages) == 3 else 0,
        timing_pooled_with_main=False, physical_raw_replay_by_analyzer=False, NN_calls_added=0,
        human_label_latency_known=False, global_people_independence_known=False,
        physical_room_independence_known=False, pretraining_overlap_known=False,
        scientific_contribution_decision=None, goal_completion_decision=None)
    all_tables = dict(tables, **timing, failures=failures)
    artifacts = {name+'.csv': csv_text(rows) for name, rows in all_tables.items()}
    artifacts['ANALYSIS.json'] = json_text(dict(summary=summary, tables=all_tables))
    artifacts['REPORT.md'] = report(tables, timing, summary)
    ev.stable()
    validation = dict(schema='CALIBRATION_TEXT_VALIDATION_v1', status='metadata_gates_and_text_analysis_completed',
        analyzer_sha256=ev.hashes[str(Path(__file__).resolve())], input_sha256=dict(ev.hashes),
        required_absent_markers=sorted(ev.absent), metadata_inventories={k: sorted(v) for k, v in ev.inventories.items()},
        raw_receipts=[dict(path=str(p['receipt_path']), sha256=ev.hashes[str(p['receipt_path'])],
                           run_repeat=p['manifest']['run_repeat']) for p in packages],
        output_sha256={name: digest(text.encode('utf-8')) for name, text in artifacts.items()},
        summary=summary, validation_self_hash='external OUTPUT_SHA256.json avoids circular hashing')
    artifacts['VALIDATION.json'] = json_text(validation)
    artifacts['OUTPUT_SHA256.json'] = json_text(dict(schema='CALIBRATION_ANALYSIS_OUTPUT_HASHES_v1',
        sha256={name: digest(text.encode('utf-8')) for name, text in artifacts.items()},
        self_hash='not embedded; hash this file externally'))
    output = args.output.absolute()
    for p in packages:
        need(not output.resolve().is_relative_to(p['prepared'].resolve()) and
             not output.resolve().is_relative_to(p['run'].resolve()), 'analysis output must be outside prepared/attempt')
    need(not output.exists(), 'exclusive new output directory required')
    output.mkdir(parents=True, exist_ok=False)
    for name, text in artifacts.items():
        with (output/name).open('x', encoding='utf-8', newline='') as stream:
            stream.write(text)
    for name, text in artifacts.items():
        need(digest((output/name).read_bytes()) == digest(text.encode('utf-8')), 'output write hash mismatch')
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('prepared', 'run', 'raw-receipt', 'source-manifest', 'selection', 'source-review', 'timing-panel', 'output'):
        parser.add_argument('--'+name, required=True, type=Path)
    parser.add_argument('--timing-repeat', action='append', nargs=3, type=Path, metavar=('PREPARED', 'RUN', 'RECEIPT'),
                        help='supply exactly twice, in repeat1 then repeat2 order; never pool with main quality')
    args = parser.parse_args(argv)
    try:
        result = run_analysis(args)
    except (Rejected, ValueError, KeyError, TypeError, OSError) as exc:
        print(json.dumps(dict(status='rejected_no_scientific_decision', error_type=type(exc).__name__, error=str(exc))), file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, allow_nan=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
