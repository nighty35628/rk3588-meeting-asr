#!/usr/bin/env python3
"""Bounded, post-unblinding fixed-channel supplement; text/JSON metadata only.

Import is inert. --self-test uses in-memory synthetic fixtures exclusively.
Actual analysis requires complete, restored, zero-failure, raw-audited inputs.
No native/runner imports, audio/tensor reads, inference, network, or subprocesses.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import csv
import hashlib
import io
import json
import math
from pathlib import Path
import random
import sys
import unicodedata

VERSION = 'fixed-text-analysis-v1'
ROOT = Path(__file__).resolve().parent
PRIOR = ROOT.parent / 'spatial_independent_test_20261015'
FIXED = tuple(f'ch{i}_sense' for i in range(8))
POLICIES = FIXED + ('rms_sense',)
ANCHORS = ('ch0_sense', 'ch4_sense', 'rms_sense')
MODES = ('primary_casefold', 'historical_case_preserved')
SEED, SCHEDULE_SEED, DRAWS, CONFIDENCE = 20261016, 20261015, 10000, 0.99375
PRIMARY_NORMALIZATION = ('UnicodeNFKC then casefold, retain Unicode isalpha or isdigit; '
                         'no numeric word conversion, synonym equivalence or reference edits')
SECONDARY_NORMALIZATION = 'historicalNFKC alpha/digit case-preserved for sensitivity; preserve all original text'
SCORE_KEYS = ('reference_characters', 'errors', 'substitutions', 'deletions', 'insertions')
ROLE = 'post_unblinding_descriptive_supplement'


class Rejected(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Rejected(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key: ' + key)
        result[key] = value
    return result


def parse(text):
    def invalid(value):
        raise Rejected('nonfinite JSON: ' + value)
    return json.loads(text, object_pairs_hook=unique_keys, parse_constant=invalid)


def valid_pin(value):
    return isinstance(value, str) and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


class Evidence:
    """Only explicitly selected metadata/code/text; never follow payload pointers."""
    def __init__(self):
        self.hashes = {}
        self.absent = set()

    def read(self, path, expected=None):
        path = Path(path).resolve()
        require(path.suffix in ('.json', '.jsonl', '.py', '.md'), 'non-metadata read refused: ' + str(path))
        data = path.read_bytes()
        pin = digest(data)
        require(expected is None or (valid_pin(expected) and expected == pin), 'hash mismatch: ' + str(path))
        require(str(path) not in self.hashes or self.hashes[str(path)] == pin, 'input changed: ' + str(path))
        self.hashes[str(path)] = pin
        return data

    def load(self, path, expected=None):
        return parse(self.read(path, expected).decode('utf-8'))

    def lines(self, path, expected=None):
        data = self.read(path, expected).decode('utf-8')
        require(not data or data.endswith('\n'), 'unterminated JSONL: ' + str(path))
        require(all(line.strip() for line in data.splitlines()), 'blank JSONL record: ' + str(path))
        return [parse(line) for line in data.splitlines()]

    def missing(self, path):
        path = Path(path).resolve()
        require(not path.exists(), 'failure/ambiguity marker: ' + str(path))
        self.absent.add(str(path))

    def stable(self):
        for name, pin in self.hashes.items():
            require(digest(Path(name).read_bytes()) == pin, 'input changed before publication: ' + name)
        for name in self.absent:
            require(not Path(name).exists(), 'new failure/ambiguity marker: ' + name)


def normalize(text, casefold=True):
    require(isinstance(text, str), 'text must be a string')
    text = unicodedata.normalize('NFKC', text)
    if casefold:
        text = text.casefold()
    return ''.join(c for c in text if c.isalpha() or c.isdigit())


def edit_counts(reference, hypothesis):
    """Copied mathematical contract from S/analyze_formal.py; no module import.

    Unit-cost Levenshtein; optimal alignment ties: diagonal, deletion, insertion.
    Counts of S/D/I are alignment-dependent; their sum/distance is tie-invariant.
    """
    previous = [(j, 0, 0, j) for j in range(len(hypothesis) + 1)]
    for i, a in enumerate(reference, 1):
        current = [(i, 0, i, 0)]
        for j, b in enumerate(hypothesis, 1):
            d, s, rem, ins = previous[j - 1]
            diagonal = (d + (a != b), s + (a != b), rem, ins)
            d, s, rem, ins = previous[j]
            deletion = (d + 1, s, rem + 1, ins)
            d, s, rem, ins = current[j - 1]
            insertion = (d + 1, s, rem, ins + 1)
            current.append(min((diagonal, deletion, insertion), key=lambda x: x[0]))
        previous = current
    errors, s, d, i = previous[-1]
    require(errors == s + d + i, 'S/D/I accounting')
    return dict(errors=errors, substitutions=s, deletions=d, insertions=i)


def finite(value, nonnegative=True):
    return type(value) in (int, float) and math.isfinite(value) and (not nonnegative or value >= 0)


def near(left, right):
    return finite(left, False) and finite(right, False) and math.isclose(left, right, rel_tol=1e-8, abs_tol=1e-6)


def schedule(samples, policies, seed):
    order = list(policies)
    random.Random(seed).shuffle(order)
    return [dict(id=s['id'], source_position=j, policy=p, policy_position=k)
            for j, s in enumerate(samples)
            for k, p in enumerate(order[j % len(order):] + order[:j % len(order)])]


def safe_member(root, name):
    require(isinstance(name, str) and not Path(name).is_absolute(), 'relative package member required')
    path = (root / name).resolve()
    require(path.is_relative_to(root) and path != root, 'package member escapes root')
    return path


def load_package(ev, prepared, supplement):
    freeze = ev.load(prepared / 'METHOD_FREEZE.json')
    manifest = ev.load(prepared / 'manifest.json', freeze['manifest_sha256'])
    source = ev.load(prepared / 'evidence/source_manifest.json', freeze['source_manifest_sha256'])
    ev.missing(prepared / 'PREPARE_FAILED.json')
    for group in ('code', 'evidence'):
        require(isinstance(freeze[group], dict) and freeze[group], 'empty frozen ' + group)
        for name, pin in freeze[group].items():
            ev.read(safe_member(prepared, name), pin)
    ev.read(prepared / 'PROTOCOL.md', freeze['protocol_sha256'])
    baseline = ev.load(prepared / 'MODEL_ASSET_BASELINE.json', freeze['model_asset_baseline_sha256'])
    receipt = ev.load(prepared / 'PREPARE_RECEIPT.json')
    require(receipt['method_freeze_sha256'] == ev.hashes[str(prepared / 'METHOD_FREEZE.json')]
            and receipt['manifest_sha256'] == freeze['manifest_sha256'], 'prepare receipt binding')
    samples = manifest['samples']
    ids = [r['id'] for r in samples]
    require(len(ids) == len(set(ids)) == 600, 'exactly 600 unique original sources required')
    require(manifest['sample_order'] == ids == [r['id'] for r in source['samples']], 'source order binding')
    require(len({r['meeting'] for r in samples}) == 18, 'exactly 18 original meetings required')
    require(len(manifest['policies']) == len(set(manifest['policies'])) == 9
            and manifest['policies'] == freeze['policies'], 'nine-policy freeze binding')
    if supplement:
        require(set(manifest['policies']) == set(POLICIES), 'all eight fixed channels plus RMS required')
        require(manifest['policies'] == list(POLICIES), 'frozen policy order')
        require(manifest['seed'] == freeze['seed'] == SCHEDULE_SEED, 'supplement schedule seed')
        stats = freeze['supplemental_statistics']
        require(stats['replicates'] == DRAWS and stats['seed'] == SEED
                and stats['marginal_confidence'] == CONFIDENCE
                and stats['nominal_family_confidence'] == .95 and stats['family_size'] == 8,
                'supplemental statistics contract')
        require(freeze['supplemental_comparisons'] == [['rms_sense', p] for p in FIXED]
                and freeze['post_unblinding'] is True and freeze['additional_independent_quality_n'] == 0
                and freeze['fresh_anchor_policies'] == list(ANCHORS)
                and freeze['new_channels'] == [1, 2, 3, 5, 6, 7], 'supplement scope/comparisons contract')
    require(freeze['source_count'] == 600 and freeze['expected_cells'] == 5400, 'frozen matrix dimensions')
    require(manifest['quality_run'] is True and freeze['quality_run'] is True
            and type(manifest['run_repeat']) is int and manifest['run_repeat'] == 0
            and type(freeze['run_repeat']) is int and freeze['run_repeat'] == 0, 'single quality matrix role')
    require(manifest['source_reference_used_for_decisions'] is False, 'reference access declaration')
    require(freeze['primary_normalization'] == PRIMARY_NORMALIZATION
            and freeze['secondary_normalization'] == SECONDARY_NORMALIZATION, 'frozen normalization changed')
    require(manifest['source_manifest_sha256'] == freeze['source_manifest_sha256']
            and manifest['model_asset_baseline_sha256'] == freeze['model_asset_baseline_sha256']
            and manifest['operating_point'] == freeze['operating_point'], 'manifest/freeze cross bindings')
    references = {r['id']: r for r in source['samples']}
    require(source['NN_calls'] == 0, 'source-only reference evidence')
    meeting_rooms = defaultdict(set)
    for row in samples:
        ref = references[row['id']]
        for key in ('meeting', 'room_cluster', 'speaker_cluster', 'sha256', 'pcm_sha256', 'frames',
                    'channels', 'sample_rate', 'encoding'):
            require(row[key] == ref[key], 'source binding: ' + row['id'] + '/' + key)
        require(row['channels'] == 8 and row['sample_rate'] == 16000 and row['encoding'] == 'PCM16', 'source geometry')
        if 'source_audio_sha256' in freeze:
            require(freeze['source_audio_sha256'][row['id']] == row['sha256'], 'declared source hash')
        pointer = ref['source_pointer']
        require(pointer['id'] == row['id'] and pointer['reference'] == ref['reference'], 'source reference pointer')
        require(digest(ref['reference'].encode()) == ref['reference_sha256'] == pointer['reference_utf8_sha256']
                and digest(pointer['raw_reference'].encode()) == pointer['raw_reference_utf8_sha256'], 'reference hashes')
        require(pointer['end_sample'] - pointer['start_sample'] == row['frames']
                and pointer['eligible_whole_utterance'] is True and pointer['source_only'] is True, 'source interval')
        require(all(normalize(ref['reference'], m == MODES[0]) for m in MODES), 'zero reference denominator')
        meeting_rooms[row['meeting']].add(row['room_cluster'])
    require(all(len(rooms) == 1 for rooms in meeting_rooms.values()), 'meeting spans multiple rooms')
    return manifest, freeze, references, baseline


def validate_complete(complete, restored, child, freeze):
    for key, expected in dict(samples=600, policies=9, expected_outputs=5400, outputs=5400,
                              failed_cells=0, sdk_failed_cells=0, actual_teacher_sdk_calls=0).items():
        # Original run has Qwen cells: its teacher count is validated separately.
        if key == 'actual_teacher_sdk_calls' and set(freeze['policies']) != set(POLICIES):
            continue
        require(type(complete.get(key)) is int and complete[key] == expected, 'COMPLETE ' + key)
    require(complete['quality_run'] is True and type(complete['run_repeat']) is int
            and complete['run_repeat'] == 0, 'COMPLETE quality role')
    require(complete['operating_point'] == freeze['operating_point'], 'COMPLETE operating point')
    require(type(child['exit_code']) is int and child['exit_code'] == 0, 'child exit must be zero')
    require(restored['all_restored'] is True and restored['cleanup_errors'] == [], 'normal restoration required')


def receipt_header(receipt, schema):
    require(receipt['schema'] == schema and receipt['status'] == 'passed', 'actual passed raw receipt required')
    require(receipt['actual_completed_run'] is True and type(receipt['NN_calls_added']) is int
            and receipt['NN_calls_added'] == 0, 'CPU-only actual completed raw audit required')
    for key, value in dict(sources=600, cells=5400, policies=9, failed_cells=0, sdk_failed_cells=0).items():
        require(type(receipt[key]) is int and receipt[key] == value, 'raw receipt ' + key)
    require(receipt['attempted_failures'] == [] and valid_pin(receipt['verifier_sha256']), 'raw failure/verifier binding')
    require(receipt['quality_run'] is True and type(receipt['run_repeat']) is int
            and receipt['run_repeat'] == 0, 'raw receipt quality role')
    require(receipt['DSP_decisions_and_waveforms_recomputed'] is True
            and receipt['own_greedy_raw_replayed'] is True, 'actual DSP/raw replay not certified')
    require(receipt['ObservedEncoder_call_output_indices_verified'] is True
            and receipt['all_four_actor_identities_pause_restore_verified'] is True
            and receipt['source_reference_used_for_audit'] is False
            and receipt['scoring_performed'] is False and receipt['SDK_exception_cells'] == [],
            'raw ownership/restoration/audit scope certification')
    require(isinstance(receipt['input_materials_sha256'], dict)
            and valid_pin(receipt['input_calls_sha256']), 'raw receipt hash inventory required')


def validate_restoration(paused, restored, provenance):
    require(paused['boot'] == restored['boot'] == provenance['boot'] == paused['original']['boot'], 'boot identity mismatch')
    identity = ('pid', 'start_ticks', 'exe_path', 'exe_sha256', 'cmdline_sha256', 'uid')
    def index(rows):
        result = {r['pid']: r for r in rows}
        require(len(result) == len(rows), 'duplicate guard process PID')
        return result
    original, stopped, after = (index(rows) for rows in (paused['original']['processes'], paused['after'], restored['after']))
    signals = index(restored['signals'])
    require(original and set(original) == set(stopped) == set(after) == set(signals), 'pause/restore process coverage')
    for pid, before in original.items():
        require(all(stopped[pid][k] == before[k] == after[pid][k] for k in identity), 'process identity changed')
        require(before['state'] not in (None, 'T', 't', 'Z') and stopped[pid]['state'] in ('T', 't')
                and after[pid]['state'] not in (None, 'T', 't', 'Z') and signals[pid]['SIGCONT_sent'] is True,
                'process pause/restoration evidence')


def gate_run(ev, prepared, run, receipt_path, manifest, freeze, baseline, supplement):
    """Gate and bind audited metadata BEFORE parsing any recognized texts."""
    receipt = ev.load(receipt_path)  # Missing receipt fails before calls are opened.
    receipt_header(receipt, 'FIXED_RAW_AUDIT_v1' if supplement else 'FORMAL_RAW_AUDIT_v1')
    pins = receipt['input_materials_sha256']
    # guard/ is the requested spelling; guard_v1/ is the unchanged old runner spelling.
    guards = [run / name for name in ('guard', 'guard_v1') if (run / name).is_dir()]
    require(len(guards) == 1, 'exactly one guard or guard_v1 directory required')
    guard = guards[0]
    ev.missing(run / ('guard_v1' if guard.name == 'guard' else 'guard'))
    for base in (run, run / 'native_v1', guard):
        for name in ('FAILED.json', 'RESTORATION_ATTENTION.json'):
            ev.missing(base / name)
    def bound(path, key):
        require(key in pins and valid_pin(pins[key]), 'raw receipt missing binding: ' + key)
        return ev.load(path, pins[key])
    # These exact bytes must have been audited, even if copies use different roots.
    for name in ('METHOD_FREEZE.json', 'manifest.json', 'PROTOCOL.md', 'MODEL_ASSET_BASELINE.json', 'PREPARE_RECEIPT.json'):
        require(pins.get(name) == ev.hashes[str(prepared / name)], 'raw/package binding: ' + name)
    native = run / 'native_v1'
    metadata = {name: bound(native / (name + '.json'), 'native_v1/' + name + '.json')
                for name in ('COMPLETE', 'PROVENANCE', 'RUNTIME_BINDINGS', 'SCHEDULE', 'INITIALIZATION')}
    guards_data = {name: bound(guard / (name + '.json'), guard.name + '/' + name + '.json')
                   for name in ('CHILD_EXIT', 'RESTORED', 'PAUSED')}
    complete, provenance, runtime = (metadata[k] for k in ('COMPLETE', 'PROVENANCE', 'RUNTIME_BINDINGS'))
    validate_complete(complete, guards_data['RESTORED'], guards_data['CHILD_EXIT'], freeze)
    validate_restoration(guards_data['PAUSED'], guards_data['RESTORED'], provenance)
    if supplement:
        require(provenance['schema'] == 'fixed_channel_supplement_v1', 'supplement provenance schema')
        require(receipt['verifier_sha256'] == freeze['code']['verify_payloads.py'], 'frozen actual raw verifier binding')
    require(provenance['method_freeze_sha256'] == ev.hashes[str(prepared / 'METHOD_FREEZE.json')]
            and provenance['manifest_sha256'] == freeze['manifest_sha256']
            and provenance['protocol_sha256'] == freeze['protocol_sha256']
            and provenance['code_sha256'] == freeze['code'] == receipt['frozen_code_sha256']
            and provenance['evidence_sha256'] == freeze['evidence'] == receipt['frozen_evidence_sha256'], 'runtime/freeze/auditor cross binding')
    require(provenance['runtime_bindings_sha256'] == ev.hashes[str(native / 'RUNTIME_BINDINGS.json')]
            and provenance['source_reference_used_for_decisions'] is False
            and provenance['operating_point'] == freeze['operating_point'] == receipt['operating_point'], 'runtime provenance binding')
    require(runtime == receipt['runtime_assets'], 'raw receipt runtime binding')
    require(runtime['model_assets'] and runtime['loaded_libraries'], 'actual model/library metadata required')
    for name, value in runtime['model_assets'].items():
        require(name in baseline['assets'] and value == {k: baseline['assets'][name][k] for k in ('bytes', 'sha256')}, 'model assets outside baseline')
    require(all(any(kind in name.lower() for name in runtime['loaded_libraries']) for kind in ('rknn', 'rkllm')), 'both resident native library records')
    init = metadata['INITIALIZATION']
    require(init['both_resident'] is True and init['excluded_from_service'] is True
            and init['operating_point'] == freeze['operating_point']
            and finite(init['sensevoice_init_s']) and finite(init['qwen_init_s']), 'resident initialization required')
    sched = metadata['SCHEDULE']
    expected = schedule(manifest['samples'], manifest['policies'], manifest['seed'])
    require(sched['seed'] == manifest['seed'] and sched['rows'] == expected
            and sched['independent_policy_execution'] is True, 'frozen schedule mismatch')
    require(receipt['input_calls_sha256'] == pins['native_v1/calls.jsonl'], 'receipt calls hash disagreement')
    # No model text has been parsed before all gates above have passed.
    calls = ev.lines(native / 'calls.jsonl', receipt['input_calls_sha256'])
    require(len(calls) == 5400, 'complete owned calls matrix required')
    for row, cell in zip(calls, expected):
        require(all(row.get(k) == v for k, v in cell.items()), 'duplicate, missing, reordered, or foreign cell')
    for name in ('CELL_FAILURES.jsonl', 'SDK_FAILURES.jsonl'):
        path = native / name
        if path.exists():
            require('native_v1/' + name in pins, 'failure ledger missing auditor binding')
            require(ev.lines(path, pins['native_v1/' + name]) == [], 'recorded failures forbid final analysis')
        else:
            ev.missing(path)
    if supplement:
        validate_fixed_calls(calls, manifest, freeze, complete, receipt)
    else:
        require(all(r['fatal'] is False and not r['cell_exception'] and not r['asr']['second_failure']
                    and r['asr']['status'] == 'ok' and r['text'] == r['asr']['text'] for r in calls), 'original zero-failure actual records')
    return calls, metadata, receipt


def validate_fixed_calls(calls, manifest, freeze, complete, receipt):
    sources = {r['id']: r for r in manifest['samples']}
    previous_end = None
    totals = defaultdict(int)
    for row in calls:
        source, asr = sources[row['id']], row['asr']
        require(row['quality_run'] is True and type(row['run_repeat']) is int and row['run_repeat'] == 0
                and row['independent_policy_execution'] is True and asr['independent_policy_execution'] is True,
                'cell quality/independent execution role')
        for key in ('meeting', 'room_cluster', 'speaker_cluster'):
            require(row[key] == source[key], 'cell/source metadata mismatch')
        require(row['operating_point'] == freeze['operating_point'] and row['audio_sha256'] == source['sha256']
                and row['audio_samples'] == source['frames'] and row['input_channels'] == 8
                and row['input_PCM_bytes'] == source['frames'] * 16, 'cell source/operating point binding')
        require(isinstance(row['text'], str) and row['text'] == asr['text'] == asr['first']['text'], 'owned actual final text binding')
        require(row['fatal'] is False and not row['cell_exception'] and asr['status'] == 'ok'
                and not asr['second_failure'] and asr['policy'] == 'sense_only' and asr['teacher'] is None
                and asr['invoked'] is False and asr['sdk_calls'] == [] and asr['sdk_errors'] == [], 'any recorded failure/substituted recognizer forbidden')
        for key in ('actual_first_native_calls', 'completed_first_native_calls', 'actual_teacher_sdk_calls'):
            require(type(row[key]) is int and row[key] >= 0, 'native/SDK count type')
            totals[key] += row[key]
        require(row['actual_first_native_calls'] == row['completed_first_native_calls'] > 0
                and row['actual_teacher_sdk_calls'] == 0, 'missing/failed actual native call')
        require(asr['actual_first_native_calls'] == row['actual_first_native_calls']
                and asr['actual_teacher_sdk_calls'] == 0, 'nested actual call counts')
        require(row['source_idle_check']['running'] is False, 'source service not idle')
        front = row['frontend']
        require(front['output_normalized'] is False and front['output_clipped'] is False, 'unrequested gain/clipping')
        if row['policy'] in FIXED:
            require(front['method'] == 'fixed_channel'
                    and type(front['selected_channel']) is int
                    and front['selected_channel'] == int(row['policy'][2]), 'fixed channel substitution')
        else:
            require(front['method'] == 'rmsmax' and type(front['selected_channel']) is int
                    and 0 <= front['selected_channel'] < 8, 'RMS frontend/channel declaration')
        for key in ('frontend_s', 'service_s', 'research_archive_s', 'start_monotonic', 'final_computed_monotonic'):
            require(finite(row[key]), 'nonfinite/negative time')
        require(finite(asr['service_s']) and finite(row['frontend_plus_asr_residual_s'], False)
                and near(row['service_s'], row['frontend_s'] + asr['service_s'] + row['frontend_plus_asr_residual_s'])
                and near(row['service_s'], row['final_computed_monotonic'] - row['start_monotonic']), 'service decomposition')
        require(previous_end is None or row['start_monotonic'] >= previous_end, 'overlapping cells')
        previous_end = row['final_computed_monotonic']
    for key in ('actual_first_native_calls', 'actual_teacher_sdk_calls'):
        require(complete[key] == receipt[key] == totals[key], 'actual native/SDK totals mismatch')
    require(complete['first_policy_calls'] == receipt['first_policy_calls'] == 5400
            and complete['teacher_policy_calls'] == receipt['teacher_policy_calls'] == 0, 'actual policy totals')
    require(complete['unique_raw_payloads'] == receipt['raw_payloads']
            and complete['processed_audio_files'] == receipt['processed_waveforms'], 'audited archive metadata totals')


def score(calls, references, policies=None):
    rows = []
    for line, call in enumerate(calls, 1):
        if policies is not None and call['policy'] not in policies:
            continue
        source = references[call['id']]
        for mode in MODES:
            ref, hyp = (normalize(t, mode == MODES[0]) for t in (source['reference'], call['text']))
            counts = edit_counts(ref, hyp)
            rows.append(dict(id=call['id'], meeting=source['meeting'], room=source['room_cluster'],
                             speaker=source['speaker_cluster'], policy=call['policy'], mode=mode,
                             reference=source['reference'], raw_text=call['text'], normalized_reference=ref,
                             normalized_text=hyp, reference_characters=len(ref), **counts,
                             cer=counts['errors'] / len(ref), calls_jsonl_line=line,
                             processed_waveform_sha256=(call.get('processed_audio') or {}).get('sha256'),
                             selected_channel=(call.get('frontend') or {}).get('selected_channel')))
    return rows


def aggregate(rows):
    require(rows, 'empty scoring group')
    sums = {key: sum(r[key] for r in rows) for key in SCORE_KEYS}
    require(sums['reference_characters'] > 0, 'empty denominator')
    return dict(n_sources=len(rows), **sums, cer=sums['errors'] / sums['reference_characters'])


def cluster_effect(delta, refs, draws):
    """Paired percentile meeting bootstrap; fraction units (report multiplies by100)."""
    import numpy as np
    delta, refs = np.asarray(delta, dtype=float), np.asarray(refs, dtype=float)
    require(delta.ndim == refs.ndim == 1 and len(delta) == len(refs) > 0
            and np.isfinite(delta).all() and np.isfinite(refs).all() and (refs > 0).all(), 'cluster dimensions')
    require(draws.ndim == 2 and draws.shape[1] == len(refs), 'paired draw dimensions')
    bootstrap = dict(pooled=delta[draws].sum(axis=1) / refs[draws].sum(axis=1),
                     equal_meeting=(delta / refs)[draws].mean(axis=1))
    points = dict(pooled=float(delta.sum() / refs.sum()), equal_meeting=float((delta / refs).mean()))
    tail = (1 - CONFIDENCE) / 2
    return {estimator: dict(point=points[estimator], ci_low=float(np.quantile(values, tail, method='linear')),
                            ci_high=float(np.quantile(values, 1 - tail, method='linear')))
            for estimator, values in bootstrap.items()}


def branch(contrasts):
    """Descriptive scope: RMS has lower CER than EVERY one of the eight fixed channels."""
    require(len(contrasts) == 8 and {r['baseline'] for r in contrasts} == set(FIXED), 'full eight-comparison family required')
    if all(r['ci_high'] < 0 for r in contrasts):
        return 'support'
    if any(r['ci_low'] > 0 for r in contrasts):
        return 'contradiction'
    return 'unresolved'


def analyze(rows, samples):
    import numpy as np
    meetings = sorted({s['meeting'] for s in samples})
    rooms = sorted({s['room_cluster'] for s in samples})
    draws = np.random.default_rng(SEED).integers(0, len(meetings), (DRAWS, len(meetings)))
    tables = {k: [] for k in ('per_policy', 'per_meeting', 'per_room', 'paired_sources', 'paired_meetings',
                              'contrasts', 'test_best_fixed', 'oracle_diagnostic', 'oracle_sources')}
    decisions = []
    for mode in MODES:
        selected = [r for r in rows if r['mode'] == mode]
        indexed = {(r['id'], r['policy']): r for r in selected}
        for policy in POLICIES:
            group = [r for r in selected if r['policy'] == policy]
            mt = [dict(mode=mode, policy=policy, meeting=m,
                       room=next(r['room'] for r in group if r['meeting'] == m),
                       **aggregate([r for r in group if r['meeting'] == m])) for m in meetings]
            tables['per_meeting'].extend(mt)
            tables['per_room'].extend(dict(mode=mode, policy=policy, room=room,
                                          **aggregate([r for r in group if r['room'] == room])) for room in rooms)
            tables['per_policy'].append(dict(mode=mode, policy=policy, **aggregate(group),
                                             n_meetings=len(mt), equal_meeting_cer=sum(r['cer'] for r in mt) / len(mt)))
        for fixed in FIXED:
            pairs = []
            for source in samples:
                left, right = (indexed[source['id'], p] for p in ('rms_sense', fixed))
                delta = left['errors'] - right['errors']
                pairs.append(dict(mode=mode, candidate='rms_sense', baseline=fixed, id=source['id'],
                                  meeting=source['meeting'], room=source['room_cluster'],
                                  reference_characters=left['reference_characters'], candidate_errors=left['errors'],
                                  baseline_errors=right['errors'], error_delta=delta,
                                  cer_delta=delta / left['reference_characters'],
                                  baseline_zero_damage=right['errors'] == 0 and delta > 0))
            tables['paired_sources'].extend(pairs)
            mp = []
            for meeting in meetings:
                subset = [r for r in pairs if r['meeting'] == meeting]
                delta = sum(r['error_delta'] for r in subset)
                refs = sum(r['reference_characters'] for r in subset)
                mp.append(dict(mode=mode, candidate='rms_sense', baseline=fixed, meeting=meeting, room=subset[0]['room'],
                               n_sources=len(subset), error_delta=delta, reference_characters=refs, cer_delta=delta / refs))
            tables['paired_meetings'].extend(mp)
            effects = cluster_effect([r['error_delta'] for r in mp], [r['reference_characters'] for r in mp], draws)
            for estimator, effect in effects.items():
                tables['contrasts'].append(dict(mode=mode, estimator=estimator, candidate='rms_sense', baseline=fixed,
                    role=ROLE, marginal_confidence=CONFIDENCE, nominal_familywise_confidence=.95,
                    family_size=8, family_scope='within this estimator and normalization; no16-joint claim',
                    n_sources=len(samples), n_meetings=len(meetings), **effect,
                    improved_sources=sum(r['error_delta'] < 0 for r in pairs),
                    damaged_sources=sum(r['error_delta'] > 0 for r in pairs),
                    unchanged_sources=sum(r['error_delta'] == 0 for r in pairs),
                    baseline_zero_sources=sum(r['baseline_errors'] == 0 for r in pairs),
                    baseline_zero_damaged=sum(r['baseline_zero_damage'] for r in pairs),
                    improved_meetings=sum(r['error_delta'] < 0 for r in mp),
                    damaged_meetings=sum(r['error_delta'] > 0 for r in mp),
                    unchanged_meetings=sum(r['error_delta'] == 0 for r in mp),
                    practical_reference_cer_delta=-.01))
        mode_policies = [r for r in tables['per_policy'] if r['mode'] == mode]
        for estimator, key in (('pooled', 'cer'), ('equal_meeting', 'equal_meeting_cer')):
            fixed_rows = [r for r in mode_policies if r['policy'] in FIXED]
            best = min(r[key] for r in fixed_rows)
            rms = next(r[key] for r in mode_policies if r['policy'] == 'rms_sense')
            tables['test_best_fixed'].append(dict(mode=mode, estimator=estimator,
                tied_best_policies=[r['policy'] for r in fixed_rows if r[key] == best],
                diagnostic_best_policy=next(r['policy'] for r in fixed_rows if r[key] == best),
                ranking=[r['policy'] for r in sorted(fixed_rows, key=lambda r: (r[key], int(r['policy'][2])))],
                tie_rule='lower channel index',
                test_best_fixed_cer=best, rms_cer=rms, rms_minus_test_best_fixed=rms - best,
                role='optimistic same-Test selected diagnostic; not a calibrated deployable policy',
                selected_best_ci=None, limitation='selection/nonregularity; use the full eight-comparison family'))
            family = [r for r in tables['contrasts'] if r['mode'] == mode and r['estimator'] == estimator]
            decisions.append(dict(mode=mode, estimator=estimator, branch=branch(family), role=ROLE,
                                  claim='RMS lower CER than all eight fixed channels in this bounded supplement'))
        oracle = []
        for source in samples:
            options = [indexed[source['id'], p] for p in FIXED]
            best = min(r['errors'] for r in options)
            winner = next(r for r in options if r['errors'] == best)
            oracle.append(dict(winner, policy='per_utterance_min_fixed_oracle',
                               tied_min_channels=[r['policy'] for r in options if r['errors'] == best]))
        tables['oracle_sources'].extend(oracle)
        tables['oracle_diagnostic'].append(dict(mode=mode, **aggregate(oracle),
            equal_meeting_cer=sum(aggregate([r for r in oracle if r['meeting'] == m])['cer'] for m in meetings) / len(meetings),
            role='reference-informed per-utterance lower bound over eight fixed outputs only; not proposed policy',
            limitation='not a bound over every possible selector or unseen ASR execution; no inference interval'))
    return tables, decisions, digest(draws.astype('<i8').tobytes(order='C'))


def compare_anchors(fresh_rows, old_rows):
    old = {(r['id'], r['policy'], r['mode']): r for r in old_rows}
    comparisons = []
    for fresh in fresh_rows:
        if fresh['policy'] not in ANCHORS:
            continue
        prior = old[fresh['id'], fresh['policy'], fresh['mode']]
        require(fresh['normalized_reference'] == prior['normalized_reference'], 'anchor reference changed')
        comparisons.append(dict(id=fresh['id'], policy=fresh['policy'], mode=fresh['mode'], meeting=fresh['meeting'],
            room=fresh['room'], fresh_calls_line=fresh['calls_jsonl_line'], original_calls_line=prior['calls_jsonl_line'],
            original_raw_text=prior['raw_text'], fresh_raw_text=fresh['raw_text'],
            raw_text_equal=prior['raw_text'] == fresh['raw_text'],
            original_processed_waveform_sha256=prior['processed_waveform_sha256'],
            fresh_processed_waveform_sha256=fresh['processed_waveform_sha256'],
            processed_waveform_equal=prior['processed_waveform_sha256'] == fresh['processed_waveform_sha256'],
            original_selected_channel=prior['selected_channel'], fresh_selected_channel=fresh['selected_channel'],
            selected_channel_equal=prior['selected_channel'] == fresh['selected_channel'],
            original_normalized_text=prior['normalized_text'], fresh_normalized_text=fresh['normalized_text'],
            normalized_text_equal=prior['normalized_text'] == fresh['normalized_text'],
            scores_equal=all(prior[k] == fresh[k] for k in SCORE_KEYS),
            **{'original_' + k: prior[k] for k in SCORE_KEYS},
            **{'fresh_' + k: fresh[k] for k in SCORE_KEYS},
            **{k + '_delta': fresh[k] - prior[k] for k in SCORE_KEYS},
            original_cer=prior['cer'], fresh_cer=fresh['cer'], cer_delta=fresh['cer'] - prior['cer']))
    summary = []
    for mode in MODES:
        for policy in ANCHORS:
            group = [r for r in comparisons if r['mode'] == mode and r['policy'] == policy]
            require(len(group) == 600, 'anchor coverage')
            summary.append(dict(mode=mode, policy=policy, n_sources=600,
                raw_text_mismatches=sum(not r['raw_text_equal'] for r in group),
                normalized_text_mismatches=sum(not r['normalized_text_equal'] for r in group),
                per_source_score_mismatches=sum(not r['scores_equal'] for r in group),
                processed_waveform_mismatches=sum(not r['processed_waveform_equal'] for r in group),
                selected_channel_mismatches=sum(not r['selected_channel_equal'] for r in group),
                original_errors=sum(r['original_errors'] for r in group), fresh_errors=sum(r['fresh_errors'] for r in group),
                reference_characters=sum(r['fresh_reference_characters'] for r in group),
                role='fresh versus original actual text/score reproducibility diagnostic; zero new confirmation n'))
    return comparisons, summary


def costs(calls):
    """Fresh phase only; never accept old cost rows or merge phases."""
    import numpy as np
    result = []
    for policy in POLICIES:
        group = [r for r in calls if r['policy'] == policy]
        for component, values in (
            ('frontend', [r['frontend_s'] for r in group]),
            ('asr', [r['asr']['service_s'] for r in group]),
            ('residual', [r['frontend_plus_asr_residual_s'] for r in group]),
            ('service', [r['service_s'] for r in group]),
            ('research_archive_excluded', [r['research_archive_s'] for r in group])):
            result.append(dict(policy=policy, phase='fixed_channel_supplement_only', component=component,
                n_cells=len(values), total_s=float(sum(values)), mean_s=float(np.mean(values)),
                median_s=float(np.median(values)), p95_s=float(np.quantile(values, .95, method='linear')),
                min_s=min(values), max_s=max(values)))
    return result


def json_text(value):
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + '\n'


def csv_text(rows):
    out = io.StringIO(newline='')
    fields = list(dict.fromkeys(k for row in rows for k in row))
    writer = csv.DictWriter(out, fieldnames=fields, lineterminator='\n')
    writer.writeheader()
    for row in rows:
        writer.writerow({k: json.dumps(v, ensure_ascii=False, allow_nan=False) if isinstance(v, (list, dict)) else v
                         for k, v in row.items()})
    return out.getvalue()


def report(summary, tables):
    lines = ['# Fixed-channel post-unblinding descriptive supplement', '',
        f"Primary pooled branch: **{summary['branch']}**. Scope: RMS lower CER than all eight fixed channels.",
        'This is posthoc descriptive evidence; it is not original primary confirmation or a publication guarantee.', '',
        '600 original sources / 18 meeting clusters. 5,400 fresh policy results = 3,600 missing-channel cells +',
        '1,800 fresh ch0/ch4/RMS anchor cells. Additional independent quality n = 0.', '',
        '## Policy points (primary normalization)', '',
        '|Policy|Sources|S|D|I|Reference characters|Pooled CER %|Equal-meeting CER %|',
        '|---|---:|---:|---:|---:|---:|---:|---:|']
    for r in tables['per_policy']:
        if r['mode'] == MODES[0]:
            lines.append(f"|{r['policy']}|{r['n_sources']}|{r['substitutions']}|{r['deletions']}|{r['insertions']}|"
                         f"{r['reference_characters']}|{100*r['cer']:.5f}|{100*r['equal_meeting_cer']:.5f}|")
    lines += ['', '## RMS minus fixed contrasts', '',
        'Negative deltas favor RMS. All deltas/intervals below are percentage points.',
        'Paired meeting bootstrap: 10,000 draws, seed 20261016, linear percentile quantiles.',
        'Eight marginal 99.375% intervals give nominal Bonferroni 95% coverage WITHIN each estimator and',
        'normalization family under the bootstrap approximation. Pooled is the main presentation;',
        'equal-meeting and historical case-preserved results are separate sensitivities.',
        'There is no joint 16-comparison or cross-normalization coverage claim.', '',
        '|Normalization|Estimator|Fixed baseline|Delta pp|99.375% CI pp|', '|---|---|---|---:|---|']
    for r in tables['contrasts']:
        lines.append(f"|{r['mode']}|{r['estimator']}|{r['baseline']}|{100*r['point']:.5f}|"
                     f"[{100*r['ci_low']:.5f}, {100*r['ci_high']:.5f}]|")
    lines += ['', '## Branch rules and diagnostics', '',
        'For each family: support iff every upper bound <0; contradiction iff any lower bound >0;',
        'otherwise unresolved. Boundary zero is unresolved; unresolved does not establish equality.', '',
        '|Normalization|Estimator|Descriptive branch|', '|---|---|---|']
    lines += [f"|{r['mode']}|{r['estimator']}|{r['branch']}|" for r in summary['decisions']]
    lines += ['', 'Test-best fixed is reselected separately for each estimator on this same Test data.',
        'Its point is optimistically selected and is not a calibrated deployable policy. No selected-best',
        'bootstrap interval is supplied; the eight-comparison families guard channel selection within estimator.',
        'Per-utterance min-fixed oracle is a reference-informed lower bound over these eight outputs only.',
        'It is a diagnostic, not a proposed policy.', '',
        '## Fresh versus original anchors', '',
        '|Normalization|Anchor|Raw mismatches|Normalized mismatches|Per-source S/D/I score mismatches|',
        '|---|---|---:|---:|---:|']
    lines += [f"|{r['mode']}|{r['policy']}|{r['raw_text_mismatches']}|{r['normalized_text_mismatches']}|"
              f"{r['per_source_score_mismatches']}|" for r in tables['anchor_summary']]
    lines += ['', 'All paired anchor texts, scores, selected channels and waveform hash identities are retained in anchor_comparison.json/csv.',
        'Any drift limits transfer back to the original phase; anchors do not add independent confirmation.',
        'Original primary results remain untouched. Old costs are neither compared nor pooled here.', '',
        '## Evidence and limitations', '',
        'Final outputs require a passed actual CPU raw-audit receipt bound to this complete zero-failure run,',
        'normal child exit/restoration, exact package/runtime/schedule metadata and 5,400 owned cells.',
        'The analyzer checks receipt bindings; it does not itself reopen or replay audio/tensor bytes.',
        'Costs use this fresh phase only, with both actual models resident. Initialization, source I/O and',
        'research archiving are excluded from service; this is not live-capture latency or an energy measure.',
        'Meeting bootstrap does not establish independent rooms/speakers or remove post-unblinding bias.',
        'Only 18 meeting clusters and extreme marginal tails limit interval precision; nominal bootstrap',
        'coverage is an approximation, not a finite-sample guarantee. No p-values or acceptance guarantee.',
        'The prior one-percentage-point improvement is a practical reference, not a threshold for the branch rules.',
        'VALIDATION.json binds every consumed input/code file, software/normalization versions and outputs.', '']
    return '\n'.join(lines)


def run_analysis(prepared, run, raw_receipt, output):
    require(prepared == ROOT / 'prepared_01' and run == ROOT / 'attempt_01', 'only authorized prepared_01/attempt_01')
    require(raw_receipt == ROOT / 'FIXED_RAW_AUDIT_v1.json', 'only authorized fixed raw receipt')
    require(output.parent == ROOT and output.name.startswith('analysis_') and not output.exists(), 'fresh exclusive sibling analysis_* required')
    ev = Evidence()
    # Also bind the analysis implementation and its schema documentation.
    ev.read(Path(__file__).resolve())
    ev.read(ROOT / 'ANALYSIS_IMPLEMENTATION_NOTES.md')
    ev.read(PRIOR / 'analyze_formal.py')  # Scoring-contract source only; never imported/executed.
    manifest, freeze, references, baseline = load_package(ev, prepared, True)
    old_prepared = PRIOR / 'prepared_01'
    old_manifest, old_freeze, old_references, old_baseline = load_package(ev, old_prepared, False)
    require(freeze['source_manifest_sha256'] == old_freeze['source_manifest_sha256']
            and references == old_references, 'original 600-source/reference evidence must be byte-identical')
    geometry = ('id', 'meeting', 'room_cluster', 'speaker_cluster', 'sha256', 'pcm_sha256', 'frames', 'channels', 'sample_rate', 'encoding')
    require([{k: r[k] for k in geometry} for r in manifest['samples']]
            == [{k: r[k] for k in geometry} for r in old_manifest['samples']], 'original source matrix changed')
    require(freeze['operating_point'] == old_freeze['operating_point']
            and freeze['model_asset_baseline_sha256'] == old_freeze['model_asset_baseline_sha256'], 'same original models/operating point required')
    require(freeze['original_main_method_sha256'] == ev.hashes[str(old_prepared / 'METHOD_FREEZE.json')], 'original method freeze binding')
    calls, metadata, receipt = gate_run(ev, prepared, run, raw_receipt, manifest, freeze, baseline, True)
    old_calls, old_metadata, _ = gate_run(ev, old_prepared, PRIOR / 'attempt_01',
        PRIOR / 'FORMAL_FORMAL_RAW_AUDIT_v1.json', old_manifest, old_freeze, old_baseline, False)
    for key in ('model_assets', 'loaded_libraries', 'versions'):
        require(metadata['RUNTIME_BINDINGS'][key] == old_metadata['RUNTIME_BINDINGS'][key], 'actual original runtime differs: ' + key)
    rows = score(calls, references)
    old_rows = score(old_calls, old_references, ANCHORS)  # Anchor texts only; no old analysis is rerun/imported.
    tables, decisions, draw_pin = analyze(rows, manifest['samples'])
    tables['anchor_comparison'], tables['anchor_summary'] = compare_anchors(rows, old_rows)
    tables['fresh_phase_costs'] = costs(calls)
    tables['per_source'] = rows
    room_counts = []
    total_chars = sum(len(normalize(r['reference'])) for r in references.values())
    for room in sorted({s['room_cluster'] for s in manifest['samples']}):
        subset = [s for s in manifest['samples'] if s['room_cluster'] == room]
        chars = sum(len(normalize(references[s['id']]['reference'])) for s in subset)
        room_counts.append(dict(room=room, n_sources=len(subset), n_meetings=len({s['meeting'] for s in subset}),
                                primary_reference_characters=chars, source_share=len(subset) / 600,
                                reference_character_share=chars / total_chars))
    tables['room_counts'] = room_counts
    summary = dict(schema='FIXED_ANALYSIS_v1', status='actual_audited_data_descriptively_analyzed', role=ROLE,
        branch=next(r['branch'] for r in decisions if r['mode'] == MODES[0] and r['estimator'] == 'pooled'),
        decisions=decisions, n_sources=600, n_meetings=18, n_rooms=len(room_counts), fresh_cells=5400,
        missing_channel_cells=3600, fresh_anchor_cells=1800, additional_independent_quality_n=0,
        primary_reference_characters=sum(len(normalize(r['reference'])) for r in references.values()),
        original_primary_results_modified=False, old_phase_costs_used=False,
        anchor_drift_observed=any(r['raw_text_mismatches'] or r['per_source_score_mismatches']
                                 or r['processed_waveform_mismatches'] or r['selected_channel_mismatches']
                                 for r in tables['anchor_summary']),
        actual_raw_receipt_sha256=ev.hashes[str(raw_receipt)], raw_replay_performed_by_analyzer=False,
        test_best_fixed=tables['test_best_fixed'], oracle_diagnostic=tables['oracle_diagnostic'])
    artifacts = {'summary.json': json_text(summary), 'REPORT.md': report(summary, tables)}
    for name, records in tables.items():
        artifacts[name + '.json'] = json_text(records)
        artifacts[name + '.csv'] = csv_text(records)
    import numpy as np
    validation = dict(schema='FIXED_ANALYSIS_VALIDATION_v1', status=summary['status'], role=ROLE,
        gates_validated=True, input_sha256=dict(ev.hashes), required_absent_markers=sorted(ev.absent),
        analyzer_sha256=ev.hashes[str(Path(__file__).resolve())], analysis_version=VERSION,
        scoring_version='S/analyze_formal.py normalize+unit-Levenshtein alignment contract; local copy v1',
        python=sys.version, unicode_database_version=unicodedata.unidata_version, numpy_version=np.__version__,
        primary_normalization=PRIMARY_NORMALIZATION, secondary_normalization=SECONDARY_NORMALIZATION,
        alignment_ties='diagonal,deletion,insertion', normalization_order='NFKC -> optional casefold -> isalpha or isdigit',
        bootstrap=dict(seed=SEED, draws=DRAWS, unit='meeting preserving all source pairs',
            rng='numpy.default_rng PCG64', quantiles='linear percentile', marginal_confidence=CONFIDENCE,
            nominal_familywise_confidence=.95, family_size=8, family_scope='within estimator and normalization only',
            joint16_claim=False, meeting_order=sorted({s['meeting'] for s in manifest['samples']}),
            draw_matrix_little_endian_int64_sha256=draw_pin),
        raw_receipt_schema=receipt['schema'], raw_receipt_status=receipt['status'],
        physical_raw_replay_by_this_analyzer=False, output_sha256={n: digest(t.encode()) for n, t in artifacts.items()},
        self_hash_rule='VALIDATION.json excluded from its own inventory; SHA256SUMS.json hashes it after serialization')
    artifacts['VALIDATION.json'] = json_text(validation)
    artifacts['SHA256SUMS.json'] = json_text({n: digest(t.encode()) for n, t in artifacts.items()})
    ev.stable()
    output.mkdir(exist_ok=False)
    # VALIDATION and SHA256SUMS are deliberately last. I/O failures may leave an incomplete NEW directory.
    for name, text in artifacts.items():
        with (output / name).open('x', encoding='utf-8', newline='') as stream:
            stream.write(text)
    return summary


def self_test():
    """No files, old outputs, prepared packages, models, audio, or tensors are read."""
    import copy
    import itertools
    import numpy as np
    require(normalize('Ａß Z-12!') == 'assz12' and normalize('Ａß Z-12!', False) == 'AßZ12', 'casefold fixture')
    require(normalize('一二3²，é_') == '一二32é' and normalize('12') != normalize('十二'), 'Unicode/no numeral rewrite')
    for ref, hyp, expected in [('abc', 'axc', (1, 0, 0)), ('abc', 'ac', (0, 1, 0)),
                                ('ac', 'abc', (0, 0, 1)), ('abc', '', (0, 3, 0)), ('', 'abc', (0, 0, 3))]:
        result = edit_counts(ref, hyp)
        require(tuple(result[k] for k in ('substitutions', 'deletions', 'insertions')) == expected, 'known S/D/I')
    # Independent recursive distance oracle for every short binary string pair.
    from functools import lru_cache
    @lru_cache(None)
    def distance(a, b):
        if not a or not b:
            return len(a) + len(b)
        return min(distance(a[1:], b) + 1, distance(a, b[1:]) + 1, distance(a[1:], b[1:]) + (a[0] != b[0]))
    words = [''] + [''.join(s) for n in (1, 2, 3) for s in itertools.product('ab', repeat=n)]
    for a in words:
        for b in words:
            require(edit_counts(a, b)['errors'] == distance(a, b), 'independent edit-distance oracle')
    draws = np.array([[0, 0], [0, 1], [1, 0], [1, 1]])
    effect = cluster_effect([10, -2], [100, 10], draws)
    require(near(effect['pooled']['point'], 8 / 110) and near(effect['equal_meeting']['point'], -.05), 'estimator weights')
    # Analytically interpolated sorted four-draw distribution, not the implementation formula.
    t = (1 - CONFIDENCE) / 2
    require(near(effect['pooled']['ci_low'], -.2 + 3*t*(8/110 + .2))
            and near(effect['pooled']['ci_high'], .1 - 3*t*(.1 - 8/110)), 'enumerated paired quantiles')
    require(cluster_effect([0, 0], [1, 10], draws)['pooled']['ci_high'] == 0, 'identical paired effects')
    require(np.array_equal(np.random.default_rng(SEED).integers(0, 18, (DRAWS, 18)),
                           np.random.default_rng(SEED).integers(0, 18, (DRAWS, 18))), 'seed reproducibility')
    family = [dict(baseline=p, ci_low=-.2, ci_high=-.1) for p in FIXED]
    require(branch(family) == 'support', 'support branch')
    family[0] = dict(family[0], ci_low=-.1, ci_high=0.)
    require(branch(family) == 'unresolved', 'zero boundary unresolved')
    family[0] = dict(family[0], ci_low=.01, ci_high=.1)
    require(branch(family) == 'contradiction', 'contradiction branch')
    def rejected(fn, label):
        try:
            fn()
        except (Rejected, KeyError, TypeError):
            return
        raise AssertionError('failed rejection fixture: ' + label)
    rejected(lambda: branch(family[:7]), 'incomplete eight-family')
    rejected(lambda: parse('{"a":1,"a":2}'), 'duplicate JSON')
    rejected(lambda: parse('{"a":NaN}'), 'nonfinite JSON')
    complete = dict(samples=600, policies=9, expected_outputs=5400, outputs=5400, failed_cells=0,
                    sdk_failed_cells=0, actual_teacher_sdk_calls=0, quality_run=True, run_repeat=0, operating_point='fixture')
    restored = dict(all_restored=True, cleanup_errors=[])
    freeze = dict(policies=list(POLICIES), operating_point='fixture')
    validate_complete(complete, restored, dict(exit_code=0), freeze)
    for key, value in (('outputs', 5399), ('failed_cells', 1), ('sdk_failed_cells', 1), ('samples', 5400), ('outputs', True)):
        rejected(lambda k=key, v=value: validate_complete(dict(complete, **{k: v}), restored, dict(exit_code=0), freeze), key)
    rejected(lambda: validate_complete(complete, restored, dict(exit_code=1), freeze), 'nonzero exit')
    rejected(lambda: validate_complete(complete, dict(restored, all_restored=False), dict(exit_code=0), freeze), 'restoration')
    receipt = dict(schema='FIXED_RAW_AUDIT_v1', status='passed', actual_completed_run=True, NN_calls_added=0,
        sources=600, cells=5400, policies=9, failed_cells=0, sdk_failed_cells=0, attempted_failures=[],
        verifier_sha256='a'*64, quality_run=True, run_repeat=0, DSP_decisions_and_waveforms_recomputed=True,
        own_greedy_raw_replayed=True, input_materials_sha256={}, input_calls_sha256='b'*64)
    receipt.update(ObservedEncoder_call_output_indices_verified=True,
        all_four_actor_identities_pause_restore_verified=True, source_reference_used_for_audit=False,
        scoring_performed=False, SDK_exception_cells=[])
    receipt_header(receipt, 'FIXED_RAW_AUDIT_v1')
    for key, value in (('status', 'pending'), ('schema', 'FORMAL_RAW_AUDIT_v1'), ('actual_completed_run', False),
                       ('cells', 1800), ('NN_calls_added', 1), ('attempted_failures', [{}])):
        rejected(lambda k=key, v=value: receipt_header(dict(receipt, **{k: v}), 'FIXED_RAW_AUDIT_v1'), 'raw ' + key)
    # Guard identities must match, not just list lengths and all_restored.
    actor = dict(pid=1, start_ticks=2, exe_path='/fixture', exe_sha256='a', cmdline_sha256='b', uid='u', state='S')
    paused = dict(boot='b', original=dict(boot='b', processes=[actor]), after=[dict(actor, state='T')])
    restored = dict(boot='b', after=[actor], signals=[dict(pid=1, SIGCONT_sent=True)])
    validate_restoration(paused, restored, dict(boot='b'))
    bad = copy.deepcopy(restored)
    bad['after'][0]['start_ticks'] += 1
    rejected(lambda: validate_restoration(paused, bad, dict(boot='b')), 'PID reuse')
    # Small full matrix exercises all9 policies, both estimators, selection, oracle, pairing and anchors.
    samples = [dict(id=str(i), meeting='m'+str(i//2), room_cluster='r'+str(i//2), speaker_cluster='s') for i in range(4)]
    refs = {s['id']: dict(s, reference='abc') for s in samples}
    calls = [dict(id=s['id'], policy=p, text='abc' if p == 'rms_sense' else ('ac' if p == 'ch0_sense' else 'axc'))
             for s in samples for p in POLICIES]
    rows = score(calls, refs)
    tables, decisions, pin = analyze(rows, samples)
    require(len(tables['per_policy']) == 18 and len(tables['contrasts']) == 32
            and all(d['branch'] == 'support' for d in decisions) and valid_pin(pin), 'full synthetic matrix')
    require(all(r['n_sources'] == 4 for r in tables['per_policy']) and all(r['cer'] == 1/3 for r in tables['oracle_diagnostic']), 'n and oracle')
    comparison, anchors = compare_anchors_synthetic(rows)
    require(all(r['scores_equal'] for r in comparison), 'identical anchors')
    self_test_run_gate()
    print('PASS: synthetic scoring/oracle, all9 rows, pairing/weights/quantiles/seed,8-family branches, complete/raw/guard gates; no experiment files read or written')


def compare_anchors_synthetic(rows):
    """Exercise anchor fields without changing production's required n=600."""
    expanded = []
    for row in rows:
        for repeat in range(150):
            expanded.append(dict(row, id=row['id'] + '_' + str(repeat)))
    return compare_anchors(expanded, [r for r in expanded if r['policy'] in ANCHORS])


def self_test_run_gate():
    """Full 5400-cell in-memory gate; corruptions must not expose texts early."""
    from unittest.mock import patch
    prepared, run, receipt_path = (Path(name) for name in ('synthetic_prepared', 'synthetic_run', 'synthetic_receipt.json'))
    samples = [dict(id=str(i), meeting='m'+str(i % 18), room_cluster='r', speaker_cluster='s',
                    sha256='a'*64, frames=1) for i in range(600)]
    manifest = dict(samples=samples, policies=list(POLICIES), seed=SCHEDULE_SEED)
    freeze = dict(policies=list(POLICIES), operating_point='fixture', manifest_sha256='a'*64,
                  protocol_sha256='a'*64, code={'verify_payloads.py': 'b'*64}, evidence={'source.json': 'c'*64})
    asset = dict(bytes=1, sha256='d'*64)
    baseline = dict(assets={'fixture-model': asset})
    runtime = dict(model_assets={'fixture-model': asset}, loaded_libraries={'librknn': asset, 'librkllm': asset}, versions={})
    complete = dict(samples=600, policies=9, expected_outputs=5400, outputs=5400, failed_cells=0,
        sdk_failed_cells=0, actual_teacher_sdk_calls=0, actual_first_native_calls=5400,
        first_policy_calls=5400, teacher_policy_calls=0, unique_raw_payloads=1, processed_audio_files=1,
        quality_run=True, run_repeat=0, operating_point='fixture')
    actor = dict(pid=1, start_ticks=2, exe_path='/fixture', exe_sha256='a', cmdline_sha256='b', uid='u', state='S')
    restored = dict(boot='b', after=[actor], signals=[dict(pid=1, SIGCONT_sent=True)], all_restored=True, cleanup_errors=[])
    paused = dict(boot='b', original=dict(boot='b', processes=[actor]), after=[dict(actor, state='T')])
    schedule_rows = schedule(samples, POLICIES, SCHEDULE_SEED)
    calls = []
    for index, cell in enumerate(schedule_rows):
        p = cell['policy']
        channel = 0 if p == 'rms_sense' else int(p[2])
        asr = dict(text='abc', first=dict(text='abc'), policy='sense_only', teacher=None, invoked=False,
            sdk_calls=[], sdk_errors=[], second_failure=None, status='ok', independent_policy_execution=True,
            actual_first_native_calls=1, actual_teacher_sdk_calls=0, service_s=.5)
        calls.append(dict(cell, meeting=samples[int(cell['id'])]['meeting'], room_cluster='r', speaker_cluster='s',
            quality_run=True, run_repeat=0, independent_policy_execution=True, operating_point='fixture',
            audio_sha256='a'*64, audio_samples=1, input_channels=8, input_PCM_bytes=16,
            text='abc', asr=asr, fatal=False, cell_exception=None, actual_first_native_calls=1,
            completed_first_native_calls=1, actual_teacher_sdk_calls=0, source_idle_check=dict(running=False),
            frontend=dict(method='rmsmax' if p == 'rms_sense' else 'fixed_channel', selected_channel=channel,
                          output_normalized=False, output_clipped=False), frontend_s=.25, service_s=1.,
            frontend_plus_asr_residual_s=.25, research_archive_s=0., start_monotonic=float(index),
            final_computed_monotonic=float(index+1)))
    contents = {}
    def put(path, data, lines=False):
        contents[str(path)] = (''.join(json.dumps(r) + '\n' for r in data) if lines else json_text(data)).encode()
        return digest(contents[str(path)])
    native = run / 'native_v1'
    runtime_pin = put(native / 'RUNTIME_BINDINGS.json', runtime)
    provenance = dict(schema='fixed_channel_supplement_v1', boot='b', method_freeze_sha256='a'*64,
        manifest_sha256='a'*64, protocol_sha256='a'*64, code_sha256=freeze['code'], evidence_sha256=freeze['evidence'],
        runtime_bindings_sha256=runtime_pin, source_reference_used_for_decisions=False, operating_point='fixture')
    for name, value in dict(COMPLETE=complete, PROVENANCE=provenance,
        INITIALIZATION=dict(both_resident=True, excluded_from_service=True, operating_point='fixture', sensevoice_init_s=1., qwen_init_s=1.),
        SCHEDULE=dict(seed=SCHEDULE_SEED, rows=schedule_rows, independent_policy_execution=True)).items():
        put(native / (name+'.json'), value)
    for name, value in dict(CHILD_EXIT=dict(exit_code=0), RESTORED=restored, PAUSED=paused).items():
        put(run / 'guard_v1' / (name+'.json'), value)
    put(native / 'calls.jsonl', calls, True)
    package_names = ('METHOD_FREEZE.json', 'manifest.json', 'PROTOCOL.md', 'MODEL_ASSET_BASELINE.json', 'PREPARE_RECEIPT.json')
    pins = {str(Path(name).relative_to(run)): digest(data) for name, data in contents.items()}
    pins.update({name: 'a'*64 for name in package_names})
    receipt = dict(schema='FIXED_RAW_AUDIT_v1', status='passed', actual_completed_run=True, NN_calls_added=0,
        sources=600, cells=5400, policies=9, failed_cells=0, sdk_failed_cells=0, attempted_failures=[],
        verifier_sha256='b'*64, quality_run=True, run_repeat=0, DSP_decisions_and_waveforms_recomputed=True,
        own_greedy_raw_replayed=True, ObservedEncoder_call_output_indices_verified=True,
        all_four_actor_identities_pause_restore_verified=True, source_reference_used_for_audit=False,
        scoring_performed=False, SDK_exception_cells=[], input_materials_sha256=pins,
        input_calls_sha256=pins['native_v1/calls.jsonl'], frozen_code_sha256=freeze['code'],
        frozen_evidence_sha256=freeze['evidence'], runtime_assets=runtime, operating_point='fixture',
        actual_first_native_calls=5400, actual_teacher_sdk_calls=0, first_policy_calls=5400,
        teacher_policy_calls=0, raw_payloads=1, processed_waveforms=1)
    put(receipt_path, receipt)
    class MemoryEvidence:
        def __init__(self):
            self.hashes = {str(prepared/name): 'a'*64 for name in package_names}
            self.text_reads = 0
        def load(self, path, expected=None):
            data = contents[str(path)]
            require(expected is None or digest(data) == expected, 'synthetic hash mismatch')
            self.hashes[str(path)] = digest(data)
            return parse(data.decode())
        def lines(self, path, expected=None):
            self.text_reads += 1
            data = contents[str(path)]
            require(expected is None or digest(data) == expected, 'synthetic calls hash mismatch')
            return [parse(line) for line in data.decode().splitlines()]
        def missing(self, path):
            require(str(path) not in contents, 'synthetic failure marker')
    with patch.object(Path, 'is_dir', lambda p: str(p) == str(run/'guard_v1')), \
         patch.object(Path, 'exists', lambda p: str(p) in contents):
        ev = MemoryEvidence()
        accepted, _, _ = gate_run(ev, prepared, run, receipt_path, manifest, freeze, baseline, True)
        require(len(accepted) == 5400 and ev.text_reads == 1, 'full synthetic actual-run gate')
        # Corrupt receipt identity or audited metadata while keeping output access under observation.
        for key, value in (('status', 'pending'), ('input_calls_sha256', '0'*64), ('verifier_sha256', '0'*64)):
            put(receipt_path, dict(receipt, **{key: value}))
            ev = MemoryEvidence()
            try:
                gate_run(ev, prepared, run, receipt_path, manifest, freeze, baseline, True)
            except Rejected:
                require(ev.text_reads == 0, 'gate parsed model text before rejecting ' + key)
            else:
                raise AssertionError('corrupt gate accepted: ' + key)
        put(receipt_path, receipt)
        # Even a passed receipt cannot authorize bytes different from what it audited.
        put(native/'COMPLETE.json', dict(complete, outputs=5399))
        ev = MemoryEvidence()
        try:
            gate_run(ev, prepared, run, receipt_path, manifest, freeze, baseline, True)
        except Rejected:
            require(ev.text_reads == 0, 'changed metadata exposed texts')
        else:
            raise AssertionError('changed audited bytes accepted')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepared', type=Path, default=ROOT / 'prepared_01')
    parser.add_argument('--run', type=Path, default=ROOT / 'attempt_01')
    parser.add_argument('--raw-receipt', type=Path, default=ROOT / 'FIXED_RAW_AUDIT_v1.json')
    parser.add_argument('--output', type=Path, default=ROOT / 'analysis_v1')
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args(argv)
    try:
        if args.self_test:
            self_test()
        else:
            result = run_analysis(args.prepared.resolve(), args.run.resolve(), args.raw_receipt.resolve(), args.output.resolve())
            print(json.dumps(dict(status=result['status'], branch=result['branch'], output=str(args.output)), ensure_ascii=False))
        return 0
    except (OSError, ValueError, TypeError, KeyError, IndexError, ImportError) as exc:
        print(f'REJECTED: {type(exc).__name__}: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
