#!/usr/bin/env python3
"""Post-completion quality analysis; local metadata only, never loads ASR code.

Default inputs: sibling prepared_01 and collected attempt_01. A fresh analysis_v1
is written ONLY after all validation/scoring succeeds. --self-test is entirely
synthetic and performs no file reads/writes. numpy is used only for statistics.
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
import random
import sys
import unicodedata

ROOT = Path(__file__).resolve().parent
SEED, DRAWS = 20261015, 10000
POLICIES = ('ch0_sense', 'ch4_sense', 'rms_sense', 'mean_sense', 'gcc_sense',
            'mvdr_sense', 'ch0_qwen', 'ch4_qwen', 'rms_qwen')
PRIMARY = [('rms_sense', 'ch4_sense'), ('rms_sense', 'ch0_sense')]
MODES = ('primary_casefold', 'historical_case_preserved')


class Rejected(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Rejected(message)


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


def digest(data):
    return hashlib.sha256(data).hexdigest()


class Evidence:
    """Hash the exact bytes parsed; reject concurrent changes before publication."""
    def __init__(self):
        self.hashes = {}

    def read(self, path, expected=None):
        path = Path(path).resolve()
        data = path.read_bytes()
        pin = digest(data)
        require(expected is None or pin == expected, 'hash mismatch: ' + str(path))
        require(str(path) not in self.hashes or self.hashes[str(path)] == pin,
                'input changed: ' + str(path))
        self.hashes[str(path)] = pin
        return data

    def load(self, path, expected=None):
        return parse(self.read(path, expected).decode('utf-8'))

    def lines(self, path, optional=False):
        if optional and not path.exists():
            return []
        data = self.read(path).decode('utf-8')
        require(not data or data.endswith('\n'), 'unterminated JSONL: ' + str(path))
        return [parse(line) for line in data.splitlines() if line.strip()]

    def stable(self):
        for name, pin in self.hashes.items():
            require(digest(Path(name).read_bytes()) == pin, 'input changed: ' + name)


def normalize(text, casefold=True):
    require(isinstance(text, str), 'raw text must be a string')
    text = unicodedata.normalize('NFKC', text)
    if casefold:
        text = text.casefold()
    return ''.join(c for c in text if c.isalpha() or c.isdigit())


def edit_counts(reference, hypothesis):
    """Unit-cost Levenshtein, stdlib; ties diagonal, deletion, insertion.

    Rows carry (distance,S,D,I), so no external scorer or project import is used.
    S/D/I describe this deterministic optimal alignment; distance is tie invariant.
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
    require(errors == s + d + i, 'edit accounting disagreement')
    return dict(errors=errors, substitutions=s, deletions=d, insertions=i)


def finite(value, nonnegative=True):
    return (type(value) in (int, float) and math.isfinite(value)
            and (not nonnegative or value >= 0))


def near(left, right):
    return finite(left, False) and finite(right, False) and math.isclose(
        left, right, rel_tol=1e-8, abs_tol=1e-6)


def schedule(samples, policies):
    order = list(policies)
    random.Random(SEED).shuffle(order)
    return [dict(id=source['id'], source_position=j, policy=p, policy_position=k)
            for j, source in enumerate(samples)
            for k, p in enumerate(order[j % len(order):] + order[:j % len(order)])]


def load_package(ev, prepared, census_path):
    """Prepared source/protocol evidence only; no runtime/output reads here."""
    freeze = ev.load(prepared / 'METHOD_FREEZE.json')
    require(freeze['code']['run_native.py'] == '37f984bd643b954f1a5c40acf852507a6f96fd877f4306dc30e99c8da05aa531', 'actual frozen runner contract')
    manifest = ev.load(prepared / 'manifest.json', freeze['manifest_sha256'])
    receipt = ev.load(prepared / 'PREPARE_RECEIPT.json')
    require(receipt['method_freeze_sha256'] == ev.hashes[str(prepared / 'METHOD_FREEZE.json')]
            and receipt['manifest_sha256'] == freeze['manifest_sha256'], 'prepare receipt binding')
    for name, pin in {**freeze['code'], **freeze['evidence']}.items():
        path = (prepared / name).resolve()
        require(path.is_relative_to(prepared), 'prepared binding escapes package')
        ev.read(path, pin)
    ev.read(prepared / 'PROTOCOL.md', freeze['protocol_sha256'])
    baseline = ev.load(prepared / 'MODEL_ASSET_BASELINE.json', freeze['model_asset_baseline_sha256'])
    require(not (prepared / 'PREPARE_FAILED.json').exists(), 'failed preparation')
    policies, samples = manifest['policies'], manifest['samples']
    ids = [r['id'] for r in samples]
    require(policies == list(POLICIES) == freeze['policies'], 'nine frozen policies required')
    require(0 < len(ids) <= 600 and len(set(ids)) == len(ids), 'source count/duplicates')
    require(manifest['sample_order'] == ids, 'source chronology mismatch')
    require(manifest.get('quality_run') is True and manifest.get('run_repeat') == 0
            and freeze.get('quality_run') is True and freeze.get('run_repeat') == 0,
            'only the original primary quality matrix may be scored')
    require(freeze['source_count'] == len(ids) and freeze['expected_cells'] == len(ids) * len(policies),
            'frozen dimensions mismatch')
    require(freeze['primary_comparisons'] == [list(p) for p in PRIMARY], 'primary contrasts changed')
    boot = freeze['bootstrap']
    require(boot['replicates'] == DRAWS and boot['seed'] == SEED
            and boot['primary_confidence'] == .975 and boot['secondary_confidence'] == .95
            and boot['primary_contrasts'] == 2 and manifest['seed'] == SEED,
            'bootstrap or schedule freeze changed')
    source = ev.load(prepared / 'evidence/source_manifest.json', freeze['source_manifest_sha256'])
    selected = ev.load(prepared / 'evidence/source_selection.json', freeze['source_selection_sha256'])
    scoring = ev.load(prepared / 'evidence/SOURCE_AND_SCORING_FREEZE_v1.json', freeze['source_scoring_freeze_sha256'])
    require(freeze['primary_normalization'] == scoring['primary_normalization']
            and freeze['secondary_normalization'] == scoring['secondary_normalization'], 'scoring freeze binding')
    complete = ev.load(prepared / 'evidence/source_complete.json')
    require(complete['status'] == 'complete' and complete['NN_calls'] == 0
            and complete['gzip_crc_verified'] is True and complete['full_archive_sha_verified'] is True
            and complete['manifest_sha256'] == freeze['source_manifest_sha256']
            and complete['clips'] == len(ids), 'source completion not certified')
    require([r['id'] for r in source['samples']] == selected['selected_ids'] == ids,
            'source/reference/order binding mismatch')
    require(source['selection_freeze_sha256'] == freeze['source_selection_sha256']
            and source['source_freeze_sha256'] == freeze['source_scoring_freeze_sha256']
            and source['NN_calls'] == 0, 'source freeze cross-binding')
    census = ev.load(census_path, source['census_manifest_sha256'])
    require(selected['census_manifest_sha256'] == source['census_manifest_sha256'], 'census binding')
    require({r['meeting'] for r in samples} == {r['meeting'] for r in census['meetings']
            if r['eligible_whole_utterances'] > 0}, 'all eligible meetings must be represented')
    source_by_id = {r['id']: r for r in source['samples']}
    for row in samples:
        ref = source_by_id[row['id']]
        for key in ('meeting', 'room_cluster', 'speaker_cluster', 'sha256', 'frames'):
            require(row[key] == ref[key], 'source geometry/identity: ' + row['id'])
        require(freeze['source_audio_sha256'][row['id']] == row['sha256'], 'audio hash declaration')
        pointer = ref['source_pointer']
        require(pointer['id'] == row['id'] and pointer['reference'] == ref['reference'], 'reference pointer')
        require(digest(ref['reference'].encode()) == ref['reference_sha256'] == pointer['reference_utf8_sha256']
                and digest(pointer['raw_reference'].encode()) == pointer['raw_reference_utf8_sha256'],
                'reference string hash')
        require(pointer['end_sample'] - pointer['start_sample'] == row['frames']
                and pointer['eligible_whole_utterance'] is True and pointer['source_only'] is True,
                'source interval eligibility')
        require(row['channels'] == 8 and row['sample_rate'] == 16000 and row['encoding'] == 'PCM16',
                'native source geometry changed')
        require(normalize(ref['reference']), 'zero normalized reference denominator')
    adoption = ev.load(prepared / 'evidence/ADOPTION_DECISION_v1.json', freeze['adoption_decision_sha256'])
    timing = ev.load(prepared / 'evidence/TIMING_SUBSET_v1.json', freeze['timing_subset_sha256'])
    plan = ev.load(prepared / 'evidence/source_plan.json')
    require(timing['source_selection_sha256'] == plan['selection_receipt_sha256'],
            'timing binds parent selection receipt, not extraction selection artifact')
    require(set(timing['selected_ids']) <= set(ids) and timing['quality_run'] is False
            and timing['quality_outputs_not_replaced'] is True
            and timing['additional_independent_quality_n'] == 0 and timing['rounds'] == [1, 2],
            'timing repeat separation')
    return manifest, freeze, source_by_id, census, adoption, timing, baseline


def gate_complete(ev, run, manifest, freeze):
    """This must run BEFORE opening calls, SDK ledgers, or any model text."""
    native, guard = run / 'native_v1', run / 'guard_v1'
    for path in (native / 'FAILED.json', guard / 'FAILED.json', guard / 'RESTORATION_ATTENTION.json'):
        require(not path.exists(), 'terminal failure marker: ' + str(path))
    complete = ev.load(native / 'COMPLETE.json')
    restored = ev.load(guard / 'RESTORED.json')
    child = ev.load(guard / 'CHILD_EXIT.json')
    n, p = len(manifest['samples']), len(manifest['policies'])
    require(all(complete.get(k) == v for k, v in dict(samples=n, policies=p,
            expected_outputs=n * p, outputs=n * p, quality_run=True, run_repeat=0).items()),
            'full primary matrix COMPLETE required')
    require(complete['quality_run'] is True and type(complete['run_repeat']) is int,
            'typed primary quality role required')
    require(restored.get('all_restored') is True and not restored.get('cleanup_errors'),
            'normal restoration required')
    require(len(restored['signals']) == len(restored['after'])
            and all(r.get('SIGCONT_sent') is True for r in restored['signals'])
            and all(r.get('state') not in (None, 'T', 't') for r in restored['after']),
            'restoration signal/process-state coverage')
    require(type(child.get('exit_code')) is int and child['exit_code'] == 0, 'child exit zero required')
    require(complete['operating_point'] == freeze['operating_point'], 'operating point changed')
    return complete


def validate_failure_accounting(ev, native, calls, complete):
    """Exact dual-ledger contract of frozen runner SHA37f984, not an earlier draft."""
    failures = [dict(id=r['id'], policy=r['policy'], failure=r['asr']['second_failure'],
        cell_exception=r['cell_exception'], sdk_calls=r['asr']['sdk_calls'],
        sdk_errors=r['asr']['sdk_errors']) for r in calls
        if r['asr']['second_failure'] or r['cell_exception']]
    sdk = [dict(id=r['id'], policy=r['policy'], failure=r['asr']['second_failure'],
        cell_exception=r['cell_exception'], sdk_calls=r['asr']['sdk_calls'],
        sdk_errors=r['asr']['sdk_errors']) for r in calls
        if r['policy'].endswith('_qwen') and r['asr']['second_failure']]
    require(ev.lines(native / 'CELL_FAILURES.jsonl', True) == failures,
            'all-failure CELL_FAILURES ledger mismatch')
    require(ev.lines(native / 'SDK_FAILURES.jsonl', True) == sdk,
            'Qwen SDK_FAILURES ledger mismatch')
    counts = dict(failed_cells=len(failures), sdk_failed_cells=len(sdk),
        actual_first_native_calls=sum(r['actual_first_native_calls'] for r in calls),
        actual_teacher_sdk_calls=sum(r['actual_teacher_sdk_calls'] for r in calls),
        first_policy_calls=sum(r['actual_first_native_calls'] > 0 for r in calls),
        teacher_policy_calls=sum(bool(r['asr']['invoked']) for r in calls))
    require(all(type(complete.get(k)) is int and complete[k] == value
                for k, value in counts.items()), 'COMPLETE dual-ledger totals mismatch')
    return failures, counts


def validate_records(ev, run, manifest, freeze, complete, baseline):
    native = run / 'native_v1'
    provenance = ev.load(native / 'PROVENANCE.json')
    restored = ev.load(run / 'guard_v1/RESTORED.json')
    require(provenance['boot'] == restored['boot'], 'runtime/restoration boot mismatch')
    for key in ('manifest_sha256', 'protocol_sha256', 'code_sha256', 'evidence_sha256'):
        expected = freeze[{'code_sha256': 'code', 'evidence_sha256': 'evidence'}.get(key, key)]
        require(provenance[key] == expected, 'runtime provenance: ' + key)
    require(provenance['method_freeze_sha256'] == ev.hashes[str((ROOT / 'prepared_01/METHOD_FREEZE.json').resolve())],
            'runtime method freeze')
    require(provenance['source_reference_used_for_decisions'] is False, 'reference access declaration')
    runtime = ev.load(native / 'RUNTIME_BINDINGS.json', provenance['runtime_bindings_sha256'])
    require(runtime['model_assets'] and runtime['loaded_libraries'], 'missing runtime assets/libraries')
    for name, pin in runtime['model_assets'].items():
        require(name in baseline['assets'] and pin == {k: baseline['assets'][name][k] for k in ('bytes', 'sha256')},
                'actual selected asset outside baseline')
    require(all(any(kind in name.lower() for name in runtime['loaded_libraries']) for kind in ('rknn', 'rkllm')),
            'both native libraries must be recorded')
    init = ev.load(native / 'INITIALIZATION.json')
    require(init['both_resident'] is True and init['excluded_from_service'] is True
            and init['operating_point'] == freeze['operating_point'], 'resident initialization accounting')
    for key in ('sensevoice_init_s', 'qwen_init_s'):
        require(finite(init[key]), 'initialization duration')
    sched = ev.load(native / 'SCHEDULE.json')
    expected = schedule(manifest['samples'], manifest['policies'])
    require(sched['rows'] == expected and sched['seed'] == SEED
            and sched['independent_policy_execution'] is True, 'full frozen schedule mismatch')
    calls = ev.lines(native / 'calls.jsonl')
    require(len(calls) == len(expected), 'all owned attempts required, no duplicates or missing cells')
    io_rows = ev.lines(native / 'SOURCE_IO.jsonl')
    idle_rows = ev.lines(native / 'IDLE_CHECKS.jsonl')
    ids = [r['id'] for r in manifest['samples']]
    require([r['id'] for r in io_rows] == ids == [r['id'] for r in idle_rows], 'source IO/idle once per source')
    source_io = {r['id']: r for r in io_rows}
    idle_by_id = {r['id']: {k: v for k, v in r.items() if k != 'id'} for r in idle_rows}
    sources = {r['id']: r for r in manifest['samples']}
    for row in io_rows:
        require(row['decoded_once'] is True and row['excluded_from_service'] is True
                and finite(row['source_io_s']) and finite(row['source_integrity_s']), 'shared source IO')
    attempts = []
    previous_end = None
    for index, (row, cell) in enumerate(zip(calls, expected)):
        label = f"{cell['id']}/{cell['policy']}"
        require(all(row.get(k) == v for k, v in cell.items()), 'owned schedule/identity: ' + label)
        source, asr = sources[row['id']], row['asr']
        require(row['source_idle_check'] == idle_by_id[row['id']]
                and idle_by_id[row['id']].get('running') is False, 'source idle declaration mismatch')
        require(row['quality_run'] is True and row['run_repeat'] == 0
                and row['independent_policy_execution'] is True, 'quality/independence: ' + label)
        require(row['operating_point'] == freeze['operating_point'], 'cell operating point')
        for k in ('meeting', 'room_cluster', 'speaker_cluster'):
            require(row[k] == source[k], 'source cluster: ' + label)
        require(row['audio_sha256'] == source['sha256'] and row['audio_samples'] == source['frames']
                and row['input_channels'] == 8 and row['input_PCM_bytes'] == source['frames'] * 16,
                'cell audio binding: ' + label)
        require(isinstance(row['text'], str) and row['text'] == asr['text'], 'raw final text mismatch: ' + label)
        require(row['fatal'] is False, 'fatal cell cannot belong to normal complete matrix')
        for k in ('frontend_s', 'service_s', 'research_archive_s'):
            require(finite(row[k]), 'invalid duration: ' + label)
        require(finite(asr['service_s']) and finite(row['frontend_plus_asr_residual_s'], False), 'ASR/residual duration')
        require(near(row['service_s'], row['frontend_s'] + asr['service_s'] + row['frontend_plus_asr_residual_s'])
                and near(row['service_s'], row['final_computed_monotonic'] - row['start_monotonic']),
                'service decomposition: ' + label)
        require(previous_end is None or row['start_monotonic'] >= previous_end, 'overlapping actual cells')
        previous_end = row['final_computed_monotonic']
        for k in ('source_io_s', 'source_integrity_s'):
            require(near(row[k], source_io[row['id']][k]), 'repeated common IO metadata mismatch')
        for side in ('environment_before', 'environment_after'):
            require(all(k in row[side] for k in ('temperatures', 'cpu_freq', 'devfreq', 'memory', 'load')),
                    'missing thermal/frequency/memory/swap environment')
        for k in ('actual_first_native_calls', 'completed_first_native_calls', 'actual_teacher_sdk_calls'):
            require(type(row[k]) is int and row[k] >= 0, 'invalid actual call count')
        require(row['completed_first_native_calls'] <= row['actual_first_native_calls'], 'native completed > attempts')
        require(row['actual_teacher_sdk_calls'] == len(asr['sdk_calls']) + len(asr['sdk_errors']), 'SDK observed count')
        if asr['status'] == 'ok':
            require(not asr['second_failure'] and not row['cell_exception'] and not asr['sdk_errors'],
                    'successful status masks recorded failure')
            require(all(c.get('ret_code') == 0 and not c.get('aborted') and c.get('finish_seen') is True
                        for c in asr['sdk_calls']), 'successful status masks SDK failure')
        require(all(c.get('cache_clear_mode') == 0 and c.get('cache_clear_ret') == 0
                    and c.get('keep_history') == 0 and c.get('keep_prefix_requested') is False
                    for c in asr['sdk_calls']), 'cache contract violation cannot be normal completion')
        qwen = row['policy'].endswith('_qwen')
        require(asr['policy'] == ('qwen_only' if qwen else 'sense_only'), 'recognizer policy substitution')
        if qwen:
            require(row['actual_first_native_calls'] == 0 and asr['first'] is None and not row['raw_tensor'],
                    'Qwen must not borrow SenseVoice calls/raw/text')
            if asr['teacher'] is not None:
                require(row['text'] == asr['teacher'].get('text', ''), 'retain actually returned Qwen final text')
            else:
                require(row['text'] == '', 'no teacher final text returned: expected owned empty outcome')
        else:
            require(row['actual_teacher_sdk_calls'] == 0 and asr['teacher'] is None, 'SenseVoice must not borrow Qwen')
            if asr['status'] == 'ok':
                require(asr['first'] is not None and row['text'] == asr['first']['text']
                        and row['actual_first_native_calls'] > 0, 'SenseVoice owned final result')
        if asr['status'] == 'ok' and qwen:
            require(row['actual_teacher_sdk_calls'] > 0 and asr['teacher'] is not None, 'successful Qwen actual call')
        raw_ids = [(x['native_call_index'], x['native_output_index']) for x in row['raw_tensor']]
        require(len(set(raw_ids)) == len(raw_ids) and all(0 <= x[0] < row['completed_first_native_calls'] for x in raw_ids),
                'raw occurrence must name this cell native call')
        # IDs are the observed per-cell occurrence indices, NOT invented global SDK IDs.
        attempts.append(dict(id=row['id'], policy=row['policy'], calls_jsonl_line=index + 1,
            actual_first_native_calls=row['actual_first_native_calls'],
            completed_first_native_calls=row['completed_first_native_calls'],
            actual_teacher_sdk_calls=row['actual_teacher_sdk_calls'], raw_occurrences=row['raw_tensor'],
            sdk_observations=asr['sdk_calls'], sdk_errors=asr['sdk_errors']))
        if not (asr['second_failure'] or row['cell_exception']):
            require(asr['status'] == 'ok', 'unlogged non-ok outcome')
    failures, counts = validate_failure_accounting(ev, native, calls, complete)
    # Archive metadata only. Never read tensor or processed-audio payload paths.
    raw_index = ev.load(native / 'RAW_INDEX.json')
    processed_index = ev.load(native / 'PROCESSED_AUDIO_INDEX.json')
    seen_raw, seen_processed = set(), set()
    for row in calls:
        for item in row['raw_tensor']:
            pin = item['sha256']
            require(pin in raw_index and all(item[k] == raw_index[pin][k] for k in ('path', 'bytes', 'sha256')),
                    'raw index occurrence mismatch')
            seen_raw.add(pin)
        item = row['processed_audio']
        if item is not None:
            require(item == processed_index.get(item['sha256']), 'processed audio index mismatch')
            seen_processed.add(item['sha256'])
    require(seen_raw == set(raw_index) and seen_processed == set(processed_index)
            and len(raw_index) == complete['unique_raw_payloads']
            and len(processed_index) == complete['processed_audio_files'], 'archive index coverage')
    return calls, io_rows, init, runtime, failures, attempts, counts


def score(calls, references):
    rows = []
    for line, call in enumerate(calls, 1):
        source = references[call['id']]
        for mode in MODES:
            ref, hyp = (normalize(t, mode == MODES[0]) for t in (source['reference'], call['text']))
            counts = edit_counts(ref, hyp)
            rows.append(dict(id=call['id'], meeting=call['meeting'], room=call['room_cluster'],
                speaker=call['speaker_cluster'], policy=call['policy'], mode=mode,
                reference=source['reference'], hypothesis=call['text'], reference_sha256=source['reference_sha256'],
                source_pointer=source['source_pointer'], normalized_reference=ref, normalized_hypothesis=hyp,
                reference_characters=len(ref), **counts, cer=counts['errors'] / len(ref),
                status=call['asr']['status'], failed=bool(call['asr']['second_failure'] or call['cell_exception']),
                calls_jsonl_line=line))
    return rows


def aggregate(rows):
    refs = sum(r['reference_characters'] for r in rows)
    require(refs > 0, 'empty analysis group')
    result = {k: sum(r[k] for r in rows) for k in ('errors', 'substitutions', 'deletions', 'insertions')}
    return dict(n=len(rows), reference_characters=refs, **result, cer=result['errors'] / refs,
                failed_cells=sum(r['failed'] for r in rows))


def cluster_effect(meeting_delta, meeting_refs, confidence, draws=None):
    """Resample meetings uniformly, keeping paired totals/denominators together.

    Pooled estimator is ratio of sums; equal-meeting is mean of meeting ratios.
    A single draw matrix is reused across contrasts and normalizations.
    """
    import numpy as np
    delta, refs = np.asarray(meeting_delta, dtype=float), np.asarray(meeting_refs, dtype=float)
    require(len(delta) == len(refs) and len(refs) > 0 and (refs > 0).all(), 'cluster dimensions')
    if draws is None:
        draws = np.random.default_rng(SEED).integers(0, len(refs), (DRAWS, len(refs)))
    pooled = delta[draws].sum(axis=1) / refs[draws].sum(axis=1)
    equal = (delta / refs)[draws].mean(axis=1)
    tail = (1 - confidence) / 2
    return dict(pooled_cer_delta=float(delta.sum() / refs.sum()),
        equal_meeting_cer_delta=float((delta / refs).mean()), confidence=confidence,
        pooled_ci_low=float(np.quantile(pooled, tail)), pooled_ci_high=float(np.quantile(pooled, 1 - tail)),
        equal_meeting_ci_low=float(np.quantile(equal, tail)), equal_meeting_ci_high=float(np.quantile(equal, 1 - tail)))


def seconds(values):
    import numpy as np
    values = np.asarray(list(values), dtype=float)
    return dict(n=len(values), total_s=float(values.sum()), mean_s=float(values.mean()),
                median_s=float(np.median(values)), p95_s=float(np.quantile(values, .95)),
                min_s=float(values.min()), max_s=float(values.max()))


def analyze(rows, calls, manifest, freeze):
    import numpy as np
    meetings = sorted({r['meeting'] for r in rows})
    rooms = sorted({r['room'] for r in rows})
    policies = manifest['policies']
    draws = np.random.default_rng(SEED).integers(0, len(meetings), (DRAWS, len(meetings)))
    per_policy, per_meeting, per_room, contrasts, pairs, meeting_pairs, room_sensitivity, costs = ([] for _ in range(8))
    comparison_list = list(PRIMARY)
    comparison_list += [tuple(x) for x in freeze['resource_comparisons']]
    comparison_list += [(p, 'rms_sense') for p in ('mean_sense', 'gcc_sense', 'mvdr_sense')]
    comparison_list += [('rms_qwen', 'ch0_qwen')]
    comparison_list = list(dict.fromkeys(comparison_list))
    for mode in MODES:
        selected = [r for r in rows if r['mode'] == mode]
        indexed = {(r['id'], r['policy']): r for r in selected}
        for policy in policies:
            group = [r for r in selected if r['policy'] == policy]
            meeting_metrics = [dict(mode=mode, policy=policy, meeting=m,
                room=next(r['room'] for r in group if r['meeting'] == m),
                **aggregate([r for r in group if r['meeting'] == m])) for m in meetings]
            per_meeting.extend(meeting_metrics)
            per_room.extend(dict(mode=mode, policy=policy, room=room,
                **aggregate([r for r in group if r['room'] == room])) for room in rooms)
            ci = cluster_effect([r['errors'] for r in meeting_metrics],
                [r['reference_characters'] for r in meeting_metrics], .95, draws)
            per_policy.append(dict(mode=mode, policy=policy, **aggregate(group),
                equal_meeting_cer=sum(r['cer'] for r in meeting_metrics) / len(meetings),
                descriptive_confidence=.95, cer_ci_low=ci['pooled_ci_low'], cer_ci_high=ci['pooled_ci_high'],
                equal_meeting_ci_low=ci['equal_meeting_ci_low'], equal_meeting_ci_high=ci['equal_meeting_ci_high']))
        for candidate, baseline in comparison_list:
            source_pairs = []
            for source in manifest['samples']:
                left, right = indexed[source['id'], candidate], indexed[source['id'], baseline]
                delta = left['errors'] - right['errors']
                source_pairs.append(dict(mode=mode, candidate=candidate, baseline=baseline, id=source['id'],
                    meeting=source['meeting'], room=source['room_cluster'], reference_characters=left['reference_characters'],
                    candidate_errors=left['errors'], baseline_errors=right['errors'], error_delta=delta,
                    cer_delta=delta / left['reference_characters'], baseline_zero_damage=right['errors'] == 0 and delta > 0))
            pairs.extend(source_pairs)
            totals, denominators = [], []
            for meeting in meetings:
                subset = [r for r in source_pairs if r['meeting'] == meeting]
                delta, refs = sum(r['error_delta'] for r in subset), sum(r['reference_characters'] for r in subset)
                totals.append(delta)
                denominators.append(refs)
                meeting_pairs.append(dict(mode=mode, candidate=candidate, baseline=baseline, meeting=meeting,
                    room=subset[0]['room'], n=len(subset), error_delta=delta, reference_characters=refs,
                    cer_delta=delta / refs, direction='improved' if delta < 0 else 'damaged' if delta > 0 else 'unchanged'))
            primary = mode == MODES[0] and (candidate, baseline) in PRIMARY
            effect = cluster_effect(totals, denominators, .975 if primary else .95, draws)
            contrasts.append(dict(mode=mode, candidate=candidate, baseline=baseline,
                role='primary_Bonferroni_family_2' if primary else 'descriptive', **effect,
                n_sources=len(source_pairs), n_meetings=len(meetings), error_delta=sum(totals),
                improved_sources=sum(r['error_delta'] < 0 for r in source_pairs),
                damaged_sources=sum(r['error_delta'] > 0 for r in source_pairs),
                unchanged_sources=sum(r['error_delta'] == 0 for r in source_pairs),
                baseline_zero_sources=sum(r['baseline_errors'] == 0 for r in source_pairs),
                baseline_zero_damaged=sum(r['baseline_zero_damage'] for r in source_pairs),
                improved_meetings=sum(x < 0 for x in totals), damaged_meetings=sum(x > 0 for x in totals),
                unchanged_meetings=sum(x == 0 for x in totals)))
            for omitted in rooms:
                keep = [r for r in source_pairs if r['room'] != omitted]
                room_meetings = sorted({r['meeting'] for r in keep})
                delta = [sum(r['error_delta'] for r in keep if r['meeting'] == m) for m in room_meetings]
                refs = [sum(r['reference_characters'] for r in keep if r['meeting'] == m) for m in room_meetings]
                room_sensitivity.append(dict(mode=mode, candidate=candidate, baseline=baseline,
                    omitted_room=omitted, n_sources=len(keep), n_meetings=len(room_meetings),
                    role='descriptive_leave_one_room_out', **cluster_effect(delta, refs, .95)))
    for policy in policies:
        group = [r for r in calls if r['policy'] == policy]
        costs.append(dict(policy=policy,
            **{name: seconds(fn(r) for r in group) for name, fn in {
                'frontend': lambda r: r['frontend_s'], 'asr': lambda r: r['asr']['service_s'],
                'residual': lambda r: r['frontend_plus_asr_residual_s'], 'service': lambda r: r['service_s'],
                'archive_excluded': lambda r: r['research_archive_s']}.items()},
            actual_first_native_calls=sum(r['actual_first_native_calls'] for r in group),
            completed_first_native_calls=sum(r['completed_first_native_calls'] for r in group),
            actual_teacher_sdk_calls=sum(r['actual_teacher_sdk_calls'] for r in group),
            native_attempts_without_completion=sum(r['actual_first_native_calls'] - r['completed_first_native_calls'] for r in group),
            sdk_failed_cells=sum(bool(r['asr']['second_failure']) for r in group if policy.endswith('_qwen')),
            sdk_exception_observations=sum(len(r['asr']['sdk_errors']) for r in group),
            failed_cells=sum(bool(r['asr']['second_failure'] or r['cell_exception']) for r in group)))
    for row in per_policy:
        cost = next(r for r in costs if r['policy'] == row['policy'])
        row['mean_service_s'] = cost['service']['mean_s']
        for key in ('actual_first_native_calls', 'completed_first_native_calls', 'actual_teacher_sdk_calls',
                    'native_attempts_without_completion', 'sdk_failed_cells', 'sdk_exception_observations'):
            row[key] = cost[key]
        row['descriptive_frontier_dominated_by'] = [other['policy'] for other in per_policy
            if other['mode'] == row['mode'] and other['policy'] != row['policy']
            and other['cer'] <= row['cer'] and next(c for c in costs if c['policy'] == other['policy'])['service']['mean_s'] <= row['mean_service_s']
            and (other['cer'] < row['cer'] or next(c for c in costs if c['policy'] == other['policy'])['service']['mean_s'] < row['mean_service_s'])]
    # Same-source actual service effects and speed ratios; exploratory one-pass timing.
    call_index = {(r['id'], r['policy']): r for r in calls}
    cost_pairs = []
    for candidate, baseline in comparison_list:
        left = [call_index[r['id'], candidate] for r in manifest['samples']]
        right = [call_index[r['id'], baseline] for r in manifest['samples']]
        for l, r in zip(left, right):
            cost_pairs.append(dict(id=l['id'], meeting=l['meeting'], candidate=candidate, baseline=baseline,
                frontend_delta_s=l['frontend_s'] - r['frontend_s'], asr_delta_s=l['asr']['service_s'] - r['asr']['service_s'],
                residual_delta_s=l['frontend_plus_asr_residual_s'] - r['frontend_plus_asr_residual_s'],
                service_delta_s=l['service_s'] - r['service_s']))
        for contrast in contrasts:
            if (contrast['candidate'], contrast['baseline']) == (candidate, baseline):
                contrast['service_mean_delta_s'] = sum(l['service_s'] - r['service_s'] for l, r in zip(left, right)) / len(left)
                denominator = sum(l['service_s'] for l in left)
                contrast['baseline_over_candidate_total_service_ratio'] = sum(r['service_s'] for r in right) / denominator if denominator else None
    return dict(per_policy=per_policy, per_meeting=per_meeting, per_room=per_room, contrasts=contrasts,
        paired_sources=pairs, paired_meetings=meeting_pairs, leave_one_room_out=room_sensitivity,
        costs=costs, paired_costs=cost_pairs)


def environment_summary(calls):
    """Numeric observed ranges, plus full snapshots in owned_attempts.jsonl."""
    values = defaultdict(list)
    for row in calls:
        for side in ('environment_before', 'environment_after'):
            env = row[side]
            for group in ('temperatures', 'cpu_freq', 'devfreq'):
                for sensor, value in env[group].items():
                    try:
                        value = float(value)
                        if math.isfinite(value):
                            values[f'{group}/{sensor}'].append(value)
                    except (TypeError, ValueError):
                        pass
            for line in env['memory']:
                parts = line.split()
                if len(parts) >= 2:
                    values['process_memory_kB/' + parts[0].rstrip(':')].append(float(parts[1]))
    return {name: dict(n=len(xs), minimum=min(xs), maximum=max(xs)) for name, xs in values.items()}


def json_text(value):
    return json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + '\n'


def csv_text(rows):
    stream = io.StringIO(newline='')
    writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows({k: json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else v
                     for k, v in row.items()} for row in rows)
    return stream.getvalue()


def report_text(summary, result):
    cohort = summary['cohort']
    lines = ['# Independent spatial confirmation: completed primary quality matrix', '',
        f"Quality n={cohort['sources']} sources, {cohort['meetings']} meetings, {cohort['rooms']} rooms; "
        f"{cohort['meeting_local_speakers']} meeting-local speaker clusters. Calls and timing repeats are not quality n.",
        f"Census has {cohort['census_source_meetings']} source Test meetings; zero-eligible meetings excluded: " + ', '.join(cohort['zero_eligible_meetings']) + '.',
        'Primary CER: NFKC, casefold, Unicode alpha/digit filtering. Historical case-preserved sensitivity is separate. '
        'No numeric-word conversion, synonym mapping or reference edits. Actual returned final text on failures is retained.', '',
        '| Policy | Errors | S / D / I | Pooled CER | Equal-meeting CER | Mean service s | Failures |',
        '|---|---:|---:|---:|---:|---:|---:|']
    for row in result['per_policy']:
        if row['mode'] == MODES[0]:
            lines.append(f"| {row['policy']} | {row['errors']} | {row['substitutions']} / {row['deletions']} / {row['insertions']} | "
                f"{row['cer']:.6f} | {row['equal_meeting_cer']:.6f} | {row['mean_service_s']:.6f} | {row['failed_cells']} |")
    lines += ['', 'Negative candidate-minus-baseline differences favor the candidate. Intervals are paired meeting-cluster '
        'percentile bootstrap, 10,000 draws, seed 20261015. The two primary intervals are marginal 97.5% '
        '(Bonferroni familywise 95%); every other interval is descriptive 95%.', '']
    for row in result['contrasts']:
        if row['role'].startswith('primary'):
            lines.append(f"- {row['candidate']} minus {row['baseline']}: pooled CER effect "
                f"{100 * row['pooled_cer_delta']:.3f} pp [{100 * row['pooled_ci_low']:.3f}, {100 * row['pooled_ci_high']:.3f}]; "
                f"equal-meeting {100 * row['equal_meeting_cer_delta']:.3f} pp "
                f"[{100 * row['equal_meeting_ci_low']:.3f}, {100 * row['equal_meeting_ci_high']:.3f}]. "
                f"Sources improved/damaged/unchanged: {row['improved_sources']}/{row['damaged_sources']}/{row['unchanged_sources']}; "
                f"baseline-zero damaged {row['baseline_zero_damaged']}/{row['baseline_zero_sources']}.")
    lines += ['', 'All nine cost/quality points and descriptive frontier flags appear in per_policy; matched-input '
        'RMS SenseVoice/Qwen and fixed ch0/ch4 comparisons appear in contrasts. Paired sources, meeting directions, '
        'room composition and leave-one-room-out effects are retained. Unequal R8009 representation and the small '
        'number of rooms limit generalization; speaker/room independence is not established.',
        '', 'Service = CPU frontend + ASR + measured residual. Common eight-channel source I/O/integrity occurs once '
        'per source and is excluded; initialization and research archive time are separate. Both models were resident. '
        'Thermal/frequency/process RSS/HWM/swap ranges are in summary; original snapshots and SDK events remain in '
        'owned_attempts.jsonl and hash-bound inputs. This is offline buffer-ready service, not capture latency, energy '
        'or a mono-input I/O saving. The first actual cell remains included.',
        '', 'Primary quality is independent of future timing rounds 1 and 2. They add no quality n, are not read here, '
        'and cannot replace primary text. One-pass costs are descriptive; repeated-timing integration is a separate later artifact.',
        '', '**Raw audit boundary:** payload indexes/occurrences are metadata only. No raw tensor or processed waveform '
        'bytes were opened or replayed by this analyzer. A separate parent raw-audit receipt is required; metadata '
        'validation is not raw-byte PASS. Source archive integrity is a hash-bound preparation certificate, not rechecked here.',
        '', 'Practical reference thresholds remain approximately 1 pp CER benefit versus reasonable fixed input, or '
        '2x service separation within 1 pp quality. Continuous effects and uncertainty are reported without automatic '
        'success, novelty, independent-confirmation, publication-sufficiency or SCI-readiness decisions. No p-values.']
    return '\n'.join(lines) + '\n'


def run_analysis(prepared, run, output, census):
    require(prepared == ROOT / 'prepared_01' and run == ROOT / 'attempt_01', 'scope is this prepared_01 / attempt_01')
    require(output.parent == ROOT and output.name.startswith('analysis_v') and not output.exists(),
            'output must be a fresh sibling analysis_v* directory')
    ev = Evidence()
    manifest, freeze, refs, census_data, adoption, timing, baseline = load_package(ev, prepared, census)
    complete = gate_complete(ev, run, manifest, freeze)
    calls, io_rows, init, runtime, failures, attempts, counts = validate_records(ev, run, manifest, freeze, complete, baseline)
    rows = score(calls, refs)
    result = analyze(rows, calls, manifest, freeze)
    sources = manifest['samples']
    composition = [dict(room=room, sources=sum(r['room_cluster'] == room for r in sources),
        meetings=len({r['meeting'] for r in sources if r['room_cluster'] == room}),
        reference_characters=sum(len(normalize(refs[r['id']]['reference'])) for r in sources if r['room_cluster'] == room))
        for room in sorted({r['room_cluster'] for r in sources})]
    total_characters = sum(r['reference_characters'] for r in composition)
    total_meetings = len({r['meeting'] for r in sources})
    for room in composition:
        room.update(source_share=room['sources'] / len(sources), meeting_share=room['meetings'] / total_meetings,
                    reference_character_share=room['reference_characters'] / total_characters)
    cohort = dict(sources=len(sources), meetings=len({r['meeting'] for r in sources}),
        rooms=len(composition), meeting_local_speakers=len({r['speaker_cluster'] for r in sources}),
        quality_cells=len(calls), census_source_meetings=len(census_data['meetings']),
        zero_eligible_meetings=[r['meeting'] for r in census_data['meetings'] if r['eligible_whole_utterances'] == 0],
        room_composition=composition)
    summary = dict(status='metadata_and_scoring_validated_NOT_raw_byte_audit', cohort=cohort,
        normalization={MODES[0]: freeze['primary_normalization'], MODES[1]: freeze['secondary_normalization']},
        bootstrap=freeze['bootstrap'], failure_and_actual_counts=counts, policies=result['per_policy'],
        contrasts=result['contrasts'], costs=result['costs'], source_audio_seconds=sum(r['frames'] for r in sources) / 16000,
        source_io_once=dict(n=len(io_rows), source_io=seconds(r['source_io_s'] for r in io_rows),
            integrity=seconds(r['source_integrity_s'] for r in io_rows), excluded_from_service=True,
            input_PCM_bytes=sum(r['frames'] * 16 for r in sources)),
        initialization=init, operating_point=freeze['operating_point'], runtime_bindings=runtime,
        environment_ranges=environment_summary(calls),
        raw_audit=dict(payload_bytes_opened=False, semantic_replay=False, status='separate_parent_receipt_required'),
        timing_repeats=dict(frozen_subset=timing, read_or_integrated=False, adds_quality_n=0),
        adoption_freeze=adoption, automatic_success_decision=False)
    artifacts = {'summary.json': json_text(summary), 'REPORT.md': report_text(summary, result)}
    for name in ('per_policy', 'per_meeting', 'per_room', 'contrasts', 'paired_sources', 'paired_meetings',
                 'leave_one_room_out', 'paired_costs', 'costs'):
        artifacts[name + '.json'] = json_text(result[name])
        artifacts[name + '.csv'] = csv_text(result[name])
    artifacts['per_example.json'] = json_text(rows)
    artifacts['per_example.csv'] = csv_text(rows)
    for name, records in (('owned_attempts', calls), ('actual_call_observations', attempts), ('failures', failures), ('source_io_once', io_rows)):
        artifacts[name + '.jsonl'] = ''.join(json.dumps(r, ensure_ascii=False, allow_nan=False) + '\n' for r in records)
    ev.stable()
    validation = dict(status=summary['status'], all_gates_passed=True, input_sha256=ev.hashes,
        analyzer_sha256=digest(Path(__file__).read_bytes()), python=sys.version,
        unicode_database_version=unicodedata.unidata_version,
        numpy_version=__import__('numpy').__version__, bootstrap_seed=SEED, bootstrap_draws=DRAWS,
        raw_byte_audit_pass=False, raw_semantic_replay=False, timing_rounds_read=False,
        expected_cells=len(sources) * len(manifest['policies']), observed_owned_cells=len(calls),
        output_sha256={name: digest(text.encode('utf-8')) for name, text in artifacts.items()})
    artifacts['VALIDATION.json'] = json_text(validation)  # Does not recursively hash itself.
    output.mkdir(exist_ok=False)
    for name, text in artifacts.items():
        with (output / name).open('x', encoding='utf-8', newline='') as stream:
            stream.write(text)
    return validation


def self_test():
    """Small in-memory fixtures only; no prepared/formal data access."""
    import numpy as np
    require(normalize('Ａß Z-12!') == 'assz12' and normalize('Ａß Z-12!', False) == 'AßZ12', 'normalization fixture')
    require(edit_counts('abc', 'axc') == dict(errors=1, substitutions=1, deletions=0, insertions=0), 'substitution fixture')
    require(edit_counts('abc', 'ac')['deletions'] == 1 and edit_counts('ac', 'abc')['insertions'] == 1, 'D/I fixture')
    require(edit_counts('abc', '')['errors'] == 3 and edit_counts('', 'abc')['insertions'] == 3, 'empty fixture')
    # Exhaustively enumerate two-cluster resamples. Source weights differ 10:1.
    draws = np.array([[0, 0], [0, 1], [1, 0], [1, 1]])
    effect = cluster_effect([10, -2], [100, 10], .95, draws)
    require(near(effect['pooled_cer_delta'], 8 / 110) and near(effect['equal_meeting_cer_delta'], -.05), 'group weights fixture')
    require(near(effect['pooled_ci_low'], -.17954545454545454) and near(effect['pooled_ci_high'], .09795454545454546), 'paired percentile fixture')
    zeros = cluster_effect([0, 0], [100, 10], .975, draws)
    require(zeros['pooled_ci_low'] == zeros['pooled_ci_high'] == 0, 'paired identical policies')
    require(cluster_effect([1, -1], [2, 2], .95) == cluster_effect([1, -1], [2, 2], .95), 'seed reproducibility')
    manifest = dict(samples=[dict(id='synthetic')], policies=list(POLICIES))
    complete = dict(samples=1, policies=9, expected_outputs=9, outputs=9,
                    quality_run=True, run_repeat=0, operating_point='synthetic')
    class MemoryEvidence:
        def __init__(self, bad=None):
            self.bad = bad
        def load(self, path):
            if path.name == 'COMPLETE.json':
                return dict(complete, **({'outputs': 8} if self.bad == 'partial' else {}))
            if path.name == 'RESTORED.json':
                return dict(all_restored=self.bad != 'restoration', cleanup_errors=[], signals=[], after=[])
            if path.name == 'CHILD_EXIT.json':
                return dict(exit_code=1 if self.bad == 'exit' else 0)
            raise AssertionError('gate must never request outputs')
    # Path.exists is never consulted on a real run path in fixtures.
    class FakePath:
        def __init__(self, name='synthetic'):
            self.name = name
        def __truediv__(self, name):
            return FakePath(name)
        def exists(self):
            return False
    for bad in ('partial', 'restoration', 'exit'):
        try:
            gate_complete(MemoryEvidence(bad), FakePath(), manifest, dict(operating_point='synthetic'))
        except Rejected:
            continue
        raise AssertionError('completeness rejection fixture: ' + bad)
    gate_complete(MemoryEvidence(), FakePath(), manifest, dict(operating_point='synthetic'))
    print('PASS: synthetic CER/S-D-I, normalization, paired bootstrap/group weights/seed, complete/restore/exit gates; no formal outputs read')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepared', type=Path, default=ROOT / 'prepared_01')
    parser.add_argument('--run', type=Path, default=ROOT / 'attempt_01')
    parser.add_argument('--output', type=Path, default=ROOT / 'analysis_v1')
    parser.add_argument('--census', type=Path, default=ROOT / 'census_v1/CENSUS_MANIFEST.json')
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args(argv)
    try:
        if args.self_test:
            self_test()
            return 0
        validation = run_analysis(args.prepared.resolve(), args.run.resolve(), args.output.resolve(), args.census.resolve())
        print(json.dumps(dict(status=validation['status'], output=str(args.output)), ensure_ascii=False))
        return 0
    except (OSError, ValueError, TypeError, KeyError, IndexError) as exc:
        print(f'REJECTED: {type(exc).__name__}: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
