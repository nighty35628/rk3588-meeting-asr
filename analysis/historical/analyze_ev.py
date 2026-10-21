#!/usr/bin/env python3
"""Future, post-audit EV/RMS secondary analysis. --self-test is synthetic only.

Never imports native/NN helpers, connects to the board, or opens payload bytes.
All three sidecar gates and the original primary audit precede scoring. No
primary result is overwritten; no repeat enlarges the 600-source quality n.
"""
import argparse
import hashlib
from pathlib import Path
import re
import sys
import types
import unicodedata

ROOT = Path(__file__).resolve().parent
SEED, DRAWS = 20261015, 10000
POLICIES = ('ev_sense', 'rms_sense')
ANALYZER_SHA = 'c900af90336398ac888ed6ae3f6a3d38eb331976e8e24d69e9e09d180647a58d'
TIMING_SHA = '633529e83160f2977233a7fd438510c5867a65868a0b1e0c4da1de4fc2c5d0c3'
PREPARER_SHA = '79e92dd5504b16e91fd2b50e3438630d5a4e0d55b696aa5a03cca2993d6e6e92'
LEAF_SHA = '47062cd22a5fa9838132c06d06dc023ec3bb95017561202648b2662de66df5b3'
# Completed auditor and handoff inspected; exact source version, no live audit.
EV_AUDITOR_SHA = 'e1db7eb1a2d54434dfb586d82d3d1924819bf9f003b35e35fdeb781ecab5a7e7'
PACKAGE_PINS = (
    ('5e52ff7a92f70dc5861947c14baaeafba79a48d464fad0f7e2f0723e5bb0a16d',
     'e9489bd43c4bf3983ab5108b41520e33c91c0d0cd6cd570e2fdb3f7a40974c8e',
     '9331b4d8b171ea6c3eead48ff0c47a909ec0db5b95cc06f6c6f97ac43f75b439'),
    ('fe72068d9797bf8714926e1df1410a42547d226ff12a563d2cfbd2fa59c1da96',
     '45e22a9aef9ffcb248442909b7c1a0d494adb9ad5882fd6db2519a3fb49051b1',
     'a9f702c0a3dc13082bfad0fc859d5a0240c7be4e2aa340a05515aaf728dc8a0d'),
    ('747d10db90d95b8c685830e21e782851e84c8f5634adaa58c3ff1943806fa9de',
     '693a860b668d94761a6b22a4ba11c22820800d040140ad151b70fd5b15c68e9a',
     '0a2c3e90ef85160ddd6584647ae2f8e1de46e6a4b7b19c2e3b16b903a6879f21'))
META_ROOT = {'manifest.json', 'METHOD_FREEZE.json', 'PREPARE_RECEIPT.json',
             'PROTOCOL.md', 'MODEL_ASSET_BASELINE.json'}
LAUNCH = {'BACKGROUND_PINS.json', 'LAUNCH.json', 'LAUNCH_CLAIM.json', 'controller.log'}
COUNTS = ('failed_cells', 'sdk_failed_cells', 'first_policy_calls', 'teacher_policy_calls',
          'actual_first_native_calls', 'actual_teacher_sdk_calls')
SPLIT_THRESHOLD = 152000  # verify_formal_payloads.split_bounds, pinned by LEAF_SHA.
COMPONENTS = ('frontend', 'asr', 'residual', 'service', 'archive')


def need(value, message):
    if not value:
        raise ValueError(message)


def pinned(name, digest, evidence=None):
    """Execute exact reviewed source bytes, without .pyc writes or runtime calls."""
    path = ROOT / name
    data = path.read_bytes() if evidence is None else evidence.read(path, digest)
    need(hashlib.sha256(data).hexdigest() == digest, 'dependency SHA: ' + name)
    module = types.ModuleType('ev_pure_' + path.stem)
    module.__file__ = str(path)
    exec(compile(data, str(path), 'exec'), module.__dict__)
    return module


def helpers(evidence=None):
    return pinned('analyze_formal.py', ANALYZER_SHA, evidence), pinned('analyze_timing.py', TIMING_SHA, evidence)


def role(value, repeat):
    need(type(repeat) is int and repeat in (0, 1, 2), 'EV repeat0/1/2 only')
    need(type(value.get('run_repeat')) is int and value['run_repeat'] == repeat
         and value.get('quality_run') is (repeat == 0), 'literal EV role')
    return 600 if repeat == 0 else 36


def bounded(base, name):
    rel = Path(name)
    need(isinstance(name, str) and not rel.is_absolute() and '..' not in rel.parts,
         'bounded input name')
    path = base / rel
    need(path.is_file() and not any(p.is_symlink() for p in (path, *path.parents))
         and path.resolve().is_relative_to(base.resolve()), 'regular collected input: ' + str(path))
    return path


def package(ev, a, p, repeat):
    prepared = ROOT / ('ev_prepared_%02d' % repeat)
    freeze_pin, manifest_pin, prep_pin = PACKAGE_PINS[repeat]
    freeze = ev.load(bounded(prepared, 'METHOD_FREEZE.json'), freeze_pin)
    manifest = ev.load(bounded(prepared, 'manifest.json'), manifest_pin)
    prep = ev.load(bounded(prepared, 'PREPARE_RECEIPT.json'), prep_pin)
    n = role(manifest, repeat); role(freeze, repeat); role(prep, repeat)
    need(not (prepared / 'PREPARE_FAILED.json').exists(), 'failed preparation')
    need(freeze['manifest_sha256'] == manifest_pin and prep['manifest_sha256'] == manifest_pin
         and prep['method_freeze_sha256'] == freeze_pin, 'prepared SHA chain')
    for name, pin in dict(freeze['code'], **freeze['evidence']).items():
        ev.read(bounded(prepared, name), pin)
    for name in ('PROTOCOL.md', 'EV_PROTOCOL_v1.md'):
        ev.read(bounded(prepared, name), freeze['protocol_sha256'])
    ev.read(bounded(prepared, 'MODEL_ASSET_BASELINE.json'), freeze['model_asset_baseline_sha256'])
    evidence = prepared / 'evidence'
    parent = ev.load(evidence / 'primary_parent_manifest.json', p.PARENT_MANIFEST_SHA256)
    parent_freeze = ev.load(evidence / 'primary_parent_METHOD_FREEZE.json', p.PARENT_FREEZE_SHA256)
    plan = ev.load(evidence / 'TIMING_SUBSET_v1.json', p.TIMING_SHA256)
    source = p.check_source_evidence(evidence, parent, parent_freeze, plan)
    p.check_original_selection(evidence / 'timing_parent_selection_receipt.json', plan, parent)
    need(manifest == p.secondary_manifest(parent, plan, repeat, manifest['reviewed_inputs_sha256'])
         and freeze == p.secondary_freeze(parent_freeze, manifest, manifest_pin, freeze['code'],
             freeze['evidence'], freeze['protocol_sha256'], freeze['ev_frontend_sha256']) | {'unix': freeze['unix']},
         'exact final secondary derivation')
    binding = ev.load(evidence / 'EV_CHILD_BINDING_v1.json')
    need(binding == p.child_binding(manifest) and binding['source_certificate_count'] == 600
         and binding['source_count'] == n, 'parent600 certificate versus own child scope')
    scoring = ev.load(evidence / 'SOURCE_AND_SCORING_FREEZE_v1.json', freeze['source_scoring_freeze_sha256'])
    for key in ('primary_normalization', 'secondary_normalization'):
        need(freeze[key] == parent_freeze[key] == scoring[key], 'unchanged normalization')
    refs = {s['id']: s for s in source['samples']}
    for row in refs.values():
        pointer = row['source_pointer']
        need(a.digest(row['reference'].encode()) == row['reference_sha256'] == pointer['reference_utf8_sha256']
             and pointer['reference'] == row['reference']
             and a.digest(pointer['raw_reference'].encode()) == pointer['raw_reference_utf8_sha256']
             and all(a.normalize(row['reference'], mode == a.MODES[0]) for mode in a.MODES),
             'original reference bytes and nonempty denominators')
    return prepared, manifest, freeze, refs, plan


def receipt_materials(ev, a, prepared, run, audit, freeze, secondary):
    """Read EVERY audited metadata name, including locally missing files (reject).

    Also reject unaudited extra collected metadata. Package payload audio/model
    tensors are never mapped here. The primary and EV inventories stay distinct.
    """
    materials = audit['input_materials_sha256']
    need(isinstance(materials, dict), 'raw receipt material mapping')
    packaged = META_ROOT | (set(freeze['code']) | set(freeze['evidence']) | {'EV_PROTOCOL_v1.md'} if secondary else set())
    expected = set(packaged) | LAUNCH
    for folder in ('native_v1', 'guard_v1'):
        directory = run / folder
        need(directory.is_dir() and not directory.is_symlink(), 'collected metadata directory')
        need(not any('FAILED' in path.name or path.name == 'RESTORATION_ATTENTION.json'
                     for path in directory.iterdir()), 'failed/partial/restoration-attention marker')
        expected |= {folder + '/' + path.name for path in directory.iterdir()
                     if path.suffix in ('.json', '.jsonl', '.log') and path.is_file()}
    need(set(materials) == expected, 'complete exact collected/audited inventory, including all frozen methods')
    for name, pin in materials.items():
        need(isinstance(pin, str) and re.fullmatch('[0-9a-f]{64}', pin), 'material digest')
        base = prepared if name in packaged else run
        ev.read(bounded(base, name), pin)
    for name, pin in dict(freeze['code'], **freeze['evidence']).items():
        ev.read(bounded(prepared, name), pin)
        if secondary:
            need(materials[name] == pin, 'raw receipt frozen method hash')
    need(materials['manifest.json'] == freeze['manifest_sha256'], 'receipt own manifest')
    if secondary:
        need(audit['frozen_code_sha256'] == freeze['code']
             and audit['frozen_evidence_sha256'] == freeze['evidence'], 'audited complete frozen maps')


def audit_contract(audit, repeat, manifest, freeze, p):
    n = role(audit, repeat)
    need(audit['schema'] == 'EV_RAW_AUDIT_v1' and audit['status'] == 'passed'
         and audit['actual_completed_run'] is True and audit['verification_complete'] is True
         and audit['verifier_sha256'] == EV_AUDITOR_SHA,
         'completed passed actual EV raw audit at pinned version')
    for key, value in dict(sources=n, cells=2*n, expected_cells=2*n, policies=2,
                          NN_calls_added=0, Qwen_SDK_execution_calls=0,
                          parent_source_certificate_count=600, child_binding_source_count=n,
                          additional_independent_quality_n=0).items():
        need(type(audit.get(key)) is int and audit[key] == value, 'receipt count: ' + key)
    need(audit['policy_names'] == list(POLICIES) and audit['selected_ids'] == manifest['sample_order']
         and audit['leaf_verifier_sha256'] == LEAF_SHA and audit['preparer_sha256'] == PREPARER_SHA
         and audit['runner_sha256'] == freeze['code']['run_native.py']
         and audit['parent_quality_manifest_sha256'] == p.PARENT_MANIFEST_SHA256
         and audit['parent_quality_method_freeze_sha256'] == p.PARENT_FREEZE_SHA256
         and audit['timing_subset_sha256'] == p.TIMING_SHA256
         and audit['source_manifest_sha256'] == manifest['source_manifest_sha256']
         and audit['source_audio_sha256'] == freeze['source_audio_sha256']
         and audit['audit_dependency_sha256'] == {str(p.BOARD / name): digest for name, digest in
              (('verify_formal_payloads.py', LEAF_SHA), ('prepare_ev.py', PREPARER_SHA),
               ('run_ev.py', freeze['code']['run_native.py']))}, 'EV receipt source/method pins')
    for key in ('DSP_decisions_and_waveforms_recomputed', 'own_greedy_raw_replayed',
                'ObservedEncoder_call_output_indices_verified', 'both_models_resident_assets_verified',
                'all_four_actor_identities_pause_restore_verified'):
        need(audit[key] is True, 'raw audit acceptance: ' + key)
    need(audit['scoring_performed'] is False and audit['source_reference_used_for_audit'] is False
         and audit['primary_quality_outputs_read'] is False,
         'raw audit scope')


def gate(ev, a, p, v, repeat):
    prepared, manifest, freeze, refs, plan = package(ev, a, p, repeat)
    run = ROOT / ('ev_secondary_%02d' % repeat)
    # Local renamed copy contains the unmodified board receipt bytes.
    audit = ev.load(bounded(ROOT, 'EV_%02d_EV_RAW_AUDIT_v1.json' % repeat))
    audit_contract(audit, repeat, manifest, freeze, p)
    need(not any('FAILED' in x.name or x.name == 'RESTORATION_ATTENTION.json' for x in run.iterdir()),
         'failed root marker')
    receipt_materials(ev, a, prepared, run, audit, freeze, True)
    complete = ev.load(run / 'native_v1/COMPLETE.json'); n = role(complete, repeat)
    need(all(type(complete.get(k)) is int and complete[k] == x for k, x in
             dict(samples=n, policies=2, outputs=2*n, expected_outputs=2*n).items()), 'full1200/72/72')
    child = ev.load(run / 'guard_v1/CHILD_EXIT.json')
    need(type(child['exit_code']) is int and child['exit_code'] == 0 and child['argv'] ==
         ['runuser', '-u', 'orangepi', '--', '/path/to/local_host/meeting-asr-qwen3/.venv/bin/python',
          '-u', manifest['remote'] + '/run_native.py'], 'own normal child exit')
    prov = ev.load(run / 'native_v1/PROVENANCE.json')
    need(prov['schema'] == 'spatial_ev_secondary_run_v1'
         and prov['manifest_sha256'] == freeze['manifest_sha256']
         and prov['method_freeze_sha256'] == PACKAGE_PINS[repeat][0]
         and prov['protocol_sha256'] == freeze['protocol_sha256']
         and prov['code_sha256'] == freeze['code'] and prov['evidence_sha256'] == freeze['evidence']
         and prov['source_reference_used_for_decisions'] is False
         and prov['operating_point'] == complete['operating_point'] == freeze['operating_point'] == audit['operating_point'],
         'actual EV provenance')
    v.verify_guard(run, prov)  # Recorded identities only, no /proc/SSH/signals.
    return dict(prepared=prepared, run=run, manifest=manifest, freeze=freeze, refs=refs,
                plan=plan, audit=audit, complete=complete)


def load_rows(ev, a, v, bundle, repeat):
    manifest, freeze, run = (bundle[k] for k in ('manifest', 'freeze', 'run'))
    native = run / 'native_v1'
    calls = ev.lines(native / 'calls.jsonl')
    expected = a.schedule(manifest['samples'], list(POLICIES))
    saved = ev.load(native / 'SCHEDULE.json')
    need(len(calls) == len(expected) and saved['rows'] == expected and saved['seed'] == SEED
         and saved['independent_policy_execution'] is True, 'complete own two-policy ordered matrix')
    sources = {s['id']: s for s in manifest['samples']}
    for row, cell in zip(calls, expected):
        role(row, repeat)
        need(all(row.get(k) == x for k, x in cell.items()) and row['fatal'] is False
             and row['independent_policy_execution'] is True, 'ordered attempted cell identity')
        s = sources[row['id']]; asr = row['asr']
        need(all(row[k] == s[k] for k in ('meeting', 'room_cluster', 'speaker_cluster'))
             and row['audio_sha256'] == s['sha256'] and row['audio_samples'] == s['frames']
             and row['operating_point'] == freeze['operating_point'], 'same source and operating point')
        need(isinstance(row['text'], str) and row['text'] == asr['text']
             and asr['policy'] == 'sense_only' and asr['invoked'] is False and asr['teacher'] is None
             and asr['sdk_calls'] == asr['sdk_errors'] == [] and type(row['actual_teacher_sdk_calls']) is int and row['actual_teacher_sdk_calls'] == 0
             and type(asr['actual_teacher_sdk_calls']) is int and asr['actual_teacher_sdk_calls'] == 0
             and asr['actual_first_native_calls'] == row['actual_first_native_calls'],
             'owned SenseVoice, Qwen resident zero SDK')
        need(asr['status'] == 'ok' or bool(asr['second_failure'] or row['cell_exception']),
             'unlogged failure')
        need(all(type(row[k]) is int and row[k] >= 0 for k in
                 ('actual_first_native_calls', 'completed_first_native_calls', 'actual_teacher_sdk_calls'))
             and row['completed_first_native_calls'] <= row['actual_first_native_calls'], 'actual native counts')
        cost_row(a, row, s, repeat)
    failures, counts = a.validate_failure_accounting(ev, native, calls, bundle['complete'])
    audit = bundle['audit']
    need(all(type(audit.get(k)) is int and audit[k] == counts[k] for k in COUNTS)
         and audit['verified_cell_totals'] == {k: counts[k] for k in COUNTS}
         and audit['observed_cell_totals'] == {k: counts[k] for k in COUNTS}
         and counts['sdk_failed_cells'] == counts['teacher_policy_calls'] == counts['actual_teacher_sdk_calls'] == 0,
         'receipt/complete/calls dual ledgers and SDK zero')
    retained = audit['attempted_failures']
    need(len(retained) == len(failures) and all(all(saved.get(k) == x for k, x in row.items())
         for saved, row in zip(retained, failures)), 'receipt retained failures')
    need(audit['audited_cells'] == audit['observed_cells'] == len(calls)
         and audit['audited_sources'] == len(sources), 'actual audited/observed counts')
    raw_index = ev.load(native / 'RAW_INDEX.json')
    wave_index = ev.load(native / 'PROCESSED_AUDIO_INDEX.json')
    need(raw_index == audit['raw_payload_index'] and wave_index == audit['processed_audio_index']
         and audit['raw_payloads_verified'] == bundle['complete']['unique_raw_payloads'] == len(raw_index)
         and audit['processed_waveforms_verified'] == bundle['complete']['processed_audio_files'] == len(wave_index)
         and audit['raw_occurrences'] == sum(len(r['raw_tensor']) for r in calls)
         and audit['DSP_waveforms_compared'] == len(calls), 'audited all raw/processed metadata coverage')
    init = ev.load(native / 'INITIALIZATION.json')
    need(init['both_resident'] is True and init['excluded_from_service'] is True
         and init['operating_point'] == freeze['operating_point'], 'two resident models and excluded init')
    runtime = ev.load(native / 'RUNTIME_BINDINGS.json', ev.load(native / 'PROVENANCE.json')['runtime_bindings_sha256'])
    need(runtime == audit['runtime_assets'], 'audited runtime assets')
    io = ev.lines(native / 'SOURCE_IO.jsonl')
    need([r['id'] for r in io] == manifest['sample_order'] and all(r['decoded_once'] is True
         and r['excluded_from_service'] is True and a.finite(r['source_io_s'])
         and a.finite(r['source_integrity_s']) for r in io), 'shared source IO excluded')
    return calls, dict(initialization=init, environment_ranges=a.environment_summary(calls),
                       runtime_bindings=runtime, failures=failures, failure_and_actual_counts=counts,
                       source_io=io, completion=bundle['complete'])


def cost_row(a, row, source, repeat):
    values = dict(frontend=row['frontend_s'], asr=row['asr']['service_s'],
                  residual=row['frontend_plus_asr_residual_s'], service=row['service_s'],
                  archive=row['research_archive_s'])
    need(all(a.finite(x, key != 'residual') for key, x in values.items())
         and a.near(values['service'], values['frontend'] + values['asr'] + values['residual']),
         'actual signed service decomposition')
    return dict(id=row['id'], meeting=row['meeting'], room=row['room_cluster'], policy=row['policy'],
                round=repeat, source_frames=source['frames'],
                failed=bool(row['asr']['second_failure'] or row['cell_exception']), **values)


def quality(a, rows, sources):
    """Score/aggregate/cluster_effect are the unchanged c900af pure helpers."""
    import numpy as np
    results = {k: [] for k in ('per_policy', 'per_meeting', 'per_room', 'contrasts',
                              'paired_sources', 'paired_meetings', 'leave_one_room_out', 'duration_context')}
    meetings = sorted({s['meeting'] for s in sources}); rooms = sorted({s['room_cluster'] for s in sources})
    draws = np.random.default_rng(SEED).integers(0, len(meetings), (DRAWS, len(meetings)))
    cutoff = SPLIT_THRESHOLD / 16000
    for mode in a.MODES:
        selected = [r for r in rows if r['mode'] == mode]
        indexed = {(r['id'], r['policy']): r for r in selected}
        need(len(indexed) == len(selected) == 2 * len(sources), 'all source/policy scores once per mode')
        for policy in POLICIES:
            group = [r for r in selected if r['policy'] == policy]
            own = [dict(mode=mode, policy=policy, meeting=m,
                   room=next(r['room'] for r in group if r['meeting'] == m),
                   **a.aggregate([r for r in group if r['meeting'] == m])) for m in meetings]
            results['per_meeting'].extend(own)
            results['per_room'].extend(dict(mode=mode, policy=policy, room=room,
                   **a.aggregate([r for r in group if r['room'] == room])) for room in rooms)
            ci = a.cluster_effect([r['errors'] for r in own], [r['reference_characters'] for r in own], .95, draws)
            results['per_policy'].append(dict(mode=mode, policy=policy, **a.aggregate(group),
                   equal_meeting_cer=ci['equal_meeting_cer_delta'],
                   pooled_cer_ci=[ci['pooled_ci_low'], ci['pooled_ci_high']],
                   equal_meeting_cer_ci=[ci['equal_meeting_ci_low'], ci['equal_meeting_ci_high']]))
        pairs = []
        for s in sources:
            left, right = (indexed[s['id'], p] for p in POLICIES)
            need(left['normalized_reference'] == right['normalized_reference'], 'paired reference')
            delta = left['errors'] - right['errors']
            pairs.append(dict(mode=mode, id=s['id'], meeting=s['meeting'], room=s['room_cluster'],
                duration_s=s['frames']/16000, reference_characters=left['reference_characters'],
                candidate_errors=left['errors'], baseline_errors=right['errors'], error_delta=delta,
                cer_delta=delta/left['reference_characters'],
                baseline_zero_damage=right['errors'] == 0 and delta > 0))
        results['paired_sources'].extend(pairs)
        own = [dict(mode=mode, meeting=m, room=next(r['room'] for r in pairs if r['meeting'] == m),
                    n=sum(r['meeting'] == m for r in pairs),
                    error_delta=sum(r['error_delta'] for r in pairs if r['meeting'] == m),
                    reference_characters=sum(r['reference_characters'] for r in pairs if r['meeting'] == m)) for m in meetings]
        for r in own:
            r['cer_delta'] = r['error_delta']/r['reference_characters']
            r['direction'] = 'gain' if r['error_delta'] < 0 else 'loss' if r['error_delta'] > 0 else 'tie'
        results['paired_meetings'].extend(own)
        effect = a.cluster_effect([r['error_delta'] for r in own], [r['reference_characters'] for r in own], .95, draws)
        results['contrasts'].append(dict(mode=mode, candidate=POLICIES[0], baseline=POLICIES[1],
            role='descriptive_late_secondary', **effect, sources=len(pairs), meetings=len(meetings),
            error_delta=sum(r['error_delta'] for r in pairs),
            source_directions={k: sum(('gain' if r['error_delta'] < 0 else 'loss' if r['error_delta'] > 0 else 'tie') == k for r in pairs) for k in ('gain', 'loss', 'tie')},
            meeting_directions={k: sum(r['direction'] == k for r in own) for k in ('gain', 'loss', 'tie')},
            baseline_zero_sources=sum(r['baseline_errors'] == 0 for r in pairs),
            baseline_zero_damaged=sum(r['baseline_zero_damage'] for r in pairs),
            baseline_zero_damage_errors=sum(r['error_delta'] for r in pairs if r['baseline_zero_damage'])))
        for room in rooms:
            keep = [r for r in own if r['room'] != room]
            results['leave_one_room_out'].append(dict(mode=mode, omitted_room=room,
                sources=sum(r['n'] for r in keep), meetings=len(keep),
                **(a.cluster_effect([r['error_delta'] for r in keep], [r['reference_characters'] for r in keep], .95)
                   if keep else {'unavailable': 'no remaining meetings'})))
        for label in ('short', 'long'):
            ids = {r['id'] for r in pairs if (r['duration_s'] <= cutoff) == (label == 'short')}
            part = [r for r in pairs if r['id'] in ids]
            results['duration_context'].append(dict(mode=mode, split=label, cutoff_s=cutoff,
                rule='short <= frozen152000 samples (9.5s); long requires supported split; descriptive context only',
                sources=len(ids), meetings=len({r['meeting'] for r in part}),
                pooled_cer_delta=(sum(r['error_delta'] for r in part)/sum(r['reference_characters'] for r in part)) if part else None,
                **{p: a.aggregate([r for r in selected if r['id'] in ids and r['policy'] == p]) if part else None for p in POLICIES}))
    return results


def selectors(a, calls):
    """Actual diagnostics only; no ranking reconstruction from audio/results."""
    indexed = {(r['id'], r['policy']): r for r in calls}
    rows = []
    for sid in sorted({r['id'] for r in calls}):
        left, right = (indexed[sid, p] for p in POLICIES)
        ev, rms = left['frontend'], right['frontend']
        def top_gap(values):
            if not isinstance(values, list) or len(values) != 8 or not all(a.finite(x) for x in values):
                return None
            high, second = sorted(values, reverse=True)[:2]
            return dict(top_minus_second=high-second, relative_gap=(high-second)/abs(high) if high else None,
                        exact_top_tie=high == second)
        # Failed frontend cells remain in quality and in the missing-diag count.
        available = isinstance(ev, dict) and 'fallback_used' in ev
        fallback = ev.get('fallback_used') if available else None
        if available:
            need(type(fallback) is bool and ev['ranking_valid'] is (not fallback)
                 and ev['defined'] is (not fallback), 'real EV diagnostic flags')
            if fallback:
                need(ev['status'] == 'undefined_score_fallback_ch0' and ev['selected_channel'] == 0
                     and ev['ev_selected_channel'] is None, 'explicit real EV fallback status')
        lc = ev.get('selected_channel') if isinstance(ev, dict) else None
        rc = rms.get('selected_channel') if isinstance(rms, dict) else None
        for channel in (lc, rc):
            need(channel is None or type(channel) is int and 0 <= channel < 8, 'actual selected channel')
        rows.append(dict(id=sid, meeting=left['meeting'], room=left['room_cluster'],
            ev_diagnostic_status=ev.get('status') if isinstance(ev, dict) else None,
            ev_fallback=fallback, ev_channel=lc, rms_channel=rc,
            agreement=(lc == rc) if lc is not None and rc is not None else None,
            ev_gap=top_gap(ev.get('scores')) if available and not fallback else None,
            rms_gap=top_gap(rms.get('channel_rms')) if isinstance(rms, dict) else None,
            ev_diagnostic=ev, rms_diagnostic=rms))
    paired = [r for r in rows if r['agreement'] is not None]
    gaps = {}
    for policy in ('ev', 'rms'):
        own = [r[policy + '_gap'] for r in rows if r[policy + '_gap'] is not None]
        gaps[policy] = dict(available=len(own), exact_top_ties=sum(r['exact_top_tie'] for r in own),
            absolute_gaps=[r['top_minus_second'] for r in own],
            relative_gaps=[r['relative_gap'] for r in own], units='selector score (EV) or amplitude (RMS), never seconds')
    valid = [r for r in paired if r['ev_fallback'] is False]
    return dict(sources=len(rows), observed_gaps=gaps, fallback_sources=sum(r['ev_fallback'] is True for r in rows),
        missing_ev_diagnostics=sum(r['ev_fallback'] is None for r in rows),
        paired_selection_sources=len(paired), agreeing_sources=sum(r['agreement'] for r in paired),
        agreement_rate=sum(r['agreement'] for r in paired)/len(paired) if paired else None,
        valid_ranking_sources=len(valid), valid_ranking_agreement_rate=sum(r['agreement'] for r in valid)/len(valid) if valid else None,
        gap_scope='observed top1-top2 EV score / RMS amplitude gap; exact tie and relative gap retained, no tuned near-tie threshold'), rows


def split_context(a, calls, sources):
    """Frozen split boundary from the pinned raw leaf; use actual recorded parts."""
    indexed = {(r['id'], r['policy']): r for r in calls}
    rows = []
    for source in sources:
        parts = {}
        for policy in POLICIES:
            row = indexed[source['id'], policy]
            first = row['asr'].get('first')
            value = first.get('parts') if isinstance(first, dict) else None
            intervals = [(p['start_sample'], p['end_sample']) for p in value] if value else None
            if intervals is not None:
                need(intervals[0][0] == 0 and intervals[-1][1] == source['frames']
                     and all(0 <= left < right <= source['frames'] for left, right in intervals)
                     and all(x[1] == y[0] for x, y in zip(intervals, intervals[1:]))
                     and len(intervals) == (2 if source['frames'] > SPLIT_THRESHOLD else 1),
                     'actual supported complete split intervals')
            parts[policy] = intervals
        left, right = (parts[p] for p in POLICIES)
        rows.append(dict(id=source['id'], meeting=source['meeting'], room=source['room_cluster'],
            frames=source['frames'], length_class='long' if source['frames'] > SPLIT_THRESHOLD else 'short',
            threshold_samples=SPLIT_THRESHOLD, threshold_source_sha256=LEAF_SHA,
            recorded_intervals=parts, split_changed=(left != right) if left and right else None,
            cut_delta_samples=left[0][1]-right[0][1] if left and right and len(left) == len(right) == 2 else None))
    return rows


def stability(a, old, new):
    fields = ('substitutions', 'deletions', 'insertions', 'errors', 'reference_characters')
    indexed = {(r['id'], r['mode']): r for r in old if r['policy'] == 'rms_sense'}
    rows = []
    for r in new:
        if r['policy'] != 'rms_sense':
            continue
        previous = indexed.pop((r['id'], r['mode']))
        need(all(previous[k] == r[k] for k in ('meeting', 'room', 'reference_sha256', 'normalized_reference')),
             'original RMS same source/reference/group')
        rows.append(dict(id=r['id'], mode=r['mode'], meeting=r['meeting'], room=r['room'],
            raw_equal=previous['hypothesis'] == r['hypothesis'],
            normalized_equal=previous['normalized_hypothesis'] == r['normalized_hypothesis'],
            error_total_equal=previous['errors'] == r['errors'], sdi_equal=all(previous[k] == r[k] for k in fields),
            original_raw=previous['hypothesis'], secondary_raw=r['hypothesis'],
            original_normalized=previous['normalized_hypothesis'], secondary_normalized=r['normalized_hypothesis'],
            original_counts={k: previous[k] for k in fields}, secondary_counts={k: r[k] for k in fields},
            original_failed=previous['failed'], secondary_failed=r['failed']))
    need(not indexed, 'every original RMS source/mode compared once')
    summary = [dict(mode=mode, sources=sum(r['mode'] == mode for r in rows),
                    **{key: sum(r[key] for r in rows if r['mode'] == mode)
                       for key in ('raw_equal', 'normalized_equal', 'error_total_equal', 'sdi_equal')}) for mode in a.MODES]
    return summary, rows


def primary(ev, a, t, v, refs, analysis):
    manifest, run, complete = t.gate(ev, a, 0)  # Primary nine-policy gates stay unchanged.
    prepared = ROOT / 'prepared_01'
    freeze = ev.load(prepared / 'METHOD_FREEZE.json')
    need(manifest.get('schema') != 'spatial_ev_secondary_manifest_v1' and len(manifest['samples']) == 600
         and freeze['expected_cells'] == 5400, 'original primary600 scope')
    ev.read(prepared / 'manifest.json', '7dbdaa0aa866c504e958fb75cc90fa101e27b3c4ae816ccf0c418d9134821a47')
    ev.read(prepared / 'METHOD_FREEZE.json', '85a82ef9c30ea01a66b524e71d8600001f35925dce4980693ebb2641ce5dc793')
    audit = ev.load(ROOT / 'FORMAL_FORMAL_RAW_AUDIT_v1.json')
    need(audit['schema'] == 'FORMAL_RAW_AUDIT_v1', 'primary raw receipt schema')
    receipt_materials(ev, a, prepared, run, audit, freeze, False)
    v.verify_guard(run, ev.load(run / 'native_v1/PROVENANCE.json'))
    a.gate_complete(ev, run, manifest, freeze)
    need({s['id']: s for s in ev.load(prepared / 'evidence/source_manifest.json', freeze['source_manifest_sha256'])['samples']} == refs,
         'original versus EV same full source/reference manifest')
    validation = ev.load(bounded(analysis, 'VALIDATION.json'))
    need(validation['status'] == 'metadata_and_scoring_validated_NOT_raw_byte_audit'
         and validation['all_gates_passed'] is True and validation['analyzer_sha256'] == ANALYZER_SHA
         and validation['expected_cells'] == validation['observed_owned_cells'] == 5400
         and validation['unicode_database_version'] == unicodedata.unidata_version,
         'original completed analysis and identical Unicode database')
    t.verify_primary_inventory(a, validation['output_sha256'], analysis)
    for name, pin in validation['output_sha256'].items():
        ev.read(bounded(analysis, name), pin)
    for name, pin in validation['input_sha256'].items():
        path = Path(name)
        need(path.is_absolute() and path.is_relative_to(ROOT), 'bounded original analysis input')
        relative = str(path.relative_to(ROOT))
        need(not any(part in ('raw_sv', 'processed_audio', 'audio') for part in path.parts),
             'analysis provenance must not reopen payload bytes')
        ev.read(bounded(ROOT, relative), pin)
    for name in ('calls.jsonl', 'COMPLETE.json', 'PROVENANCE.json'):
        path = str((run / 'native_v1' / name).resolve())
        need(validation['input_sha256'][path] == ev.hashes[path], 'original raw/scored provenance')
    baseline = ev.load(prepared / 'MODEL_ASSET_BASELINE.json', freeze['model_asset_baseline_sha256'])
    calls, *_ = a.validate_records(ev, run, manifest, freeze, complete, baseline)
    rms = [r for r in calls if r['policy'] == 'rms_sense']
    rescored = a.score(rms, refs)
    saved = [r for r in ev.load(analysis / 'per_example.json') if r['policy'] == 'rms_sense']
    # Per-file line numbers differ after selecting RMS; every score/text remains exact.
    clean = lambda r: {k: x for k, x in r.items() if k != 'calls_jsonl_line'}
    need([clean(r) for r in saved] == [clean(r) for r in rescored], 'unchanged original RMS raw/norm/S-D-I scores')
    return rescored, calls, manifest


def costs(a, t, rows):
    summaries = []
    for repeat in sorted({r['round'] for r in rows}):
        for policy in POLICIES:
            own = [r for r in rows if r['round'] == repeat and r['policy'] == policy]
            summaries.append(dict(round=repeat, policy=policy, sources=len(own),
                failed_cells=sum(r['failed'] for r in own),
                **{key: a.seconds(r[key] for r in own) for key in COMPONENTS}))
    effect, pairs = t.repeated_effect('ev_sense', 'rms_sense', rows, .95)
    return dict(policy_by_round=summaries, repeated_contrast=effect, repeated_source_pairs=pairs)


def run(output, analysis):
    need(output == ROOT / 'ev_analysis_v1' and not output.exists() and not output.is_symlink(),
         'only fresh ev_analysis_v1; existing output refused')
    need(analysis.parent == ROOT and analysis.name.startswith(('mainanalysis_v', 'analysis_v')) and not analysis.is_symlink(),
         'original primary analysis sibling')
    a, t = helpers(); ev = a.Evidence(); helpers(ev)
    p = pinned('prepare_ev.py', PREPARER_SHA, ev)
    v = pinned('verify_formal_payloads.py', LEAF_SHA, ev)
    ev.read(ROOT / 'verify_ev_payloads.py', EV_AUDITOR_SHA)
    bundles = [gate(ev, a, p, v, r) for r in (0, 1, 2)]
    refs, plan = bundles[0]['refs'], bundles[0]['plan']
    for b in bundles:
        need(b['refs'] == refs and b['plan'] == plan, 'all packages same parent600/frozen36 evidence')
    original, main_calls, main_manifest = primary(ev, a, t, v, refs, analysis)
    calls, environments, timing_rows = {}, {}, []
    for repeat, bundle in enumerate(bundles):
        calls[repeat], environments[repeat] = load_rows(ev, a, v, bundle, repeat)
        lookup = {s['id']: s for s in bundle['manifest']['samples']}
        timing_rows.extend(cost_row(a, r, lookup[r['id']], repeat) for r in calls[repeat])
    need(sum(len(x) for x in calls.values()) == 1344, 'exact total1344 actual added cells')
    rows = a.score(calls[0], refs)
    result = quality(a, rows, bundles[0]['manifest']['samples'])
    select_summary, select_rows = selectors(a, calls[0])
    for repeat, bundle in enumerate(bundles):
        own_summary, own = selectors(a, calls[repeat])
        fallback = [r['id'] for r in own if r['ev_fallback'] is True]
        need(set(fallback) == set(bundle['audit']['EV_fallback_source_ids'])
             and len(fallback) == bundle['audit']['EV_fallback_cells'], 'actual fallback/receipt consistency')
        environments[repeat]['selector_summary'] = own_summary
    stable_summary, stable_rows = stability(a, original, rows)
    splits = split_context(a, calls[0], bundles[0]['manifest']['samples'])
    cost = costs(a, t, timing_rows)
    main_sources = {s['id']: s for s in main_manifest['samples']}
    context = [dict(context='original_primary_matched36_descriptive_only',
                    **cost_row(a, r, main_sources[r['id']], 0)) for r in main_calls
               if r['id'] in set(plan['selected_ids']) and r['policy'] == 'rms_sense']
    need(len(context) == 36 and cost['repeated_contrast']['sources'] == 36, 'matched panel, no cell independence')
    summary = dict(status='completed_audited_EV_secondary_analysis', quality_sources=600,
        additional_independent_quality_n=0, actual_added_cells=1344, secondary_quality_cells=1200,
        repeated_cost_cells=144, policies=list(POLICIES), primary_quality_outputs_replaced=False,
        original_primary_quality_cells=5400, bootstrap=dict(draws=DRAWS, seed=SEED, confidence=.95,
            unit='meeting preserving source/policy pairs; cost averages rounds1/2 within source first', interpretation='descriptive late secondary'),
        normalization={key: bundles[0]['freeze'][key] for key in ('primary_normalization', 'secondary_normalization')},
        unicode_database_version=unicodedata.unidata_version,
        quality_contrasts=result['contrasts'], selector_summary=select_summary, rms_stability=stable_summary,
        repeated_cost=cost['repeated_contrast'], round_environment_initialization=environments,
        cost_scope='both models resident; source IO/integrity, initialization, archive excluded; signed residual retained',
        inference_scope='cost conditional on frozen36 sources and fixed two rounds; no cross-session tiny-difference, cross-day/device or energy inference',
        original_primary_matched36_role='RMS descriptive context only; never pooled into repeated estimate or quality',
        raw_payload_bytes_reopened_locally=False, raw_semantic_replay_locally=False,
        raw_board_receipts_verified=True, automatic_publication_value_claim=False)
    artifacts = {'summary.json': a.json_text(summary), 'per_example.json': a.json_text(rows),
                 'per_example.csv': a.csv_text(rows), 'selector_sources.json': a.json_text(select_rows),
                 'selector_sources.csv': a.csv_text(select_rows),
                 'rms_stability_sources.csv': a.csv_text(stable_rows),
                 'rms_stability_sources.json': a.json_text(stable_rows),
                 'split_context_sources.json': a.json_text(splits),
                 'original_primary_matched36_context.json': a.json_text(context),
                 'actual_cost_cells.json': a.json_text(timing_rows)}
    for name, value in dict(result, **cost).items():
        artifacts[name + '.json'] = a.json_text(value)
        if isinstance(value, list):
            artifacts[name + '.csv'] = a.csv_text(value)
    for repeat in (0, 1, 2):
        artifacts['owned_attempts_%02d.jsonl' % repeat] = ''.join(a.json_text(r).strip().replace('\n', '') + '\n' for r in calls[repeat])
    report = ['# EV versus RMS secondary analysis', '',
        '600 reused independent quality sources; 1200 contemporaneous quality cells and144 cost-repeat cells. '
        'Original5400 primary cells and their scores remain unchanged. Repeats add zero quality n.', '',
        'EV minus RMS quality intervals are descriptive95% paired meeting bootstrap,10000 draws, seed20261015. '
        'Both casefold and case-preserved scores include every attempted outcome, including failures.', '',
        'Cost first averages rounds1/2 within each source/policy, then resamples meetings. '
        'Baseline/candidate ratio means RMS/EV. It conditions on the frozen36-source panel and these two rounds. '
        'Original matched36 RMS is descriptive context only. Both models stay resident; initialization, source I/O, '
        'integrity and research archive are excluded. No energy or cross-day/device claim.', '',
        'Selector gaps are raw observed top1-top2 EV scores and RMS amplitudes, with relative gaps/exact ties. '
        'Undefined EV rankings and missing diagnostics remain disclosed. RMS stability compares original and secondary '
        'raw text, normalized text, total errors and S/D/I; it never selects a favorable repeat.', '']
    for r in result['contrasts']:
        report.append(f"{r['mode']}: pooled EV−RMS CER {r['pooled_cer_delta']:.6f} "
                      f"[{r['pooled_ci_low']:.6f}, {r['pooled_ci_high']:.6f}]; equal-meeting "
                      f"{r['equal_meeting_cer_delta']:.6f} [{r['equal_meeting_ci_low']:.6f}, {r['equal_meeting_ci_high']:.6f}].")
    report.append(a.json_text(dict(selector_summary=select_summary, rms_stability=stable_summary, repeated_cost=cost['repeated_contrast'])))
    artifacts['REPORT.md'] = '\n'.join(report) + '\n'
    ev.read(Path(__file__))
    ev.stable()
    validation = dict(status=summary['status'], all_gates_passed=True, actual_added_cells=1344,
        independent_quality_sources=600, additional_independent_quality_n=0,
        input_sha256=ev.hashes, output_sha256={n: a.digest(s.encode()) for n, s in artifacts.items()},
        analyzer_sha256=a.digest(Path(__file__).read_bytes()), pure_score_helper_sha256=ANALYZER_SHA,
        repeated_cost_helper_sha256=TIMING_SHA, raw_auditor_sha256=EV_AUDITOR_SHA,
        unicode_database_version=unicodedata.unidata_version, python=sys.version,
        numpy_version=__import__('numpy').__version__, seed=SEED, draws=DRAWS,
        actual_board_raw_audit_receipts_verified=True, local_raw_replay=False)
    artifacts['VALIDATION.json'] = a.json_text(validation)  # Nonrecursive artifact inventory.
    # No directory or PASS-like receipt is written on any missing/partial/mismatch gate.
    output.mkdir(exist_ok=False)
    for name, text in artifacts.items():
        with (output / name).open('x', encoding='utf-8', newline='') as stream:
            stream.write(text)
    return validation


def synthetic_publication(a, t):
    """Exercise the complete1344-cell report/serialization path in RAM only.

    Gate acceptance, primary records and run rows are injected; raw gate mutations
    are tested separately. This is not an end-to-end actual audit assertion.
    """
    import io
    refs, sources, calls = {}, [], {0: [], 1: [], 2: []}
    for i in range(600):
        sid = str(i); text = 'Ａb １２'
        refs[sid] = dict(reference=text, reference_sha256=a.digest(text.encode()), source_pointer={'id': sid})
        source = dict(id=sid, meeting='m%d' % (i % 18), room_cluster='r%d' % (i % 3),
                      speaker_cluster='sp', frames=160000 if i % 2 else 32000)
        sources.append(source)
        for policy in POLICIES:
            parts = [dict(start_sample=0, end_sample=source['frames'])] if source['frames'] <= SPLIT_THRESHOLD else [
                dict(start_sample=0, end_sample=80000), dict(start_sample=80000, end_sample=source['frames'])]
            row = dict(id=sid, policy=policy, meeting=source['meeting'], room_cluster=source['room_cluster'],
                speaker_cluster='sp', text=text, cell_exception=None, frontend_s=.1, service_s=1.,
                frontend_plus_asr_residual_s=-.01, research_archive_s=.02,
                asr=dict(status='ok', second_failure=None, service_s=.91, first={'parts': parts}))
            row['frontend'] = dict(selected_channel=0, fallback_used=False, ranking_valid=True, defined=True,
                ev_selected_channel=0, scores=[1.0]*8) if policy == 'ev_sense' else dict(selected_channel=0, channel_rms=[1.0]*8)
            calls[0].append(row)
            if i < 36:
                for repeat in (1, 2): calls[repeat].append(dict(row))
    ids = [s['id'] for s in sources[:36]]
    bundles = [dict(refs=refs, plan={'selected_ids': ids}, manifest={'samples': sources if r == 0 else sources[:36]},
        audit=dict(EV_fallback_source_ids=[], EV_fallback_cells=0),
        freeze=dict(primary_normalization='synthetic', secondary_normalization='synthetic')) for r in (0, 1, 2)]
    old = a.score([r for r in calls[0] if r['policy'] == 'rms_sense'], refs)
    artifacts = {}
    class RAMOutput:
        def __eq__(self, other): return other == ROOT / 'ev_analysis_v1'
        def exists(self): return False
        def is_symlink(self): return False
        def mkdir(self, **kw): pass
        def __truediv__(self, name):
            class Target:
                def open(self, mode, **kw):
                    need(mode == 'x' and name not in artifacts, 'exclusive RAM artifact')
                    class Writer(io.StringIO):
                        def __exit__(self, *args):
                            artifacts[name] = self.getvalue()
                            return super().__exit__(*args)
                    return Writer()
            return Target()
    overrides = dict(helpers=lambda evidence=None: (a, t), gate=lambda *args: bundles[args[-1]],
        primary=lambda *args: (old, calls[0], {'samples': sources}),
        load_rows=lambda *args: (calls[args[-1]], {}))
    saved = {k: globals()[k] for k in overrides}
    try:
        globals().update(overrides)
        validation = run(RAMOutput(), ROOT / 'analysis_v1')
    finally:
        globals().update(saved)
    need(validation['actual_added_cells'] == 1344 and validation['independent_quality_sources'] == 600,
         'synthetic publication counts')
    for name, pin in validation['output_sha256'].items():
        need(a.digest(artifacts[name].encode()) == pin, 'RAM output digest')
    need(len(a.parse(artifacts['per_example.json'])) == 2400
         and len(a.parse(artifacts['rms_stability_sources.json'])) == 1200
         and len(a.parse(artifacts['actual_cost_cells.json'])) == 1344, 'RAM score/stability/cost dimensions')
    for repeat, n in ((0, 1200), (1, 72), (2, 72)):
        lines = artifacts['owned_attempts_%02d.jsonl' % repeat].splitlines()
        need(len(lines) == n and all(a.parse(line)['policy'] in POLICIES for line in lines), 'RAM complete JSONL')
    return len(artifacts)


def self_test():
    """In-memory synthetic only; helper source reads, no data/fixture directories."""
    a, t = helpers()
    calls, refs, sources = [], {}, []
    for i in range(8):
        sid = str(i); reference = 'Ａb Straße １２!'
        refs[sid] = dict(reference=reference, reference_sha256=a.digest(reference.encode()), source_pointer={'id': sid})
        sources.append(dict(id=sid, meeting='m' + str(i//2), room_cluster='r' + str(i//4), frames=32000+i*16000))
        for policy in POLICIES:
            text = reference if policy == 'rms_sense' else ('ab strasse 12' if i % 2 == 0 else '')
            calls.append(dict(id=sid, policy=policy, text=text, meeting=sources[-1]['meeting'],
                room_cluster=sources[-1]['room_cluster'], speaker_cluster='sp', cell_exception=None,
                asr=dict(status='ok', second_failure=None)))
    rows = a.score(calls, refs); result = quality(a, rows, sources)
    failed = dict(calls[0], cell_exception={'type': 'synthetic_failure'}, text='',
                  asr=dict(status='cell_failed', second_failure=None))
    failed_scores = a.score([failed], refs)
    need(len(failed_scores) == 2 and all(r['failed'] and r['errors'] == r['reference_characters']
         for r in failed_scores), 'failed attempted outcome kept in both denominators')
    need(len(rows) == 32 and len(result['paired_sources']) == 16
         and len(result['per_room']) == 8 and len(result['leave_one_room_out']) == 4, 'quality dimensions')
    need(a.normalize('Ａ ß!１２') == 'ass12' and a.normalize('Ａ ß!１２', False) == 'Aß12', 'Unicode modes')
    need([r['baseline_zero_damaged'] for r in result['contrasts']] == [4, 8], 'baseline-zero damage retained in both modes')
    zero = quality(a, a.score([dict(r, text=reference) for r in calls], refs), sources)
    need(all(r['pooled_ci_low'] == r['pooled_ci_high'] == 0 for r in zero['contrasts']), 'paired zero interval')
    sums, comparisons = stability(a, rows, rows)
    need(all(r['raw_equal'] == 8 for r in sums) and len(comparisons) == 16, 'stability exact match')
    changed_calls = [dict(r, text=r['text']+'!') if r['policy'] == 'rms_sense' and r['id'] == '0' else r for r in calls]
    changed_summary, _ = stability(a, rows, a.score(changed_calls, refs))
    need(all(r['raw_equal'] == 7 and r['normalized_equal'] == r['sdi_equal'] == 8 for r in changed_summary),
         'raw changes distinguished from normalized/error agreement')
    timing = [dict(id=s['id'], meeting=s['meeting'], policy=p, round=r,
        service=(2 if p == 'ev_sense' else 4)*r) for s in sources for p in POLICIES for r in (1, 2)]
    effect, pairs = t.repeated_effect('ev_sense', 'rms_sense', timing)
    need(effect['baseline_over_candidate_ratio'] == 2 and effect['candidate_minus_baseline_s'] == -3
         and effect['ratio_ci'] == [2, 2] and len(pairs) == 8, 'fixed-round source means and ratio')
    # Unequal cluster sizes test pooled and equal-meeting estimands independently.
    eff = a.cluster_effect([1, -1], [1, 9], .95)
    need(eff['pooled_cer_delta'] == 0 and abs(eff['equal_meeting_cer_delta']-4/9) < 1e-12, 'distinct estimands')
    for bad in ({'quality_run': 1, 'run_repeat': 0}, {'quality_run': True, 'run_repeat': False}):
        try:
            role(bad, 0)
        except ValueError:
            pass
        else:
            raise AssertionError('bad typed role accepted')
    from copy import deepcopy
    rejects = 0
    def reject(fn, *args):
        nonlocal rejects
        try:
            fn(*args)
        except (ValueError, FileNotFoundError, KeyError, TypeError):
            rejects += 1
        else:
            raise AssertionError('invalid synthetic evidence accepted')

    # Literal current raw receipt schema; no fabricated on-disk receipt.
    p = types.SimpleNamespace(PARENT_MANIFEST_SHA256='parent_manifest', PARENT_FREEZE_SHA256='parent_freeze',
                              TIMING_SHA256='subset', BOARD=Path('/synthetic_board'))
    for repeat in (0, 1, 2):
        n = 600 if repeat == 0 else 36
        manifest = dict(sample_order=[str(i) for i in range(n)], source_manifest_sha256='sources')
        freeze = dict(code={'run_native.py': 'runner'}, source_audio_sha256={'source': 'sha'})
        audit = dict(schema='EV_RAW_AUDIT_v1', status='passed', actual_completed_run=True,
            verification_complete=True, verifier_sha256=EV_AUDITOR_SHA, quality_run=repeat == 0,
            run_repeat=repeat, sources=n, cells=2*n, expected_cells=2*n, policies=2,
            NN_calls_added=0, Qwen_SDK_execution_calls=0, parent_source_certificate_count=600,
            child_binding_source_count=n, additional_independent_quality_n=0, policy_names=list(POLICIES),
            selected_ids=manifest['sample_order'], leaf_verifier_sha256=LEAF_SHA, preparer_sha256=PREPARER_SHA,
            runner_sha256='runner', parent_quality_manifest_sha256='parent_manifest',
            parent_quality_method_freeze_sha256='parent_freeze', timing_subset_sha256='subset',
            source_manifest_sha256='sources', source_audio_sha256=freeze['source_audio_sha256'],
            audit_dependency_sha256={str(p.BOARD / name): digest for name, digest in
              (('verify_formal_payloads.py', LEAF_SHA), ('prepare_ev.py', PREPARER_SHA), ('run_ev.py', 'runner'))},
            DSP_decisions_and_waveforms_recomputed=True, own_greedy_raw_replayed=True,
            ObservedEncoder_call_output_indices_verified=True, both_models_resident_assets_verified=True,
            all_four_actor_identities_pause_restore_verified=True, scoring_performed=False,
            source_reference_used_for_audit=False, primary_quality_outputs_read=False)
        audit_contract(audit, repeat, manifest, freeze, p)
        for key, value in [('status', 'failed'), ('verification_complete', False), ('verifier_sha256', 'stale'),
                           ('cells', 2*n-1), ('run_repeat', True), ('policy_names', list(a.POLICIES)),
                           ('NN_calls_added', 1), ('Qwen_SDK_execution_calls', 1),
                           ('parent_source_certificate_count', 36), ('additional_independent_quality_n', 144),
                           ('source_audio_sha256', {}), ('audit_dependency_sha256', {})]:
            bad = deepcopy(audit); bad[key] = value
            reject(audit_contract, bad, repeat, manifest, freeze, p)
        bad = deepcopy(audit); del bad['verification_complete']
        reject(audit_contract, bad, repeat, manifest, freeze, p)

    # Full collected inventory test in RAM: a receipt entry absent locally must
    # fail, just as an extra unaudited collected metadata file must fail.
    class MemoryPath:
        def __init__(self, name): self.name = name
        def __truediv__(self, name): return MemoryPath(self.name + '/' + name)
        def is_dir(self): return True
        def is_symlink(self): return False
        def iterdir(self): return [MemoryPath('calls.jsonl')] if self.name.endswith('native_v1') else []
        def is_file(self): return True
        @property
        def suffix(self): return Path(self.name).suffix
    class MemoryEvidence:
        def __init__(self, names): self.names, self.read_names = set(names), set()
        def read(self, path, pin):
            if path.name not in self.names: raise FileNotFoundError(path.name)
            self.read_names.add(path.name)
    pin = 'a'*64
    names = META_ROOT | LAUNCH | {'EV_PROTOCOL_v1.md', 'method.py', 'evidence/source.json', 'native_v1/calls.jsonl'}
    freeze = dict(code={'method.py': pin}, evidence={'evidence/source.json': pin}, manifest_sha256=pin)
    audit = dict(input_materials_sha256={n: pin for n in names},
                 frozen_code_sha256=freeze['code'], frozen_evidence_sha256=freeze['evidence'])
    original_bounded = globals()['bounded']
    globals()['bounded'] = lambda base, name: MemoryPath(name)
    try:
        ram = MemoryEvidence(names)
        receipt_materials(ram, a, MemoryPath('prep'), MemoryPath('run'), audit, freeze, True)
        need(ram.read_names == names, 'every receipt metadata entry opened and bound')
        reject(receipt_materials, MemoryEvidence(names - {'LAUNCH.json'}), a,
               MemoryPath('prep'), MemoryPath('run'), audit, freeze, True)
        bad = deepcopy(audit); bad['input_materials_sha256']['native_v1/missing.json'] = pin
        reject(receipt_materials, MemoryEvidence(names), a, MemoryPath('prep'), MemoryPath('run'), bad, freeze, True)
        bad = deepcopy(audit); del bad['input_materials_sha256']['native_v1/calls.jsonl']
        reject(receipt_materials, MemoryEvidence(names), a, MemoryPath('prep'), MemoryPath('run'), bad, freeze, True)
        bad = deepcopy(audit); bad['frozen_code_sha256'] = {}
        reject(receipt_materials, MemoryEvidence(names), a, MemoryPath('prep'), MemoryPath('run'), bad, freeze, True)
    finally:
        globals()['bounded'] = original_bounded

    # Real publication entry point with in-memory gate failures. No actual path
    # existence probe/output mkdir, no package/result data opened by these calls.
    class FutureOutput:
        present = False
        def __eq__(self, other): return other == ROOT / 'ev_analysis_v1'
        def exists(self): return self.present
        def is_symlink(self): return False
        def mkdir(self, **kw): raise AssertionError('a rejected run attempted publication')
    original_gate = globals()['gate']
    try:
        for missing_round in (0, 1, 2):
            def missing(*args):
                if args[-1] == missing_round: raise FileNotFoundError('synthetic missing receipt')
                return {}
            globals()['gate'] = missing
            reject(run, FutureOutput(), ROOT / 'analysis_v1')
        existing = FutureOutput(); existing.present = True
        reject(run, existing, ROOT / 'analysis_v1')
    finally:
        globals()['gate'] = original_gate

    # A disclosed fallback counts as selection agreement but never valid ranking.
    diag_calls = []
    for i in range(2):
        evdiag = dict(fallback_used=i == 0, ranking_valid=i != 0, defined=i != 0,
            selected_channel=0, ev_selected_channel=None if i == 0 else 0,
            scores=[None]*8 if i == 0 else [1.0]*8)
        if i == 0: evdiag['status'] = 'undefined_score_fallback_ch0'
        for policy in POLICIES:
            diag_calls.append(dict(id=str(i), policy=policy, meeting='m', room_cluster='r',
                frontend=evdiag if policy == 'ev_sense' else dict(selected_channel=0, channel_rms=[0.0]*8)))
    diag_summary, diag_rows = selectors(a, diag_calls)
    need(diag_summary['fallback_sources'] == 1 and diag_summary['valid_ranking_sources'] == 1
         and diag_rows[0]['ev_gap'] is None and diag_rows[1]['ev_gap']['exact_top_tie'] is True,
         'real fallback and tied diagnostics, no fake RMS status')
    bad = deepcopy(diag_calls); del bad[0]['frontend']['status']
    reject(selectors, a, bad)
    split_sources = [dict(id=str(i), meeting='m', room_cluster='r', frames=n)
                     for i, n in enumerate((152000, 152160))]
    split_calls = [dict(id=s['id'], policy=p, asr={'first': {'parts':
        [dict(start_sample=0, end_sample=s['frames'])] if s['frames'] <= SPLIT_THRESHOLD else
        [dict(start_sample=0, end_sample=76000), dict(start_sample=76000, end_sample=s['frames'])]}})
        for s in split_sources for p in POLICIES]
    need([r['length_class'] for r in split_context(a, split_calls, split_sources)] == ['short', 'long'],
         'frozen split threshold boundary')
    artifact_count = synthetic_publication(a, t)
    return dict(status='synthetic_self_test_passed', rejected_invalid_cases=rejects, ram_only_artifacts=artifact_count, actual_results_opened=False, directories_created=False,
                scoring_helper_sha256=ANALYZER_SHA, repeated_cost_helper_sha256=TIMING_SHA)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--output', type=Path, default=ROOT / 'ev_analysis_v1')
    parser.add_argument('--primary-analysis', '--main-analysis', type=Path, default=ROOT / 'analysis_v1')
    args = parser.parse_args()
    a, _ = helpers()
    try:
        result = self_test() if args.self_test else run(args.output.absolute(), args.primary_analysis.absolute())
    except (ValueError, KeyError, FileNotFoundError, TypeError) as exc:
        print('REJECTED: ' + str(exc), file=sys.stderr)
        return 2
    print(a.json_text(result))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
