"""Fixed-strata paired recording statistics: SEPARATE quality and cost cohorts.

API: analyze(manifest, rows, analysis_scope=None) -> JSON-compatible dict.
CLI: python3 -B formal_statistics.py --manifest FROZEN.json --rows SCORED.jsonl
Print only; no writes, NN, scoring, fitting, sample selection or success claims.
Run analyze separately with quality_manifest/quality_rows and cost_manifest/
cost_rows. No combined quality+cost estimator is produced. A cost subset's
paired errors are diagnostic, never extra observations for primary quality.

Shared manifest schema (additional provenance fields allowed):
{
 "schema": "FIXED_RECORDING_STATISTICS_MANIFEST_v1", "cohort_id": "quality_v1",
 "analysis_scope": "quality", "outcome_provenance": "bank_projection",
 "policies": ["candidate", "baseline"], "repeats": [0], "quality_round": 0,
 "recordings": [{"recording_id": "20200706_L_R001S08C01",
                 "date_prefix": "20200706", "filename_R": "R001"}, ...],
 "sources": [{"id": "20200706_L_R001S08C01_u0001",
              "recording_id": "20200706_L_R001S08C01", "n": 17}, ...],
 "contrasts": [{"candidate": "candidate", "comparator": "baseline"}, ...]
}
QUALITY: repeats MUST be [0] (one projected outcome per source/policy); repeat 0
is a bank projection index, not a real router repeat. quality_round: 0 or
quality_repeats: [0] may explicitly select it; never both. Each row requires:
 {"source_id": "..._u0001", "recording_id": "20200706_L_R001S08C01",
  "policy": "candidate", "repeat": 0, "n": 17, "errors": 2}.
service_s and actual_calls are FORBIDDEN in projection rows. Response-bank NN
counts must come from the bank's own audited receipts, not projected row counts.
Outputs: macro/pooled CER, paired differences and descriptive percentile CIs.

COST: use a separate manifest with analysis_scope: "cost", outcome_provenance:
"actual_policy_execution", cohort_id: "cost_v1", repeats: [1, 2], and its own
predeclared source subset. No quality_round/quality_repeats in this manifest.
Rows require the same IDs/repeat/n plus finite positive service_s. errors is
optional but all-or-none across the panel; if present it is reported separately
as diagnostic_actual_quality (point estimates only, averaged over planned
repeats). No CER fields enter the main cost methods/contrasts/CIs.
Optional cost row actual_calls: {"SV_native": 2, "teacher_SDK": 1} must be
all-or-none, with identical key sets and nonnegative integer counts. These are
summed as REPORTED actual calls, not physically verified here. No inference of
NN counts from cell counts, and full-Q rows need not pay any first-SV cost.
repeats can also be a complete policy -> list[positive int] mapping for an
explicitly planned asymmetric repeat schedule; every source must follow it.

In both cohorts: the EXACT frozen source x policy x repeat roster is mandatory.
Reject duplicates, missing/unknown/failed cells, bool or invalid n/errors, and
nonfinite/nonpositive service. n is a fixed positive reference-character count
in the manifest, equal across arms/repeats. Nonnegative integer errors may
exceed n (insertions). Unequal source counts/recording are allowed as frozen,
not via missing cells. Cost averages repeats WITHIN source first, then sources
within recording; quality sums edits/reference characters WITHIN recording.
All primary summaries weight recordings equally. Complete dated recording IDs
and matching date_prefix/filename_R are required; speaker labels are not people.

Bootstrap is fixed: seed 2026101622, 10000 draws. Within each date x filename-R
stratum resample its original number of COMPLETE PAIRED recordings, retaining
frozen n_h/N stratum weights and one common draw for all arms. Pooled CER uses
resampled edit/reference totals. CIs are descriptive 95%, conditional on observed
strata and within-stratum recording exchangeability, not new-room inference.
Singleton strata have no resampling variance and are disclosed. Per date x R,
date and R summaries and leave-one-group/date/R sensitivities are POINT ONLY;
deletions use equal remaining-recording weights. Never bootstrap two R groups.

Caller freezes manifest, bank/router rules, SRS cost-subset selection, reference
normalization and scored row/receipt bindings BEFORE analyzing. This module
cannot verify physical independence, bank attribution, SRS, drift or actual
execution; it does not create a contribution PASS, noninferiority margin or N.
"""
import argparse
from collections import defaultdict
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path
import re
import sys

import numpy as np

SEED = 2026101622
BOOTSTRAPS = 10000
SCHEMA = 'FIXED_RECORDING_STATISTICS_MANIFEST_v1'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def parse(text):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON key: ' + key)
            result[key] = value
        return result
    def constant(value):
        raise ValueError('nonfinite JSON: ' + value)
    return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)


def name(value, label):
    require(isinstance(value, str) and value.strip() == value and bool(value), label)
    return value


def positive_int(value, label):
    require(type(value) is int and value > 0, label)
    return value


def repeat_list(value, label, zero=False):
    require(isinstance(value, list) and bool(value), label)
    for item in value:
        require(type(item) is int and item >= (0 if zero else 1), label)
    require(len(set(value)) == len(value), label + ': duplicate round')
    return sorted(value)


def validate(manifest, rows, analysis_scope=None):
    require(isinstance(manifest, dict) and manifest.get('schema') == SCHEMA, 'manifest schema')
    scope = manifest['analysis_scope']
    require(scope in ('quality', 'cost'), 'analysis_scope must be quality or cost')
    require(analysis_scope is None or analysis_scope == scope, 'analysis_scope contradicts manifest')
    name(manifest['cohort_id'], 'cohort_id required')
    require(manifest['outcome_provenance'] == ('bank_projection' if scope == 'quality' else 'actual_policy_execution'),
            'cohort outcome provenance')
    policies = manifest['policies']
    require(isinstance(policies, list) and policies, 'policies required')
    for policy in policies:
        name(policy, 'policy name')
    require(len(set(policies)) == len(policies), 'duplicate policy')
    repeats = manifest['repeats']
    if isinstance(repeats, list):
        repeats = {policy: repeat_list(repeats, 'planned repeats', scope == 'quality') for policy in policies}
    else:
        require(isinstance(repeats, dict) and set(repeats) == set(policies), 'complete per-policy repeat plan')
        repeats = {policy: repeat_list(repeats[policy], 'planned repeats: ' + policy, scope == 'quality') for policy in policies}
    if scope == 'quality':
        require(not ('quality_round' in manifest and 'quality_repeats' in manifest), 'ambiguous quality selector')
        quality = (repeat_list([manifest['quality_round']], 'quality_round', True) if 'quality_round' in manifest
                   else repeat_list(manifest.get('quality_repeats', [0]), 'quality_repeats', True))
        require(quality == [0] and all(repeats[p] == [0] for p in policies), 'bank projection must have exactly repeat 0')
    else:
        require('quality_round' not in manifest and 'quality_repeats' not in manifest,
                'cost cohort cannot choose primary quality rounds')

    recordings = {}
    require(isinstance(manifest['recordings'], list) and manifest['recordings'], 'recordings required')
    for rec in manifest['recordings']:
        rid = name(rec['recording_id'], 'full dated recording ID')
        date = name(rec['date_prefix'], 'date_prefix')
        room = name(rec['filename_R'], 'filename_R')
        require(re.fullmatch(r'\d{8}', date) is not None, 'date_prefix format')
        datetime.strptime(date, '%Y%m%d')
        match = re.fullmatch(r'(\d{8})_(?:[A-Za-z0-9]+_)?(R\d{3})S\d+C\d+', rid)
        require(match is not None and match[1] == date and match[2] == room,
                'recording ID must preserve full date and match filename R')
        require(rid not in recordings, 'duplicate recording ID')
        recordings[rid] = dict(recording_id=rid, date_prefix=date, filename_R=room)
    sources = {}; populated = set()
    require(isinstance(manifest['sources'], list) and manifest['sources'], 'sources required')
    for source in manifest['sources']:
        sid = name(source['id'], 'source ID'); rid = source['recording_id']
        require(sid not in sources, 'duplicate source ID')
        require(rid in recordings, 'source references unknown recording')
        n = positive_int(source['n'], 'frozen reference n must be a positive integer')
        sources[sid] = dict(id=sid, recording_id=rid, n=n); populated.add(rid)
    require(populated == set(recordings), 'empty recording in frozen roster')

    contrasts = manifest['contrasts']; seen = set()
    require(isinstance(contrasts, list) and contrasts, 'predeclared contrasts required')
    for contrast in contrasts:
        a, b = contrast['candidate'], contrast['comparator']
        require(a in policies and b in policies and a != b, 'invalid contrast policies')
        require((a, b) not in seen, 'duplicate contrast'); seen.add((a, b))

    expected = {(sid, p, rep) for sid in sources for p in policies for rep in repeats[p]}
    observed = {}
    for row in rows:
        require(isinstance(row, dict), 'cell must be an object')
        sid = row['source_id']; policy = row['policy']; rep = row['repeat']
        require(sid in sources and policy in policies, 'unknown cell source/policy')
        require(type(rep) is int and rep >= (0 if scope == 'quality' else 1), 'invalid cell repeat')
        key = (sid, policy, rep)
        require(key in expected, 'unplanned cell repeat')
        require(key not in observed, 'duplicate cell; repeats/cells are not new recordings')
        require(row['recording_id'] == sources[sid]['recording_id'], 'cell recording differs from frozen source')
        require(type(row['n']) is int and row['n'] == sources[sid]['n'], 'cell n differs from frozen reference')
        if scope == 'quality' or 'errors' in row:
            require(type(row['errors']) is int and row['errors'] >= 0, 'invalid edit count')
        if scope == 'quality':
            require('service_s' not in row and 'actual_calls' not in row, 'bank projection cannot supply fake service/call counts')
        else:
            service = row['service_s']
            require(type(service) in (int, float) and math.isfinite(service) and service > 0,
                    'service_s must be finite and positive')
            if 'actual_calls' in row:
                require(isinstance(row['actual_calls'], dict) and row['actual_calls'], 'actual_calls must be a nonempty object')
                for counter_name, value in row['actual_calls'].items():
                    name(counter_name, 'actual call type')
                    require(type(value) is int and value >= 0, 'invalid actual call count')
        require(row.get('status', 'ok') == 'ok', 'failed cell cannot enter complete-case inference')
        observed[key] = row
    require(set(observed) == expected, 'missing planned cells / unbalanced paired panel')
    require(len({'errors' in r for r in observed.values()}) == 1, 'partially missing diagnostic errors')
    require(len({'actual_calls' in r for r in observed.values()}) == 1, 'partially missing actual call counts')
    if any('actual_calls' in r for r in observed.values()):
        keys = [set(r['actual_calls']) for r in observed.values()]
        require(all(k == keys[0] for k in keys), 'unbalanced actual call counter keys')
    return policies, repeats, recordings, sources, contrasts, observed


def _summaries(denominators, errors, service, policies, contrasts):
    """Point estimates over complete recordings, including deletion subsets."""
    require(len(denominators) > 0, 'empty summary')
    methods = []
    for j, policy in enumerate(policies):
        method = dict(policy=policy)
        if errors is not None:
            method.update(macro_CER_pct=float(np.mean(100 * errors[:, j] / denominators)),
                          pooled_CER_pct=float(100 * errors[:, j].sum() / denominators.sum()))
        if service is not None:
            method['mean_service_s'] = float(service[:, j].mean())
        methods.append(method)
    by = {m['policy']: m for m in methods}; effects = []
    for contrast in contrasts:
        a, b = by[contrast['candidate']], by[contrast['comparator']]
        effect = dict(candidate=a['policy'], comparator=b['policy'])
        if errors is not None:
            effect.update(macro_CER_difference_pp=a['macro_CER_pct'] - b['macro_CER_pct'],
                          pooled_CER_difference_pp=a['pooled_CER_pct'] - b['pooled_CER_pct'])
        if service is not None:
            ratio = a['mean_service_s'] / b['mean_service_s']
            effect.update(mean_service_difference_s=a['mean_service_s'] - b['mean_service_s'],
                          service_ratio=ratio, relative_service_change_pct=100 * (ratio - 1),
                          service_saving_pct=100 * (1 - ratio))
        effects.append(effect)
    return methods, effects


def _bootstrap_weights(recordings):
    """Canonical ordering makes the fixed-seed result invariant to row order."""
    groups = defaultdict(list)
    for i, rec in enumerate(recordings):
        groups[rec['date_prefix'], rec['filename_R']].append(i)
    rng = np.random.default_rng(SEED)
    weights = np.zeros((BOOTSTRAPS, len(recordings)), dtype=np.int64)
    strata = []
    for (date, room), indices in sorted(groups.items()):
        size = len(indices)
        weights[:, indices] = rng.multinomial(size, np.full(size, 1 / size), size=BOOTSTRAPS)
        strata.append(dict(date_prefix=date, filename_R=room, recording_N=size,
                           fixed_weight=size / len(recordings), singleton=size == 1))
    return weights, strata


def analyze(manifest, rows, analysis_scope=None):
    policies, repeats, recordings, sources, contrasts, cells = validate(manifest, rows, analysis_scope)
    scope = manifest['analysis_scope']; has_errors = 'errors' in next(iter(cells.values()))
    recs = [recordings[rid] for rid in sorted(recordings)]
    per_source = []
    for sid, source in sorted(sources.items()):
        for policy in policies:
            entry = dict(source_id=sid, recording_id=source['recording_id'], policy=policy, n=source['n'])
            if has_errors:
                key = 'errors_quality_mean' if scope == 'quality' else 'diagnostic_errors_repeat_mean'
                entry[key] = float(np.mean([cells[sid, policy, rep]['errors'] for rep in repeats[policy]]))
            if scope == 'cost':
                entry['service_repeat_mean_s'] = float(np.mean([cells[sid, policy, rep]['service_s'] for rep in repeats[policy]]))
            per_source.append(entry)
    grouped = defaultdict(list)
    for source in per_source:
        grouped[source['recording_id'], source['policy']].append(source)
    per_recording = []; denominators = []; errors = []; service = []
    for rec in recs:
        err, seconds = [], []
        n = sum(s['n'] for s in sources.values() if s['recording_id'] == rec['recording_id'])
        denominators.append(n)
        for policy in policies:
            entries = grouped[rec['recording_id'], policy]
            entry = dict(**rec, policy=policy, source_N=len(entries), n=n)
            if has_errors:
                key = 'errors_quality_mean' if scope == 'quality' else 'diagnostic_errors_repeat_mean'
                e = sum(x[key] for x in entries); err.append(e)
                entry[key] = e
                entry['CER_pct' if scope == 'quality' else 'diagnostic_CER_pct'] = 100 * e / n
            if scope == 'cost':
                t = float(np.mean([x['service_repeat_mean_s'] for x in entries])); seconds.append(t)
                entry['service_mean_s'] = t
            per_recording.append(entry)
        errors.append(err); service.append(seconds)
    den = np.asarray(denominators, dtype=np.float64)
    all_err = np.asarray(errors, dtype=np.float64) if has_errors else None
    err = all_err if scope == 'quality' else None
    svc = np.asarray(service, dtype=np.float64) if scope == 'cost' else None
    require(np.isfinite(den).all() and (all_err is None or np.isfinite(all_err).all())
            and (svc is None or (np.isfinite(svc).all() and (svc > 0).all())), 'nonfinite aggregated inputs')
    methods, effects = _summaries(den, err, svc, policies, contrasts)
    weights, strata = _bootstrap_weights(recs)
    if scope == 'quality':
        macro_draws = weights @ (100 * err / den[:, None]) / len(recs)
        pooled_draws = 100 * (weights @ err) / (weights @ den)[:, None]
    else:
        service_draws = weights @ svc / len(recs)
    for effect in effects:
        a, b = policies.index(effect['candidate']), policies.index(effect['comparator'])
        if scope == 'quality':
            draws = dict(macro_CER_difference_pp=macro_draws[:, a] - macro_draws[:, b],
                         pooled_CER_difference_pp=pooled_draws[:, a] - pooled_draws[:, b])
        else:
            ratio = service_draws[:, a] / service_draws[:, b]
            draws = dict(mean_service_difference_s=service_draws[:, a] - service_draws[:, b],
                         service_ratio=ratio, relative_service_change_pct=100 * (ratio - 1),
                         service_saving_pct=100 * (1 - ratio))
        effect['descriptive95'] = {key: np.quantile(value, [.025, .975]).tolist() for key, value in draws.items()}

    per_group = {}; leave_one_out = {}
    for label, fields in (('date_R', ('date_prefix', 'filename_R')), ('date', ('date_prefix',)), ('R', ('filename_R',))):
        groups = defaultdict(list)
        for i, rec in enumerate(recs):
            groups[tuple(rec[f] for f in fields)].append(i)
        per_group[label] = []; leave_one_out[label] = []
        for key, indices in sorted(groups.items()):
            group = dict(zip(fields, key)); subset = np.asarray(indices)
            m, e = _summaries(den[subset], None if err is None else err[subset],
                              None if svc is None else svc[subset], policies, contrasts)
            group_ids = {recs[i]['recording_id'] for i in indices}
            source_count = sum(s['recording_id'] in group_ids for s in sources.values())
            per_group[label].append(dict(group=group, recording_N=len(indices), source_N=source_count,
                reference_characters=int(den[subset].sum()), methods=m, contrasts=e))
            remaining = np.asarray([i for i in range(len(recs)) if i not in indices], dtype=int)
            if len(remaining):
                m, e = _summaries(den[remaining], None if err is None else err[remaining],
                                  None if svc is None else svc[remaining], policies, contrasts)
                leave_one_out[label].append(dict(dropped=group, recording_N=len(remaining),
                    estimable=True, weighting='equal remaining recordings', methods=m, contrasts=e))
            else:
                leave_one_out[label].append(dict(dropped=group, recording_N=0, estimable=False,
                    reason='deletion leaves no recordings', methods=[], contrasts=[]))
    reported_calls = None
    if 'actual_calls' in next(iter(cells.values())):
        reported_calls = {policy: {key: sum(row['actual_calls'][key] for row in cells.values() if row['policy'] == policy)
                                   for key in next(iter(cells.values()))['actual_calls']} for policy in policies}
    result = dict(schema='FIXED_STRATA_PAIRED_RECORDING_STATISTICS_v1',
        cohort_id=manifest['cohort_id'], analysis_scope=scope, outcome_provenance=manifest['outcome_provenance'],
        design=dict(source_N=len(sources), recording_N=len(recs), analysis_rows_N=len(cells),
                    primary_quality_source_N=len(sources) if scope == 'quality' else 0,
                    primary_quality_recording_N=len(recs) if scope == 'quality' else 0,
                    bank_projection_rows_N=len(cells) if scope == 'quality' else 0,
                    actual_policy_execution_rows_N=len(cells) if scope == 'cost' else 0,
                    reported_actual_call_counts_by_policy=reported_calls,
                    actual_call_counts_physically_verified_here=False,
                    bank_actual_calls_inferable_from_projection_rows=False,
                    policies=policies, planned_repeats=repeats,
                    quality_repeats=[0] if scope == 'quality' else None,
                    reference_characters=sum(s['n'] for s in sources.values()), strata=strata,
                    singleton_strata=sum(s['singleton'] for s in strata),
                    all_strata_singleton=all(s['singleton'] for s in strata),
                    physical_meeting_or_participant_independence_verified=False),
        bootstrap=dict(seed=SEED, replicates=BOOTSTRAPS, confidence=.95,
                       unit='complete paired recording within fixed date x filename-R strata',
                       strata_weights='frozen recording counts n_h / N',
                       scope='descriptive, conditional on observed strata and within-stratum recording exchangeability'),
        methods=methods, contrasts=effects, per_source=per_source, per_recording=per_recording,
        per_group=per_group, leave_one_out=leave_one_out,
        boundaries=dict(group_sensitivity='point estimates only; no date/R population bootstrap',
                        cohorts_combined=False, repetitions_are_independent_quality_N=False,
                        speakerlabels_are_participant_IDs=False, NN_calls_added=0,
                        noninferiority_margin=None, primary_claim=None, success_decision=None,
                        singleton_warning='singleton strata contribute no resampling variance; zero-width CIs do not establish safety or equivalence',
                        upstream_audit='bank attribution, actual execution, SRS cost-subset membership and per-source bank/route drift are caller-verified'))
    if scope == 'cost' and has_errors:
        m, e = _summaries(den, all_err, None, policies, contrasts)
        result['diagnostic_actual_quality'] = dict(scope='cost subset only; point estimates, not primary quality; planned-repeat means',
                                                  methods=m, contrasts=e)
    json.dumps(result, allow_nan=False)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--rows', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        manifest_bytes, row_bytes = args.manifest.read_bytes(), args.rows.read_bytes()
        manifest = parse(manifest_bytes)
        rows = [parse(line) for line in row_bytes.splitlines() if line.strip()]
        result = analyze(manifest, rows)
        result['input_sha256'] = dict(manifest=hashlib.sha256(manifest_bytes).hexdigest(),
                                      per_cell_rows=hashlib.sha256(row_bytes).hexdigest())
        result['code_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        print(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False))
        return 0
    except (ValueError, KeyError, TypeError, OSError, OverflowError) as exc:
        print(json.dumps(dict(status='invalid_inputs', error=type(exc).__name__, message=str(exc)), ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
