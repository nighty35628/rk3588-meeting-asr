"""Author-side, allowlisted extraction; never copy transcripts or model payloads.

Requires the separately held research/provenance sources. Readers use reproduce.py.
Source hashes identify excluded evidence; they do not make it publicly accessible.
"""
import argparse
import csv
import gzip
import hashlib
import io
import json
from pathlib import Path
import re


def digest(b):
    return hashlib.sha256(b).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--research-root', type=Path, required=True)
    ap.add_argument('--model-root', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    src, models, out = a.research_root.resolve(), a.model_root.resolve(), a.output.resolve()
    assert src != out and not out.is_relative_to(src) and not src.is_relative_to(out)
    entries = []

    def read(name, model=False):
        return ((models if model else src)/name).read_bytes()

    def put(dest, data, source, operation, fields=None, model=False):
        raw = read(source, model)
        p = out/dest
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        entries.append(dict(path=dest, source_root='model_provenance' if model else 'research',
                            source=source, source_sha256=digest(raw), source_bytes=len(raw),
                            sha256=digest(data), bytes=len(data), operation=operation, fields=fields))

    def js(dest, obj, source, fields=None, model=False):
        put(dest, (json.dumps(obj, ensure_ascii=False, indent=2, allow_nan=False)+'\n').encode(),
            source, 'allowlisted_extraction', fields, model)

    def copy(dest, source, model=False):
        raw=read(source,model)
        if dest.endswith('.py'):
            clean=re.sub(rb'/(?:home|Users)/[^/\s\x27\"]+(?=/)',b'/path/to/local_host',raw)
            if clean!=raw:
                put(dest,clean,source,'path_redacted_copy',fields=['local home-account roots replaced by explicit /path/to placeholders; all other bytes retained'],model=model)
                return
        put(dest, raw, source, 'byte_identical_copy', model=model)

    def parse(name):
        return json.loads(read(name))

    def pick(row, keys):
        return {k: row[k] for k in keys if k in row}

    def csvbytes(rows):
        f = io.StringIO(newline='')
        w = csv.DictWriter(f, fieldnames=list(dict.fromkeys(k for r in rows for k in r)))
        w.writeheader(); w.writerows(rows)
        return f.getvalue().encode()

    data = 'reproducibility/data/'
    for cohort in ('A', 'EV', 'F', 'C'):
        source = data+cohort+('/SCORES.jsonl' if cohort in ('A','EV') else '/analysis/per_source.csv.gz')
        raw = read(source)
        rows = [json.loads(v) for v in raw.splitlines()] if cohort in ('A','EV') else list(csv.DictReader(io.StringIO(gzip.decompress(raw).decode())))
        keys = ['id','meeting','policy','mode','reference_characters','errors','substitutions','deletions','insertions']
        put(f'data/scores/{cohort}.csv', csvbytes([pick(r,keys) for r in rows]), source, 'allowlisted_extraction', keys)
        expected = data+cohort+'/analysis/per_policy.'+('csv' if cohort=='C' else 'json')
        copy(f'data/expected/{cohort}_per_policy.'+('csv' if cohort=='C' else 'json'), expected)

    for scope in ('QUALITY', 'COST'):
        source = data+f'S/analysis/{scope}_ROWS.jsonl'
        keys = ['source_id','recording_id','policy','repeat','n','errors','service_s','actual_calls','status',
                'outcome_provenance','execution_scope','actions','predicted_Q_calls','predicted_probe_calls',
                'predicted_first_SV_calls','predicted_SV_native_calls','first_empty','same_waveform','mixture_component']
        rows = [pick(json.loads(line), keys) for line in read(source).splitlines()]
        put(f'data/S/{scope}_ROWS.jsonl', b''.join((json.dumps(r,ensure_ascii=False,allow_nan=False)+'\n').encode() for r in rows), source, 'allowlisted_extraction', keys)
        # Manifest contains only numeric roster and statistical design, no text.
        copy(f'data/S/{scope}_MANIFEST.json', data+f'S/cohorts/{scope}_STATISTICS_MANIFEST.json')
        source = data+f'S/analysis/{scope}_STATISTICS.json'
        keys = ['schema','cohort_id','analysis_scope','outcome_provenance','design','bootstrap','methods','contrasts','boundaries']
        js(f'data/expected/S_{scope}.json',pick(parse(source),keys),source,keys)

    source = data+'A/SOURCE_COORDINATES.json'
    keys = ['id','meeting','tier_index','tier_interval_index','start_sample','end_sample','duration_s','input_channels','archive_sha256']
    coords = []
    for row in parse(source):
        r = pick(row,keys)
        for key in ('source_audio','source_textgrid'):
            r[key] = pick(row[key], ['archive_member','bytes','sha256','header'])
        coords.append(r)
    js('data/cohorts/AF_coordinates.json',coords,source,keys+['source_audio.{archive_member,bytes,sha256,header}','source_textgrid.{archive_member,bytes,sha256}'])
    source = data+'C/freeze/CLIPS_WITH_REFERENCES.jsonl'
    keys = ['id','meeting','tier_index','tier_interval_index','start_sample','end_sample','source_start_sample','source_end_sample',
            'frames','duration_s','channels','sample_rate','encoding','role','calibration_id','wav_sha256','pcm_sha256','original_flac_sha256','original_full_pcm_sha256']
    rows = [pick(json.loads(v),keys) for v in read(source).splitlines()]
    js('data/cohorts/C_coordinates.json',rows,source,keys)
    source = data+'S/source/DATA_REFERENCES.json'
    keys = ['id','recording_id','tier_index','tier_interval_index','start_sample','end_sample','frames','duration_s',
            'channels','sample_rate','encoding','normalized_reference_characters','quality_member','cost_member','quality_draw_position','cost_draw_position']
    rows = []
    for row in parse(source)['samples']:
        r=pick(row,keys)
        for key in ('source_flac','source_textgrid'):
            r[key]=pick(row[key],['member','bytes','sha256','frames','channels','sample_rate','encoding'])
        rows.append(r)
    js('data/cohorts/S_coordinates.json',rows,source,keys+['source_flac.{member,bytes,sha256,frames,channels,sample_rate,encoding}','source_textgrid.{member,bytes,sha256}'])

    base='raw_execution/matched_v5/measurement_pair_04_positive_idle/'
    selection=parse(base+'selection.json')
    keys=['cell_index','block_id','repeat','mode','source_id','recording_id','policy','status',
          'actual_SV_native_attempts','actual_SV_native_completed','actual_SDK_calls','actual_teacher_policy_calls',
          'frontend_s','first_s','first_confidence_s','probe_s','probe_frontend_s','teacher_s','routing_s',
          'service_s','service_minus_stage_sum_s']
    for block, attempt in selection.items():
        source=base+f'blocks/{block}/{attempt}/native_v1/calls.jsonl'
        rows=[pick(json.loads(v),keys) for v in read(source).splitlines()]
        put(f'data/matched/{block}.jsonl', b''.join((json.dumps(r,allow_nan=False)+'\n').encode() for r in rows),source,'allowlisted_extraction',keys)
    source=base+'SOURCE_MANIFEST.json'
    keys=['id','recording_id','date_prefix','filename_R','frames','sample_rate','channels','sha256','pcm_sha256']
    js('data/matched/roster.json', [pick(r,keys) for r in parse(source)['samples']],source,keys)
    copy('data/matched/schedule.json',base+'SCHEDULE.json')
    # Historical guard/maintenance files and full runtime logs deliberately excluded.
    for name in ('actual120_diagnostic_scores','historical_bank_drift'):
        source=f'analysis/matched_measurement_v2/actual_v5_01/{name}.csv'
        rows=list(csv.DictReader(io.StringIO(read(source).decode())))
        fields=[k for k in rows[0] if k!='hypothesis']
        put(f'data/matched/{name}.csv',csvbytes([pick(r,fields) for r in rows]),source,'allowlisted_extraction',fields)

    for n in ['analyze.py']:
        copy('analysis/matched_measurement_v2/'+n,'analysis/matched_measurement_v2/'+n)
    copy('analysis/formal_statistics.py','reproducibility/original_code/S/formal_statistics.py')
    for cohort,name in [('A','analyze_formal'),('EV','analyze_ev'),('F','analyze_fixed'),('C','analyze_calibration')]:
        source=f'reproducibility/original_code/{cohort if cohort!="EV" else "A"}/{name}.py'
        copy(f'analysis/historical/{name}.py',source)
    copy('hardware/historical/matched/run_native.py',base+'run_native.py')
    copy('hardware/historical/S/run_native.py','reproducibility/original_code/S/bank_01/run_native.py')
    for n in ['formal_policy_core.py','formal_execution_core.py','confidence_metrics_v1.py','rf_inference_v1.py']:
        copy('hardware/policy/'+n,'reproducibility/original_code/S/'+n)
    copy('work/measurement_core/formal_policy_core.py','work/measurement_core/formal_policy_core.py')
    for n,source in [('POLICY_PARAMETERS.json','S/bank_01/POLICY_PARAMETERS.json'),('CHEAP_RF.json','S/bank_01/CHEAP_RF.json'),('MIXTURE_ASSIGNMENTS.json','S/freeze/MIXTURE_ASSIGNMENTS.json')]:
        copy('hardware/config/'+n,data+source)

    mb='materials/nightytop/rkllm-toolchain/'
    copy('conversion/qwen/convert_decoder_rk3588_fp16.historical.py',mb+'rebuild/qwen3asr-0.6b-rk3588/scripts/convert_decoder_rk3588_fp16.py',True)
    for folder,label,names in [('models/Qwen3-ASR-0.6B/','upstream',['config.json','generation_config.json','preprocessor_config.json']),
                                ('rebuild/qwen3asr-0.6b-rk3588/decoder_hf_qwen3_clean/','decoder_clean',['config.json','generation_config.json'])]:
        for n in names:copy('conversion/qwen/'+label+'/'+n,mb+folder+n,True)
    copy('licenses/Apache-2.0.txt',mb+'venv/lib/python3.12/site-packages/transformers-4.55.2.dist-info/licenses/LICENSE',True)
    # Asset records omit local host/path and keep basename, observed bytes and hash.
    source='MODEL_PROVENANCE.json'; prov=json.loads(read(source,True));assets={}
    for model,detail in prov['models'].items():
        values=detail.get('deployed_assets',detail.get('deployed_asset_records'))
        assets[model]=values
    clean={}
    for model, values in assets.items():
        clean[model]=[dict(filename=Path(v['board_path']).name,bytes=v['bytes'],sha256=v['sha256'],
            hash_basis='recovered physical file matched historical record' if model.startswith('Qwen') else 'historical record only; physical file not recovered in provenance search',
            payload_in_this_repository=False) for v in values]
    js('conversion/MODEL_ASSETS.json',clean,source,['models.*.deployed_assets / deployed_asset_records: board_path basename, bytes, sha256; explicit observation basis; no payload'],True)
    (out/'reproducibility').mkdir(exist_ok=True)
    (out/'reproducibility/EXPORT_MANIFEST.json').write_text(json.dumps(dict(schema='PUBLIC_NUMERIC_EXPORT_v1',entries=entries,
        boundary='Excluded sources are hash-identified, not distributed; text rescoring and physical replay are not verified by these extractions.'),indent=2)+'\n')
    print(json.dumps(dict(exported_files=len(entries),bytes=sum(e['bytes'] for e in entries))))


if __name__=='__main__':
    main()
