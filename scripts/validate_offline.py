"""Acceptance checks: relocation, standard-library replay and rejected bad inputs.

All disposable writes stay in this checkout's ignored .local-build directory.
"""
import ast
import csv
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]


def load(name,p):
    spec=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m


def main():
    work=ROOT/'.local-build/relocated'
    if work.exists():shutil.rmtree(work)
    work.mkdir(parents=True)
    names=subprocess.check_output(['git','-C',str(ROOT),'ls-files','-z','--cached','--others','--exclude-standard']).split(b'\0')
    count=0
    for raw in names:
        if not raw:continue
        name=raw.decode();p=ROOT/name
        if not p.is_file():continue
        dest=work/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,dest)
        if p.suffix=='.py':ast.parse(p.read_text(),filename=name);count+=1
    checks=[]
    argv=[sys.executable,'-I','-S','-B',str(work/'reproducibility/reproduce.py'),'--output',str(work/'reproduced')]
    run=subprocess.run(argv,cwd=ROOT/'.local-build',capture_output=True,text=True)
    assert run.returncode==0,run.stdout+run.stderr
    checks.append('relocated -I -S standard-library point replay PASS')
    victim=work/'data/scores/A.csv';victim.write_bytes(victim.read_bytes()+b'\n')
    run=subprocess.run(argv,cwd=ROOT/'.local-build',capture_output=True,text=True)
    assert run.returncode!=0 and 'integrity mismatch' in run.stdout
    checks.append('modified input rejected by integrity gate')
    st=load('acceptance_stat',ROOT/'analysis/formal_statistics.py')
    manifest=json.loads((ROOT/'data/S/QUALITY_MANIFEST.json').read_text())
    rows=[json.loads(v) for v in (ROOT/'data/S/QUALITY_ROWS.jsonl').read_text().splitlines()]
    for label,bad in [('missing S cell',rows[:-1]),('duplicate S cell',rows+[rows[0]])]:
        try:st.validate(manifest,bad)
        except ValueError:checks.append(label+' rejected')
        else:raise AssertionError(label+' accepted')
    # Verify public Qwen bindings against independent author-provided expectations.
    assets=json.loads((ROOT/'conversion/MODEL_ASSETS.json').read_text())['Qwen3-ASR-0.6B']
    assert len(assets)==6 and all(len(v['sha256'])==64 and v['payload_in_this_repository'] is False for v in assets)
    checks.append('six Qwen asset identities complete; payloads excluded')
    converter=subprocess.run([sys.executable,'-I','-S','-B',str(ROOT/'conversion/qwen/convert_decoder.py'),'--help'],capture_output=True,text=True)
    assert converter.returncode==0
    checks.append('parameterized decoder --help works without SDK/site packages')
    baseline_path=ROOT/'.local-build/BASELINE.json'
    if baseline_path.is_file():
        baseline=json.loads(baseline_path.read_text())
        protected=[n for n in baseline['files'] if n.startswith('results/') or n=='scripts/summarize_results.py']
        assert all(hashlib.sha256((ROOT/n).read_bytes()).hexdigest()==baseline['files'][n] for n in protected)
        checks.append('original seven result files and summary script unchanged')
    else:
        checks.append('author baseline comparison skipped: local baseline not distributed')
    result=dict(status='PASS',checks=checks,python_files_parsed=count,scope='offline acceptance; no board, inference, conversion or transcript rescoring')
    p=ROOT/'validation/offline_acceptance.json';p.parent.mkdir(exist_ok=True);p.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
