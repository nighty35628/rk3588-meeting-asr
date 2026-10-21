"""Inspect the Git release candidate, optionally seal static hashes. No network.

Scans tracked and untracked nonignored files, excluding .git and local test files.
Heuristics do not certify rights clearance or detect every possible secret.
"""
import argparse
import csv
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import subprocess

ROOT=Path(__file__).resolve().parents[1]
FORBIDDEN_KEYS={'reference','raw_reference','hypothesis','raw_text','normalized_text','normalized_reference','normalized_hypothesis','password','passwd','access_token','api_key','private_key'}
BLOCKED_EXT={'.wav','.flac','.mp3','.m4a','.rknn','.rkllm','.onnx','.safetensors','.npy','.npz','.so','.dylib','.whl','.zip','.bin','.pem','.key','.log','.pyc'}


def candidates():
    raw=subprocess.check_output(['git','-C',str(ROOT),'ls-files','-z','--cached','--others','--exclude-standard'])
    return sorted({v.decode() for v in raw.split(b'\0') if v})


def walk(obj):
    if isinstance(obj,dict):
        for k,v in obj.items():
            if k.lower() in FORBIDDEN_KEYS:raise ValueError('forbidden payload key: '+k)
            walk(v)
    elif isinstance(obj,list):
        for v in obj:walk(v)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--seal',action='store_true',help='author-only refresh after intentional edits; never repair evidence to pass')
    ap.add_argument('--output',type=Path)
    ap.add_argument('--history',action='store_true',help='also inspect every reachable Git blob, without changing Git state')
    a=ap.parse_args();issues=[];files={}
    for name in candidates():
        p=ROOT/name
        if not p.is_file() or p.is_symlink():issues.append(dict(file=name,reason='missing/nonregular/symlink'));continue
        if p.suffix.lower() in BLOCKED_EXT or p.name.startswith('.env'):issues.append(dict(file=name,reason='excluded payload extension'))
        b=p.read_bytes()
        if len(b)>10_000_000:issues.append(dict(file=name,reason='unexpectedly large individual file'))
        try:text=b.decode('utf-8')
        except UnicodeDecodeError:issues.append(dict(file=name,reason='binary file'));continue
        patterns=[r'-----BEGIN [A-Z ]*PRIVATE KEY-----',r'gh[pousr]_[A-Za-z0-9]{25,}',r'github_pat_[A-Za-z0-9_]{20,}',r'AKIA[A-Z0-9]{16}',r'sk-[A-Za-z0-9]{24,}',r'(?i)https?://[^\s/@:]+:[^\s/@]+@',r'(?i)(?:password|passwd|api_key|access_token)\s*[:=]\s*["\x27][^"\x27\s]{6,}["\x27]']
        for pattern in patterns:
            if re.search(pattern,text):issues.append(dict(file=name,reason='credential pattern; inspect locally'))
        for value in re.findall(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])',text):
            try:ipaddress.ip_address(value)
            except ValueError:continue
            issues.append(dict(file=name,reason='IPv4-like string requires review'));break
        if name.startswith('data/'):
            try:
                if p.suffix=='.json':walk(json.loads(text))
                elif p.suffix=='.jsonl':
                    for line in text.splitlines():walk(json.loads(line))
                elif p.suffix=='.csv':
                    for row in csv.DictReader(text.splitlines()):walk(row)
            except (ValueError,TypeError) as exc:issues.append(dict(file=name,reason=str(exc)))
        if name!='reproducibility/SHA256_MANIFEST.json' and not name.startswith('validation/'):
            files[name]=dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
    history=None
    if a.history:
        history=dict(commits=int(subprocess.check_output(['git','-C',str(ROOT),'rev-list','--count','--all'])),blobs=0,tracked_files=len(subprocess.check_output(['git','-C',str(ROOT),'ls-files','-z']).split(b'\0'))-1)
        objects=subprocess.check_output(['git','-C',str(ROOT),'rev-list','--objects','--all']).decode().splitlines()
        for item in objects:
            oid,_,name=item.partition(' ')
            kind=subprocess.check_output(['git','-C',str(ROOT),'cat-file','-t',oid]).strip()
            if kind!=b'blob':continue
            history['blobs']+=1
            b=subprocess.check_output(['git','-C',str(ROOT),'cat-file','blob',oid])
            try:t=b.decode('utf-8')
            except UnicodeDecodeError:issues.append(dict(file=name,reason='binary Git-history blob'));continue
            if Path(name).suffix.lower() in BLOCKED_EXT:issues.append(dict(file=name,reason='excluded payload in Git history'))
            for pattern in patterns:
                if re.search(pattern,t):issues.append(dict(file=name,reason='credential pattern in Git history'))
            for value in re.findall(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])',t):
                try:ipaddress.ip_address(value)
                except ValueError:continue
                issues.append(dict(file=name,reason='IPv4-like string in Git history'));break
            if re.search(r'(?i)["\x27](?:reference|hypothesis|raw_text|normalized_reference)["\x27]\s*:',t):
                issues.append(dict(file=name,reason='possible transcript payload in Git history'))
    report=dict(status='PASS' if not issues else 'FAIL',candidate_files=len(candidates()),git_history=history,
                candidate_bytes=sum((ROOT/n).stat().st_size for n in candidates() if (ROOT/n).is_file()),issues=issues,
                scope='working-tree candidate and, with --history, all reachable Git blobs; heuristic scan, not legal clearance',
                excluded='ignored .venv, .local-build and reproduced directories; .git is never distributed by this inventory')
    if a.seal:
        if issues:raise SystemExit(json.dumps(report,indent=2))
        (ROOT/'reproducibility/SHA256_MANIFEST.json').write_text(json.dumps(dict(schema='PUBLIC_STATIC_INTEGRITY_v1',files=files),indent=2)+'\n')
    if a.output:
        output=a.output.resolve()
        if not output.is_relative_to(ROOT) or output==ROOT:raise SystemExit('audit output must be within repository')
        output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2));return 0 if not issues else 1


if __name__=='__main__':raise SystemExit(main())
