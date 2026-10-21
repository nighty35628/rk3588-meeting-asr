"""Plot recomputed matched estimates; requires a successful bootstrap receipt."""
import argparse
import csv
import hashlib
import json
from pathlib import Path


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--input',type=Path,default=Path('reproduced'))
    ap.add_argument('--output',type=Path,default=Path('reproduced/figures'))
    a=ap.parse_args()
    report=json.loads((a.input/'VERIFICATION.json').read_text())
    if report['status']!='PASS' or not isinstance(report['bootstrap'],dict):raise SystemExit('successful --bootstrap reproduction required')
    # Exported values were compared to the preserved historical CSVs.
    source=a.input/'matched_effects.csv';raw=source.read_bytes()
    rows=list(csv.DictReader(raw.decode().splitlines()))
    choices=[('distinct_probe_confirmation-mean95','Distinct probe − Mean95'),
             ('distinct_probe_confirmation-cheap_sameview_skip','Distinct probe − Cheap skip'),
             ('mean95-full_qwen','Mean95 − Full Qwen')]
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    a.output.mkdir(parents=True,exist_ok=True)
    with plt.rc_context({'font.size':10,'svg.fonttype':'none','pdf.fonttype':42}):
        fig,axes=plt.subplots(1,2,figsize=(10.2,4.2),sharex=True,sharey=True,layout='constrained')
        for ax,mode,marker,color in zip(axes,['audit','minimal'],['o','s'],['#0072B2','#9A5500']):
            for y,(name,label) in enumerate(choices):
                hits=[r for r in rows if r['mode']==mode and r['sampler']=='fixed_date_R_recording' and r['metric']=='candidate_minus_comparator_ms' and r['contrast']==name]
                if len(hits)!=1:raise ValueError('missing/duplicate plot coordinate')
                r=hits[0];x,lo,hi=[float(r[k]) for k in ['estimate','ci95_low','ci95_high']]
                ax.errorbar(x,y,xerr=[[x-lo],[hi-x]],fmt=marker,color=color,capsize=4)
            ax.axvline(0,color='#555555',linewidth=.8,linestyle='--')
            ax.set(title=mode.capitalize(),xlabel='Candidate − comparator service (ms)',yticks=range(len(choices)),yticklabels=[x[1] for x in choices])
            ax.grid(axis='x',alpha=.2);ax.spines[['top','right']].set_visible(False)
        fig.suptitle('Matched policy service: descriptive 95% bootstrap intervals')
        fig.supxlabel('120 intervals / 30 recording files; two repeats per mode. Fixed date × filename-R strata.\nMode differences also contain time-block / OS-cache confounding.',fontsize=9)
        for ext in ['png','svg','pdf']:fig.savefig(a.output/f'matched_service.{ext}',dpi=300,facecolor='white')
        plt.close(fig)
    (a.output/'SOURCE.csv').write_bytes(raw)
    (a.output/'FIGURE.json').write_text(json.dumps(dict(source_sha256=hashlib.sha256(raw).hexdigest(),matplotlib=matplotlib.__version__,
        caption='Recording-paired, fixed-strata percentile intervals; 10,000 draws, seed 2026101622. Singleton strata have no resampling variance. Repetitions are not new quality samples.',
        alt_text='Two panels compare audit and minimal policy-service contrasts. Negative values indicate shorter candidate service. Exact estimates and intervals are in SOURCE.csv.'),indent=2)+'\n')


if __name__=='__main__':main()
