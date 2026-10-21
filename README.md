# RK3588 Meeting ASR

Research companion for **Microphone Selection and Recognizer Cascading for Embedded Meeting Transcription: An RK3588 Study**.

**Author:** OUYANG Tiancheng
**Contact:** nighty@nightytech.com
**ORCID:** https://orcid.org/0009-0002-0335-7147
**Repository:** https://github.com/nighty35628/rk3588-meeting-asr

This public research companion provides numerical reproduction from released scores and timings. Hardware reruns require the separately obtained assets described below. No DOI, journal acceptance or external submission is asserted.

## Run the offline reproduction

From the repository root, Python 3.9+ can check file integrity and recompute A/F/C/EV numeric CER summaries using only its standard library:

```sh
python3 -B reproducibility/reproduce.py
```

For the S quality/cost bootstrap and the completed matched measurement comparison:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -B reproducibility/reproduce.py --bootstrap
MPLCONFIGDIR="$PWD/reproduced/mplconfig" .venv/bin/python -B analysis/plot_numeric.py --input reproduced --output reproduced/figures
python3 -B scripts/audit_release.py --history
```

The tested environment is Python 3.14.7, NumPy 2.5.2 and Matplotlib 3.11.2. The pins describe offline analysis dependencies, not the historical conversion environment. Installation needs package access; reproduction and plotting then run without network, audio, models, SDKs or the original workspace. Successful runs write `reproduced/VERIFICATION.json`; inspect its current status before using any generated output. Re-running overwrites generated outputs, never the distributed inputs.

## What can be reproduced

| Layer | Included and executable | Boundary |
|---|---|---|
| Integrity and numerical scores | A/F/C/EV: per-sample edit counts, pooled and equal-recording CER, both saved normalization modes | Stored counts are inputs; references/hypotheses are excluded, so no independent text rescoring |
| S quality and cost | Unchanged frozen statistics code; 6,000 bank-projected quality rows / 600 intervals / 30 recording files; separate 2,400 actual cost rows / 120 intervals | Fixed date × filename-R recording bootstrap, 10,000 draws, seed 2026101622; projection rows are not actual router runs |
| Matched service comparison | 2,400 numerical execution records, four blocks, five policies, 120 intervals, two modes × two rounds; means, intervals, component ledger, round and leave-date sensitivities | Compared against all six original aggregate CSVs; 1,200 paired executions are not new quality samples |
| Figures | Numeric effect plots in PNG/SVG/PDF and source values | New rendering of recomputed values, not a pixel-identical rebuild of every manuscript figure |
| Device execution | Frozen historical runners, policy/confidence/RF code and configuration | Published for inspection; guarded runtime, SDK, model and input dependencies remain incomplete; no portable device run claimed |
| Model conversion | Recovered Qwen decoder script/configuration and a parameterized command; ten asset hash records including the six Qwen files | Qwen encoder export/build and original checkpoint revision incomplete; SenseVoice conversion chain not recovered |

The S intervals are descriptive and conditional on the observed strata; singleton strata have no resampling variance. The matched mode contrast contains time-block and OS-cache confounding and does not isolate instrumentation overhead. Neither repeated executions nor filename speaker labels establish independent meetings or participants.

## File map

- `data/scores/`, `data/cohorts/`: numerical scores and text-free corpus coordinates.
- `data/S/`, `data/matched/`, `data/expected/`: frozen rosters, counts, timings, comparison targets and drift summaries.
- `analysis/`: executable statistics and plotting; `analysis/historical/` retains original A/F/C/EV analysis code for inspection only.
- `hardware/`: historical board runners and frozen causal routing, confidence and RF implementation.
- `conversion/`: recovered decoder material, precise model identities and remaining conversion gaps.
- `results/matched_measurement/`: the six existing aggregate CSVs and original SHA256 record, retained unchanged.
- `reproducibility/`: commands, extraction provenance and static integrity manifest.
- `validation/`: local validation receipts. These do not certify hardware reproduction or rights clearance.

See [reproduction details](reproducibility/README.md), [data/access](docs/DATA_AND_ACCESS.md), [model provenance](conversion/README.md), [hardware limits](hardware/README.md), and [third-party notices](docs/THIRD_PARTY_NOTICES.md).

Audio, transcription text, neural weights, SDK binaries, private execution logs, credentials and board-maintenance scripts are excluded. qzxyz source without an established license is not redistributed. There is no blanket open-source license: see [rights status](LICENSE.md).
