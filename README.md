# RK3588 Meeting ASR

Research companion for **Microphone Selection and Recognizer Cascading for Embedded Meeting Transcription: An RK3588 Study**.

**Author:** OUYANG Tiancheng — Independent Researcher  
**Contact:** nighty@nightytech.com  
**ORCID:** https://orcid.org/0009-0002-0335-7147

## Status

This private repository is being prepared for a future research release. It is not yet a public reproducibility deposit. Model conversion scripts will be added by the author. No journal acceptance or external submission is claimed.

## Included now

- `results/matched_measurement/`: copied aggregate CSVs from the completed audit/minimal comparison, with SHA-256 identities.
- `scripts/summarize_results.py`: prints the saved minimal-mode policy contrasts.
- `conversion/README.md`: checklist for the forthcoming conversion scripts and source-model information.
- `docs/DATA_AND_ACCESS.md`: dataset sources and preparation boundaries.

```sh
python3 scripts/summarize_results.py
```

The saved cost comparison uses 120 preselected intervals, five policies, two measurement modes and two rounds (2,400 actual requests). The 1,200 paired executions are not new independent quality samples. These aggregate CSVs alone do not reproduce inference or recompute the confidence intervals. Full per-sample inputs, evaluation code and release instructions will be integrated before public release.

## Publication preparation

The repository is private. A fixed release and access arrangements must be prepared before citing it as publicly available evidence. Converted model binaries, original audio, native SDK payloads, credentials and private device logs are not included.

## Rights

No blanket open-source license has been selected for this preparation repository. Third-party datasets, models and code retain their own terms. A code license and complete notices will be added before public release.
