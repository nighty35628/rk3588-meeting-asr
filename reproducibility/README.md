# Numerical reproduction and evidence boundaries

Run from the repository root:

```sh
python3 -B reproducibility/reproduce.py --output reproduced/points
python3 -B reproducibility/reproduce.py --bootstrap --output reproduced
python3 -B scripts/audit_release.py --history
```

Only the second command needs NumPy. Install the tested dependencies from `requirements.txt` for statistics and plotting. Script inputs resolve relative to their own repository, so relocation and a different working directory are supported. `--output` may point to a new generated directory, never the repository root or its evidence/code subdirectories. A failure returns nonzero and records FAIL; stale table files are not successful evidence.

## Implementations and checks

Primary counts use Unicode NFKC, casefold and retention of Unicode alphabetic/digit characters; historical case-preserved sensitivity retains case. Unit-cost Levenshtein S/D/I counts are saved inputs, not rescored here. CER is exported in percent; stored original CER fields are fractions. Service/component values are seconds in input records, milliseconds in matched contrast/ledger CSVs.

A/F/C/EV scores retain source IDs, recording IDs, policy, normalization mode, reference character count and S/D/I counts. The standard-library runner validates the complete paired roster, positive denominator, nonnegative counts and `errors = substitutions + deletions + insertions`, then independently aggregates pooled and equal-recording CER and compares them with the historical per-policy files. A and F share exposed sources. F retains nine channel policies; its historical supplement analysis used inherited anchors as described in the original code. C's score rows cover 800 later test intervals across 20 recording files; 20 calibration prefixes appear separately in its coordinates. EV is the contemporary two-policy panel. The public command does not rerun their original confidence intervals, service measurements or native-call audits.

`analysis/formal_statistics.py` is copied byte-for-byte from the frozen S implementation. QUALITY and COST manifests preserve the exact source/recording/stratum roster and contrasts. Numeric row extraction removes hypotheses and keeps the inputs consumed by the implementation. The current command recomputes S point estimates and all saved contrast intervals and compares the design, bootstrap, methods, contrasts and boundaries with the extracted historical results. Cost diagnostic errors remain separate from primary quality. Per-policy actual calls are reported counters, not a physical audit.

`analysis/matched_measurement_v2/analyze.py` is the byte-identical original. The public entry calls its numeric `summarize` and `component_ledger` functions, using the original frozen policy module. It checks all 2,400 rows against the schedule, completed call counters and service/component closure, then compares **arms, effects, rounds, leave_one_date, mode_associated and components** with the six pre-existing CSVs. The 120-interval diagnostic score and bank-drift exports are supplied without hypotheses. Their text/action parity conclusions remain historical observations; they cannot be independently re-established from the numerical extract. The original analyzer's raw-product CLI needs excluded raw records and is not the public reproduction command.

## Outputs

`reproduced/VERIFICATION.json` contains the current status, environment, A/F/C/EV points and execution scope. `S_QUALITY.json`, `S_COST.json` and `matched_*.csv` are regenerated only with `--bootstrap`. Plotting uses those values and a successful receipt. It exports a source CSV, caption/alt-text metadata and PNG/SVG/PDF.

`EXPORT_MANIFEST.json` records source-relative paths, original SHA256/bytes, exact-copy, path-redacted-copy and allowlisted extraction operations, retained fields and exported SHA256/bytes. Excluded originals cannot be recovered or verified from a hash alone. No transcript is replaced or rewritten: originals remain in the separate research source, and the public files explicitly represent extracts.

`SHA256_MANIFEST.json` seals static candidate files. It is a self-consistency check, not a signed or externally timestamped attestation. Original `results/matched_measurement/SHA256.json` is retained and can be checked independently. Generated outputs, validation receipts and the manifest itself are outside that seal.

## Author-side export

Readers do not need either private source directory. The allowlisted export can be rebuilt by an authorized holder of the original materials:

```sh
python3 -B scripts/export_public_inputs.py --research-root /path/to/jaes_revision_v1_20261020 --model-root /path/to/asr_model_provenance_20261022 --output /path/to/this-checkout
```

This command refreshes the designated extract files. It does not copy arbitrary source directories or alter original evidence. After intentional edits only, the owner may refresh the public integrity manifest:

```sh
python3 -B scripts/audit_release.py --history --seal --output validation/sensitive_scan.json
```

Do not reseal merely to hide a failing verification. Publication and Git operations are separate owner actions.

## Not reproduced

No text normalization/Levenshtein rescoring from transcripts; no A/F/C/EV bootstrap replay; no complete historical table/TeX pipeline; no logits/native tensor audit; no inference or fresh latency measurement; no verified recreation of all model exports. Full audio-to-results reproduction is currently incomplete. The repository supports numerical reproduction from released scores and timings, with source extraction and original code identities available for review.
