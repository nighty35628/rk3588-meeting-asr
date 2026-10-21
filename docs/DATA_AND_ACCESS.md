# Data, acquisition and access

The recorded corpus sources are [AliMeeting, OpenSLR 119](https://www.openslr.org/119/) and [AISHELL-4, OpenSLR 111](https://www.openslr.org/111/). Existing research records identify both distributions as CC BY-SA 4.0; this release carries that attribution and does not claim a fresh online license audit. Obtain the original distributions and their license/readme files from those distributors. Do not treat this repository's rights notice as a grant over either corpus.

Attribution: AliMeeting — Yu et al., “M2MeT: The ICASSP 2022 Multi-Channel Multi-Party Meeting Transcription Challenge.” AISHELL-4 — Fu et al., “AISHELL-4: An Open Source Dataset for Speech Enhancement, Separation, Recognition and Speaker Diarization in Conference Scenario.” The linked distributor pages supply the full corpus references.

| Panel | Coordinates provided | Missing physical inputs |
|---|---|---|
| A/F and EV | `data/cohorts/AF_coordinates.json`: 600 AliMeeting Test intervals, exact archive members, TextGrid tier/interval, half-open sample bounds, source hashes and input header | Original `Test_Ali/Test_Ali_far/` audio and TextGrid; full annotation-selection pipeline |
| C | `data/cohorts/C_coordinates.json`: 820 AISHELL-4 interval records, calibration/test roles, exact sample bounds and clip/original hashes | Original corpus member mapping and acquisition archives are not fully reconstructed in this public extract; 800 later test intervals enter quality scores |
| S | `data/cohorts/S_coordinates.json`: 600 AISHELL-4 train_S intervals, exact FLAC/TextGrid members and hashes, 120 cost membership flags | Original corpus audio/TextGrid; physical clip materialization not rerun here |

Use stored half-open sample indices, channel ordering, 16 kHz and PCM16 scaling. C's original annotation-to-sample rule is Decimal16000 ROUND_HALF_UP; do not substitute a new float rounding rule. IDs and filename-R/date strata identify recording files, not proven independent participants or rooms. A/F share source exposure; S's response-bank predictions and actual cost subsets have different statistical roles.

No audio, reference/hypothesis text, NN tensor or model payload is distributed. Numeric scores and identifiers are derived research material. Any applicable corpus attribution/share-alike obligations remain with that material; rights to redistribute new excerpts must be established separately. Access to the omitted research records, annotations, historical model exports and SDKs is not automatically granted, promised or guaranteed by a hash record or the author's contact address.

Public numeric commands are self-contained. Acquisition, transcript rescoring, device execution and exact model rebuilding require additional authorized materials and may not be achievable from public sources alone. Contact OUYANG Tiancheng at nighty@nightytech.com for questions about evidence, without assuming that excluded artifacts can be supplied.
