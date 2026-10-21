# Third-party attribution and rights status

| Material | Evidence and scope | Distribution here |
|---|---|---|
| AliMeeting / AISHELL-4 | Existing research records identify CC BY-SA 4.0; distributor links and corpus citations in DATA_AND_ACCESS.md | Numeric derivatives and coordinates only; no audio or transcription text. Retain source attribution and applicable derivative-data terms |
| Qwen3-ASR-0.6B | Recovered original model card declares Apache-2.0; actual historical revision unknown. Qwen team / Alibaba Group; HuggingFace Inc. where named in upstream source headers | Recovered small configuration JSON; no weight/tokenizer/mel payloads or upstream model implementation |
| qzxyz/qwen3asr_rk | Recovered conversion/runtime reference, observed API revision documented in conversion/README.md; overall LICENSE/NOTICE not found | No unlicensed repository source copied. Reference links, hash identities and access limitations only |
| SenseVoice | Actual historical checkpoint/conversion license unknown; later reference statements cannot bind the old assets. Saved inference vendor author header names lovemefan | No vendor source, BPE, embedding or weights copied; original research runner imports remain visible |
| Rockchip RKNN / RKLLM | Historical tool/runtime versions supported by saved evidence; full historical SDK/toolkit license texts not recovered | No SDK, wheel, binary, header bundle or converted model redistribution; obtain from their publisher under its terms |
| Transformers Apache text | `licenses/Apache-2.0.txt` copied verbatim from recovered installed Transformers 4.55.2 license | Generic license reference only; **not** a recovered Qwen model-directory LICENSE or authorization over qzxyz/SenseVoice/toolkits |
| NumPy / Matplotlib and dependencies | Installed separately for optional analysis and plots; retain their own published terms | Version pins only; no vendored packages |

The decoder converter is an actual recovered local conversion driver, not a wholesale qzxyz export. Its parameters are retained and its source hash is recorded. Ownership/licensing of locally authored research scripts is not replaced by the license of imported packages. No copyright header has been removed from copied files. Copied code and configuration are listed in the extraction manifest; no blanket license is inferred from a model family name or a third-party reference.

This is an evidence and access notice, not a legal clearance opinion. Public visibility and open-source licensing are separate decisions. Unknown permissions remain unknown; recipients should not assume a grant over all files.
