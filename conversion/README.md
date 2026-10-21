# Recovered model material and conversion gaps

## Qwen3-ASR 0.6B

The saved download/configuration evidence identifies [Qwen/Qwen3-ASR-0.6B](https://huggingface.co/Qwen/Qwen3-ASR-0.6B). **Original checkpoint revision: unknown.** The download used `main`; local tensor/file identity is not a repository commit.

The recovered conversion/runtime reference is [qzxyz/qwen3asr_rk](https://huggingface.co/qzxyz/qwen3asr_rk). A saved API receipt reports `800ff333bfef5033f765f11306e3f6258d519aae`. This is an observed reference revision, **not** a verified pin for all actual scripts or downloaded auxiliary files. The overall qzxyz repository license was not found. Its source is not copied here; obtain it from its original publisher subject to permission and applicable terms.

Included material:

- `qwen/convert_decoder_rk3588_fp16.historical.py`: recovered actual decoder conversion script, with local home-account roots replaced by explicit /path/to placeholders. All other bytes and settings are retained; original and public-copy hashes are recorded. Use the parameterized command below.
- `qwen/convert_decoder.py`: new path-parameterized command using the same recovered build settings. It is not an original shell-history record.
- `qwen/upstream/`: recovered model, generation and preprocessor JSON configuration.
- `qwen/decoder_clean/`: actual repacked decoder and generation configuration; Qwen3ForCausalLM, model_type=qwen3, rope_scaling=null. The repacked stored tensors were BF16; that does not make the compiled decoder BF16.
- `MODEL_ASSETS.json`: six Qwen asset identities and four SenseVoice historical identities, with byte sizes, full SHA256 and explicit observation basis. **No listed payload is included here.**

Recovered decoder settings: RKLLM Toolkit 1.2.3, `load_huggingface(device=cpu, dtype=float32)`; `do_quantization=False`, `optimization_level=1`, `target_platform=rk3588`, `num_npu_core=3`, `max_context=4096`. The historical model header reports FP16. No calibration dataset is passed by this decoder script. The recovered output name contained `clean_qwen3`; the deployed name omits it. Final deployed hash matches the saved record; the original rename command is unknown.

With an authorized, **already repacked** decoder checkpoint and separately obtained compatible toolkit, the convenience command is:

```sh
python3 conversion/qwen/convert_decoder.py --model /path/to/decoder_hf_qwen3_clean --output /path/to/new/decoder_hf.fp16.rk3588.rkllm
```

`--help` is SDK-free. Actual conversion was not run for this repository. This command does not repack the decoder, extract embeddings, export the encoder, or prove a bit-identical model rebuild.

## Six-file Qwen deployed binding

The exact bytes/hashes in `MODEL_ASSETS.json` match the source provenance record and the historical deployed bindings: frontend RKNN, backend RKNN, FP16 RKLLM decoder, external embedding NPY, mel filters NPY and tokenizer JSON. The provenance search matched all six to recovered physical files; this export only copies their descriptors. It does not hash omitted binaries anew.

The filename `frontend.fp16.onnx` does not describe its actual graph dtype: saved ONNX inspection found FLOAT inputs/outputs and all seven initializers. Backend ONNX is FLOAT with 294 FLOAT initializers. Saved graph metadata: PyTorch producer 2.6.0, opset 17, IR 8; frontend `[1,3000,128]`, backend `[1,390,896] -> [1,390,1024]`. RKNN build metadata identifies Toolkit2 2.3.2 and RK3588. Rebuild notes say no quantization; original encoder exporter/build drivers and logs are missing, so per-operator RKNN precision and complete settings remain unknown. The reference multi-shape converter defaults to RK3576 internally and is not evidence of the actual RK3588 command.

Also unknown: original checkpoint commit, actual conversion Git baseline/local diff, decoder repacking and embedding extraction commands, complete historical dependency lock and toolkit license texts. Current environment versions are not retroactively assigned to the historical converter. Historical Python minor was 3.12; exact conversion patch version is unknown. Runtime versions are separately recorded as Python 3.12.13, librknnrt/Toolkit Lite2 2.3.2, RKLLM runtime 1.2.3, driver 0.9.8.

## SenseVoice Small

The author confirms that the model family is original SenseVoice Small (October 22, 2026). This confirmation does not identify its exact checkpoint revision or conversion configuration.

Only historical asset hashes, inference code references and model-header metadata are recovered. **Actual checkpoint/revision, export and conversion code, commands, precision/quantization, calibration provenance, auxiliary-file generation, conversion Python/dependencies and license binding are unknown. No SenseVoice conversion chain has been restored.**

The saved model header reports RKNN Toolkit 2.3.3a25 and compiler 2.3.3b3; that is distinct from the board runtime 2.3.2. The four file hashes refer to encoder RKNN, am.mvn, BPE and embedding. The provenance search did not recover those four physical files on the conversion host; a separately saved historical BPE copy was matched, but is not distributed here. A later upstream MIT code statement is not proof of the historical weight license.

Model-card Apache-2.0 declarations and the generic Apache text do not establish permission for qzxyz code, unknown SenseVoice weights or SDKs. See [third-party notices](../docs/THIRD_PARTY_NOTICES.md).
