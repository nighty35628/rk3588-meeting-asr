#!/usr/bin/env python3
from pathlib import Path
from rkllm.api import RKLLM

model = Path("/path/to/local_host/rkllm-toolchain/rebuild/qwen3asr-0.6b-rk3588/decoder_hf_qwen3_clean")
out = Path("/path/to/local_host/rkllm-toolchain/rebuild/qwen3asr-0.6b-rk3588/package-clean/models/rkllm/decoder_hf.clean_qwen3.fp16.rk3588.rkllm")
out.parent.mkdir(parents=True, exist_ok=True)

llm = RKLLM()
print("[load]", model, flush=True)
ret = llm.load_huggingface(model=str(model), device="cpu", dtype="float32")
print("[load_ret]", ret, flush=True)
if ret != 0:
    raise SystemExit(ret)
print("[build] rk3588 fp16", flush=True)
ret = llm.build(
    do_quantization=False,
    optimization_level=1,
    target_platform="rk3588",
    num_npu_core=3,
    max_context=4096,
)
print("[build_ret]", ret, flush=True)
if ret != 0:
    raise SystemExit(ret)
print("[export]", out, flush=True)
ret = llm.export_rkllm(str(out))
print("[export_ret]", ret, flush=True)
if ret != 0:
    raise SystemExit(ret)
print("[done]", out, out.stat().st_size, flush=True)
