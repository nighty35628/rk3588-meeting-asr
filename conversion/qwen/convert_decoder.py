"""Path-parameterized convenience adaptation of the recovered decoder script.

Settings match convert_decoder_rk3588_fp16.historical.py. This is a new command
interface, not a recovered historical shell invocation or reconstruction proof.
"""
import argparse
from pathlib import Path


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--model',type=Path,required=True,help='already repacked Qwen3 text-decoder HF directory')
    ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args()
    if a.output.exists():raise SystemExit('refusing to overwrite model output')
    if not (a.model/'config.json').is_file():raise SystemExit('repacked model directory required')
    from rkllm.api import RKLLM
    a.output.parent.mkdir(parents=True,exist_ok=True)
    llm=RKLLM()
    for call in [lambda:llm.load_huggingface(model=str(a.model),device='cpu',dtype='float32'),
                 lambda:llm.build(do_quantization=False,optimization_level=1,target_platform='rk3588',num_npu_core=3,max_context=4096),
                 lambda:llm.export_rkllm(str(a.output))]:
        ret=call()
        if ret!=0:raise SystemExit(ret)


if __name__=='__main__':main()
