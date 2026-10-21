"""Read saved aggregate contrasts; no inference or statistical recomputation."""
from pathlib import Path
import csv
root = Path(__file__).resolve().parents[1]
with (root/'results/matched_measurement/effects.csv').open(newline='') as f:
    for row in csv.DictReader(f):
        if row['mode'] == 'minimal' and row['sampler'] == 'fixed_date_R_recording' and row['metric'] == 'candidate_minus_comparator_ms':
            print(f"{row['contrast']}: {float(row['estimate']):+.3f} ms "
                  f"[descriptive 95% interval {float(row['ci95_low']):+.3f}, {float(row['ci95_high']):+.3f}]")
