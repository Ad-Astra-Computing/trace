#!/usr/bin/env bash
# Regenerate the LoRA package from the frozen reviewer export and symlink
# the files to the names mlx-lm expects (train.jsonl / valid.jsonl / test.jsonl).
#
# Run from the repo root on perdurabo before starting the mlx-lm training:
#   bash lora/prepare_mlx_data.sh
set -euo pipefail
cd "$(dirname "$0")/.."

# 1. Regenerate from the v1.0 frozen export (gitignored but reproducible)
echo "==> Packaging LoRA data from exports/reviewer-v1.0/reviewer.jsonl"
python3 eval/package_lora.py --seq-len 16384

# 2. Create mlx-lm-expected symlinks in exports/lora/
# (mlx-lm looks for train.jsonl + valid.jsonl in the --data dir)
cd exports/lora
ln -sf reviewer.train.jsonl train.jsonl
ln -sf reviewer.dev.jsonl   valid.jsonl
ln -sf reviewer.test.jsonl  test.jsonl
echo "==> Symlinked: train.jsonl -> reviewer.train.jsonl"
echo "              valid.jsonl -> reviewer.dev.jsonl"
echo "              test.jsonl  -> reviewer.test.jsonl"

# 3. Quick sanity: count lines
echo "==> Line counts:"
wc -l train.jsonl valid.jsonl test.jsonl
echo ""
echo "Ready. Run:"
echo "  python3 -m mlx_lm.lora --config lora/mlx_config.yaml"
