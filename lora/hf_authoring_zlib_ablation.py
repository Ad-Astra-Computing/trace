# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "torch==2.5.1",
#   "transformers==4.47.1",
#   "peft==0.14.0",
#   "bitsandbytes==0.45.0",
#   "datasets==3.2.0",
#   "accelerate==1.2.1",
#   "huggingface-hub>=0.26.0",
# ]
# ///
"""
Authoring-LoRA zlib positional-bias ablation — HF Jobs UV-script.

Tests the hypothesis that the EXLEN case block (an early lookalike containing
`else if (state->head != Z_NULL) / state->head->extra = Z_NULL;`) acts as a
distractor that pulls the model's edit ~9 lines EARLIER than the true fix site
(the EXTRA case block with `len = state->head->extra_len - state->length;` and
the `zmemcpy(...)` call).

Downloads the CVE-2022-37434 canary record from
adastracomputing/authoring-lora-data-v6 (authoring.canary.jsonl) and constructs
TWO ablation variants of the user turn (source window only), plus the original:

  - original        : the canary user turn, unchanged.
  - narrowed        : the entire EXLEN case block removed so the window starts at
                      `case EXTRA:` (distractor gone). Description unchanged.
  - reordered-hint  : full window unchanged; one sentence appended to the CVE
                      description naming the EXTRA state case + zmemcpy.

Runs greedy inference for {original, narrowed, reordered-hint} × {v1.0, v1.1}
= 6 generations (base loaded once; adapters attached/detached sequentially) and
uploads zlib-ablation-responses.jsonl to adastracomputing/authoring-lora-v1.1
with fields: adapter, variant, generated.

BASE-MODEL CONTROL: set INCLUDE_BASE=1 to run the same 3 variants against the
bare base model (no adapter attached, "adapter" field = "base"). When
INCLUDE_BASE=1 and ADAPTERS is empty/unset-to-none, only the base pass runs and
results upload to zlib-ablation-base-responses.jsonl (does not clobber the
v1.0/v1.1 artifact). ADAPTERS is a comma-separated subset of {v1.0,v1.1}; unset
means both (original behavior). UPLOAD_FILENAME overrides the target filename.

Usage (see lora/submit_hf_zlib_ablation.sh):
  hf jobs uv run --flavor a100-large --namespace odoom \\
    --secrets HF_TOKEN \\
    lora/hf_authoring_zlib_ablation.py

Base-only control:
  INCLUDE_BASE=1 ADAPTERS= UPLOAD_FILENAME=zlib-ablation-base-responses.jsonl \\
    hf jobs uv run ... lora/hf_authoring_zlib_ablation.py
"""

import json
import os
from pathlib import Path

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

DATASET_REPO = os.environ.get("DATASET_REPO", "adastracomputing/authoring-lora-data-v6")
UPLOAD_REPO = os.environ.get("UPLOAD_REPO", "adastracomputing/authoring-lora-v1.1")
_ALL_ADAPTER_REPOS = {
    "v1.0": os.environ.get("ADAPTER_V10", "adastracomputing/authoring-lora-v1.0"),
    "v1.1": os.environ.get("ADAPTER_V11", "adastracomputing/authoring-lora-v1.1"),
}
# ADAPTERS: comma-separated subset of {v1.0,v1.1}. Unset -> both (original
# behavior). Empty string -> none (base-only control pass).
_adapters_env = os.environ.get("ADAPTERS")
if _adapters_env is None:
    ADAPTER_REPOS = dict(_ALL_ADAPTER_REPOS)
else:
    _sel = [a.strip() for a in _adapters_env.split(",") if a.strip()]
    for a in _sel:
        if a not in _ALL_ADAPTER_REPOS:
            raise RuntimeError(
                f"unknown adapter {a!r}; known: {list(_ALL_ADAPTER_REPOS)}"
            )
    ADAPTER_REPOS = {a: _ALL_ADAPTER_REPOS[a] for a in _sel}
INCLUDE_BASE = os.environ.get("INCLUDE_BASE", "0") == "1"
UPLOAD_FILENAME = os.environ.get("UPLOAD_FILENAME", "zlib-ablation-responses.jsonl")
BASE_MODEL_ID = "Qwen/Qwen2.5-Coder-14B-Instruct"
MODEL_REVISION = "aedcc2d42b622764e023cf882b6652e646b95671"
MAX_NEW_TOKENS = 1024
CVE_ID = "CVE-2022-37434"

HINT = (
    " The overflow occurs in the EXTRA state case, where the extra-field bytes "
    "are copied via zmemcpy."
)

# Drift guards: exact lines that must be present in the original window before we
# transform it. If the canary is edited upstream, these assertions fail loudly
# rather than silently producing a meaningless ablation.
EXPECT_LINES = [
    "        case EXLEN:",
    "            else if (state->head != Z_NULL)",
    "                state->head->extra = Z_NULL;",
    "        case EXTRA:",
    "                        len = state->head->extra_len - state->length;",
]
SRC_HEADER = "\n\n# Vulnerable source"


def load_zlib_record(dataset_repo: str) -> dict:
    from huggingface_hub import hf_hub_download

    path = hf_hub_download(
        repo_id=dataset_repo,
        filename="authoring.canary.jsonl",
        repo_type="dataset",
    )
    with open(path) as f:
        recs = [json.loads(l) for l in f if l.strip()]
    matches = [r for r in recs if r["provenance"]["cve_id"] == CVE_ID]
    if len(matches) != 1:
        raise RuntimeError(f"expected exactly 1 {CVE_ID} record, found {len(matches)}")
    return matches[0]


def build_variants(user_content: str) -> dict[str, str]:
    """Return {variant_name: user_turn_text}. Transforms are programmatic and
    guarded by drift assertions against EXPECT_LINES."""
    # Drift guard on raw content.
    for line in EXPECT_LINES:
        if line not in user_content:
            raise AssertionError(f"canary drift: expected line missing: {line!r}")
    if "```c\n" not in user_content or SRC_HEADER not in user_content:
        raise AssertionError("canary drift: source-window fence/header not found")

    # --- original ---
    original = user_content

    # --- narrowed: drop everything in the code window before `case EXTRA:` ---
    head, rest = user_content.split("```c\n", 1)
    code, tail = rest.split("\n```", 1)
    lines = code.split("\n")
    extra_label = "        case EXTRA:"
    if extra_label not in lines:
        raise AssertionError("canary drift: `case EXTRA:` label not on its own line")
    idx = lines.index(extra_label)
    narrowed_code = "\n".join(lines[idx:])
    # Sanity: EXLEN distractor gone, EXTRA fix site retained, braces balanced.
    assert "case EXLEN:" not in narrowed_code, "narrowed still has EXLEN"
    assert "state->head->extra = Z_NULL;" not in narrowed_code, (
        "narrowed kept distractor"
    )
    assert "len = state->head->extra_len - state->length;" in narrowed_code
    assert narrowed_code.count("{") == narrowed_code.count("}"), (
        "narrowed brace imbalance"
    )
    narrowed = head + "```c\n" + narrowed_code + "\n```" + tail

    # --- reordered-hint: append hint sentence to the CVE description ---
    cve_section, after = user_content.split(SRC_HEADER, 1)
    reordered = cve_section + HINT + SRC_HEADER + after

    return {"original": original, "narrowed": narrowed, "reordered-hint": reordered}


def generate(model, tokenizer, system: str, user: str) -> str:
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]
    text = tokenizer.apply_chat_template(
        messages, tokenize=False, add_generation_prompt=True
    )
    inputs = tokenizer(text, return_tensors="pt").to(model.device)
    with torch.no_grad():
        out = model.generate(
            **inputs,
            max_new_tokens=MAX_NEW_TOKENS,
            do_sample=False,
            temperature=None,
            top_p=None,
            pad_token_id=tokenizer.eos_token_id,
        )
    generated_ids = out[0][inputs["input_ids"].shape[1] :]
    return tokenizer.decode(generated_ids, skip_special_tokens=True).strip()


def main():
    print(f"Loading {CVE_ID} canary from {DATASET_REPO}", flush=True)
    rec = load_zlib_record(DATASET_REPO)
    system = rec["messages"][0]["content"]
    user = rec["messages"][1]["content"]

    variants = build_variants(user)
    print("Built variants:", list(variants), flush=True)
    for name, text in variants.items():
        window = text.split("```c\n", 1)[1].split("\n```", 1)[0]
        print(f"\n----- VARIANT {name} (window) -----\n{window}\n", flush=True)

    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.bfloat16,
        bnb_4bit_use_double_quant=True,
    )

    print(f"Loading base model {BASE_MODEL_ID} @ {MODEL_REVISION}", flush=True)
    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL_ID, revision=MODEL_REVISION)
    tokenizer.pad_token = tokenizer.eos_token
    base = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL_ID,
        revision=MODEL_REVISION,
        quantization_config=bnb_config,
        device_map="auto",
    )

    responses = []

    # --- base-model control: bare base, no adapter attached ---
    if INCLUDE_BASE:
        print("\n=== Base model (no adapter) ===", flush=True)
        base.eval()
        for variant_name, user_text in variants.items():
            print(f"Generating base / {variant_name}...", flush=True)
            generated = generate(base, tokenizer, system, user_text)
            responses.append(
                {"adapter": "base", "variant": variant_name, "generated": generated}
            )
            print(f"  {len(generated)} chars", flush=True)

    model = None
    for label, adapter_repo in ADAPTER_REPOS.items():
        # PEFT adapter names become nn.Module keys and cannot contain ".".
        peft_name = label.replace(".", "_")
        print(f"\n=== Attaching adapter {label} ({adapter_repo}) ===", flush=True)
        if model is None:
            model = PeftModel.from_pretrained(
                base, adapter_repo, adapter_name=peft_name
            )
        else:
            model.load_adapter(adapter_repo, adapter_name=peft_name)
        model.set_adapter(peft_name)
        model.eval()

        for variant_name, user_text in variants.items():
            print(f"Generating {label} / {variant_name}...", flush=True)
            generated = generate(model, tokenizer, system, user_text)
            responses.append(
                {"adapter": label, "variant": variant_name, "generated": generated}
            )
            print(f"  {len(generated)} chars", flush=True)

    out_path = Path("/tmp") / UPLOAD_FILENAME
    out_path.write_text("\n".join(json.dumps(r) for r in responses) + "\n")
    print(f"\nResponses written to {out_path}", flush=True)

    from huggingface_hub import HfApi

    api = HfApi()
    api.upload_file(
        path_or_fileobj=str(out_path),
        path_in_repo=UPLOAD_FILENAME,
        repo_id=UPLOAD_REPO,
        repo_type="model",
    )
    print(f"Uploaded to {UPLOAD_REPO}/{UPLOAD_FILENAME}", flush=True)


if __name__ == "__main__":
    main()
