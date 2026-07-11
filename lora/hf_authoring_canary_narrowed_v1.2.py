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
Authoring-LoRA narrowed-window localization ablation — HF Jobs UV-script.

v1.2 scores 0/4 on the Authoring-LoRA canaries; the diagnosed bottleneck is
localization (finding the true fix line, not authoring the edit). This ablation
falsifies-or-confirms "localization is the only blocker" by tightly narrowing
ONLY the source window in each canary user turn to a tight excerpt around the
true fix site (every line the reference diff touches + a few lines of context
each side), while keeping the system turn and CVE-description text IDENTICAL.

For each of the four canaries we build two variants of the user turn:
  - original : the canary user turn, unchanged (sanity check — should reproduce
               the recorded v1.2 failure).
  - narrowed : same system turn + same CVE description; source window shrunk to
               a tight excerpt around the true fix site, distractor blocks
               removed. Each transform is programmatic with runtime drift-guard
               assertions on expected pre-transformation lines, and asserts the
               known distractor is gone and the fix site retained. Windows stay
               syntactically plausible (balanced braces / no dangling blocks).

Runs greedy inference for {original, narrowed} x 4 canaries = 8 generations
against adapter adastracomputing/authoring-lora-v1.2, and uploads
canary-narrowed-responses.jsonl to that model repo with fields:
  cve_id, variant, generated.

Base-model pin: Qwen/Qwen2.5-Coder-14B-Instruct @
aedcc2d42b622764e023cf882b6652e646b95671, nf4 4-bit quant, MAX_NEW_TOKENS=1024,
greedy (do_sample=False).

Usage (see lora/submit_hf_gen_canaries_v1.2.sh style / the submit wrapper):
  hf jobs uv run --flavor a100-large --namespace odoom --timeout 1h --detach \\
    --secrets HF_TOKEN lora/hf_authoring_canary_narrowed_v1.2.py
"""
import json
import os
import re
from pathlib import Path

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

DATASET_REPO = os.environ.get("DATASET_REPO", "adastracomputing/authoring-lora-data-v6")
ADAPTER_REPO = os.environ.get("ADAPTER_REPO", "adastracomputing/authoring-lora-v1.2")
ADAPTER_LABEL = "v1.2"
UPLOAD_REPO = os.environ.get("UPLOAD_REPO", ADAPTER_REPO)
UPLOAD_FILENAME = os.environ.get("UPLOAD_FILENAME", "canary-narrowed-responses.jsonl")
BASE_MODEL_ID = "Qwen/Qwen2.5-Coder-14B-Instruct"
MODEL_REVISION = "aedcc2d42b622764e023cf882b6652e646b95671"
MAX_NEW_TOKENS = 1024

CVE_ORDER = [
    "CVE-2022-37434",
    "CVE-2026-42250",
    "CVE-2024-47081",
    "CVE-2026-48526",
]

FENCE_RE = re.compile(
    r"^(?P<head>.*?```)(?P<lang>\w+)\n(?P<code>.*?)\n```(?P<tail>.*)$",
    re.DOTALL,
)


def split_window(user: str):
    m = FENCE_RE.match(user)
    if not m:
        raise AssertionError("canary drift: no fenced source window found")
    return m.group("head"), m.group("lang"), m.group("code"), m.group("tail")


def rebuild(head: str, lang: str, code: str, tail: str) -> str:
    return f"{head}{lang}\n{code}\n```{tail}"


# ---- CVE-2022-37434 (zlib): keep from `case EXTRA:` onward; drop EXLEN block ----
def narrow_zlib(user: str):
    head, lang, code, tail = split_window(user)
    lines = code.split("\n")
    for expect in ["        case EXLEN:", "            else if (state->head != Z_NULL)",
                   "                state->head->extra = Z_NULL;", "        case EXTRA:",
                   "                        len = state->head->extra_len - state->length;"]:
        if expect not in lines:
            raise AssertionError(f"zlib canary drift: missing {expect!r}")
    label = "        case EXTRA:"
    idx = lines.index(label)
    narrowed = "\n".join(lines[idx:])
    assert "case EXLEN:" not in narrowed, "zlib narrowed still has EXLEN"
    assert "state->head->extra = Z_NULL;" not in narrowed, "zlib narrowed kept distractor"
    assert "len = state->head->extra_len - state->length;" in narrowed, "zlib fix site missing"
    assert narrowed.count("{") == narrowed.count("}"), "zlib narrowed brace imbalance"
    removed = "\n".join(lines[:idx])
    return rebuild(head, lang, narrowed, tail), removed


# ---- CVE-2026-42250 (bzip2recover): keep guard region; excise `>= 130` fprintf block ----
def narrow_bzip2(user: str):
    head, lang, code, tail = split_window(user)
    lines = code.split("\n")
    guard = "         if (currBlock >= BZ_MAX_HANDLED_BLOCKS)"
    dist_open = "         if (currBlock > 0 &&"
    dist_test = "\t     (bEnd[currBlock] - bStart[currBlock]) >= 130) {"
    lead_start = "         if (bitsRead > 49) {"
    end_anchor = "         bStart[currBlock] = bitsRead;"
    for expect in [guard, dist_open, dist_test, lead_start, end_anchor,
                   "            tooManyBlocks(BZ_MAX_HANDLED_BLOCKS);",
                   "         currBlock++;"]:
        if expect not in lines:
            raise AssertionError(f"bzip2 canary drift: missing {expect!r}")
    # Excise the whole `if (currBlock > 0 && ... >= 130) { ... }` distractor block.
    d_start = lines.index(dist_open)
    # closing brace of the distractor block is the standalone `         }` after rbCtr++.
    rbctr = lines.index("            rbCtr++;")
    d_close = rbctr + 1
    if lines[d_close].strip() != "}":
        raise AssertionError("bzip2 canary drift: distractor close brace not where expected")
    # Keep: lead-in (bEnd computation) up to just before distractor, then guard region onward.
    lead_idx = lines.index(lead_start)
    end_idx = lines.index(end_anchor)
    kept = lines[lead_idx:d_start] + lines[d_close + 1:end_idx + 1]
    narrowed = "\n".join(kept)
    assert ">= 130) {" not in narrowed, "bzip2 distractor >=130 still present"
    assert "block %d runs from" not in narrowed, "bzip2 fprintf distractor present"
    assert guard.strip() in narrowed, "bzip2 fix guard missing"
    assert "currBlock++;" in narrowed, "bzip2 currBlock++ missing"
    assert narrowed.count("{") == narrowed.count("}"), "bzip2 narrowed brace imbalance"
    removed = "\n".join(lines[:lead_idx]) + \
        "\n... [removed `>= 130` fprintf block-runs distractor] ...\n" + \
        "\n".join(lines[end_idx + 1:])
    return rebuild(head, lang, narrowed, tail), removed


# ---- CVE-2024-47081 (requests): keep netloc-splitting region + authenticators call ----
def narrow_requests(user: str):
    head, lang, code, tail = split_window(user)
    lines = code.split("\n")
    start_anchor = "        if netrc_path is None:"
    fix_anchor = "        host = ri.netloc.split(splitstr)[0]"
    auth_anchor = "            _netrc = netrc(netrc_path).authenticators(host)"
    for expect in [start_anchor, "        ri = urlparse(url)", '        splitstr = b":"',
                   fix_anchor, auth_anchor]:
        if expect not in lines:
            raise AssertionError(f"requests canary drift: missing {expect!r}")
    sidx = lines.index(start_anchor)
    aidx = lines.index(auth_anchor)
    # keep through the `if _netrc:` line for a balanced-looking tail.
    kept = lines[sidx:aidx + 2]
    narrowed = "\n".join(kept)
    assert fix_anchor in narrowed, "requests fix site missing"
    assert 'splitstr = b":"' in narrowed, "requests splitstr missing"
    assert "netrc_locations" not in narrowed, "requests earlier loop distractor present"
    assert "os.path.expanduser" not in narrowed, "requests expanduser distractor present"
    removed = "\n".join(lines[:sidx]) + \
        "\n... [removed earlier get_netrc_auth body: netrc_locations loop] ...\n" + \
        "\n".join(lines[aidx + 2:])
    return rebuild(head, lang, narrowed, tail), removed


# ---- CVE-2026-48526 (pyjwt): keep prepare_key body only (already small) ----
def narrow_pyjwt(user: str):
    head, lang, code, tail = split_window(user)
    lines = code.split("\n")
    start_anchor = "    def prepare_key(self, key: str | bytes) -> bytes:"
    end_anchor = "        return key_bytes"
    for expect in [start_anchor, "        key_bytes = force_bytes(key)",
                   "        if is_pem_format(key_bytes) or is_ssh_key(key_bytes):",
                   end_anchor]:
        if expect not in lines:
            raise AssertionError(f"pyjwt canary drift: missing {expect!r}")
    sidx = lines.index(start_anchor)
    eidx = lines.index(end_anchor)
    kept = lines[sidx:eidx + 1]
    narrowed = "\n".join(kept)
    assert "key_bytes = force_bytes(key)" in narrowed, "pyjwt fix site missing"
    assert "to_jwk" not in narrowed, "pyjwt to_jwk distractor present"
    assert "class HMACAlgorithm" not in narrowed, "pyjwt class header present"
    removed = "\n".join(lines[:sidx]) + \
        "\n... [removed class header + SHA ClassVars + to_jwk overloads] ...\n" + \
        "\n".join(lines[eidx + 1:])
    return rebuild(head, lang, narrowed, tail), removed


TRANSFORMS = {
    "CVE-2022-37434": narrow_zlib,
    "CVE-2026-42250": narrow_bzip2,
    "CVE-2024-47081": narrow_requests,
    "CVE-2026-48526": narrow_pyjwt,
}


def load_records(dataset_repo: str) -> dict:
    from huggingface_hub import hf_hub_download
    path = hf_hub_download(
        repo_id=dataset_repo,
        filename="authoring.canary.jsonl",
        repo_type="dataset",
    )
    out = {}
    with open(path) as f:
        for line in f:
            if not line.strip():
                continue
            r = json.loads(line)
            out[r["provenance"]["cve_id"]] = r
    return out


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
    generated_ids = out[0][inputs["input_ids"].shape[1]:]
    return tokenizer.decode(generated_ids, skip_special_tokens=True).strip()


def main():
    print(f"Loading canaries from {DATASET_REPO}", flush=True)
    recs = load_records(DATASET_REPO)
    missing = [c for c in CVE_ORDER if c not in recs]
    if missing:
        raise RuntimeError(f"canary records missing: {missing}")

    # Build {cve: {variant: user_text}} with drift-guarded programmatic narrowing.
    per_cve = {}
    for cve in CVE_ORDER:
        rec = recs[cve]
        system = rec["messages"][0]["content"]
        user = rec["messages"][1]["content"]
        narrowed_user, removed = TRANSFORMS[cve](user)
        per_cve[cve] = {
            "system": system,
            "original": user,
            "narrowed": narrowed_user,
        }
        _, _, ncode, _ = split_window(narrowed_user)
        print("\n" + "=" * 80, flush=True)
        print(f"NARROWED WINDOW — {cve}", flush=True)
        print("=" * 80, flush=True)
        print(ncode, flush=True)
        print("---- REMOVED ----", flush=True)
        print(removed, flush=True)

    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.bfloat16,
        bnb_4bit_use_double_quant=True,
    )

    print(f"\nLoading base model {BASE_MODEL_ID} @ {MODEL_REVISION}", flush=True)
    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL_ID, revision=MODEL_REVISION)
    tokenizer.pad_token = tokenizer.eos_token
    base = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL_ID,
        revision=MODEL_REVISION,
        quantization_config=bnb_config,
        device_map="auto",
    )

    # PEFT adapter names become nn.Module keys and cannot contain ".".
    peft_name = ADAPTER_LABEL.replace(".", "_")
    print(f"\n=== Attaching adapter {ADAPTER_LABEL} ({ADAPTER_REPO}) ===", flush=True)
    model = PeftModel.from_pretrained(base, ADAPTER_REPO, adapter_name=peft_name)
    model.set_adapter(peft_name)
    model.eval()

    responses = []
    for cve in CVE_ORDER:
        system = per_cve[cve]["system"]
        for variant in ("original", "narrowed"):
            print(f"Generating {cve} / {variant}...", flush=True)
            generated = generate(model, tokenizer, system, per_cve[cve][variant])
            responses.append(
                {"cve_id": cve, "variant": variant, "generated": generated}
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
