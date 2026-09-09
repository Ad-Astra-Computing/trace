"""
Build authoring-lora-data-v9: v6 base + 21 hand-authored training examples.

v9 = v8 (v6 base + 6 supplements: bzip2/libssh2/FFmpeg condition-refine +
libpng/libraw/libarchive real-diff) plus 15 new real-diff hand-authored
examples stratified by fix-site position, distractor density, edit type,
language, function size, signal shape and token rarity:

    - libtiff    CVE-2015-8784  (NeXTDecode OOB write)
    - tcpdump    CVE-2017-12898 (NFS OOB read)
    - tcpdump    CVE-2017-13024 (mobility OOB read)
    - libpng     CVE-2018-13785 (png_check_chunk_length row-factor overflow)
    - file       CVE-2019-18218 (cdf vector element limit)
    - nginx      CVE-2021-23017 (resolver DNS off-by-one)
    - Pillow     CVE-2021-28677 (FliDecode copy OOB read)
    - lz4        CVE-2021-3520  (negative outputSize)
    - openjpeg   CVE-2021-3575  (sycc420_to_rgb OOB read)
    - libssh     CVE-2023-3603  (sftp read null check)
    - c-ares     CVE-2024-25629 (read_line NUL-embedded)
    - libarchive CVE-2024-37407 (zip empty-name OOB)
    - Werkzeug   CVE-2024-49766 (safe_join Windows abspath)
    - cJSON      CVE-2025-57052 (array index cursor)
    - gpac       CVE-2026-7135  (elng box read size overflow)

Like the v7/v8 supplement examples, these bypass the standard behavioral gate
(no reproducer/cert infrastructure for these historical CVEs). They are pure
authoring-example.json hand-authored pairs.

Usage (from repo root, after `set -a && source .env && set +a`):
    python3 lora/build_authoring_dataset_v9.py [--upload]

Writes exports/authoring-v9/authoring.jsonl, the messages-only split files
(authoring.train.jsonl / authoring.dev.jsonl / authoring.test.jsonl) and a
manifest.json, mirroring the layout of the v8 HF dataset repo.
With --upload, also pushes to adastracomputing/authoring-lora-data-v9.
"""

import argparse
import json
import re
import sys
from pathlib import Path

_AUTHORING_SYSTEM = (
    "You are a security engineer fixing a CVE. You are given the vulnerability "
    "description (symptom only) and the vulnerable source window. Author the "
    "MINIMAL fix as a unified diff. Follow these rules exactly:\n"
    "1. Target ONLY the file named in the `# Vulnerable source (...)` header — "
    "do not invent or substitute file paths.\n"
    "2. Modify ONLY code visible in the shown source window.\n"
    "3. Change as few lines as possible; do not rewrite surrounding logic.\n"
    "4. Output only the unified diff with no other text.\n"
    "5. Prefer the minimal structural change: if an existing condition is missing "
    "a check, add it inline to that condition rather than inserting a new code "
    "block. If existing code is redundant or overcomplicated, replace it — do not "
    "add more code around it.\n"
    "6. Edit the most specific method or class that directly handles the vulnerable "
    "operation — not a base class, interface, or Protocol definition."
)

_REMEDIATION_RE = re.compile(
    r"\b(fixed (in|by|upstream)|the fix|patched? (in|by)|adds? a (bounds|null|length) check|"
    r"resolved by|remediat\w+|commit [0-9a-f]{7,}|backport|shipped in)\b",
    re.IGNORECASE,
)

# Directories under traces/example/ that are hand-authored training examples.
# These are NOT exported by the standard pipeline (no behavioral validation).
# v9 = the 6 v8 supplement dirs + 15 new real-diff dirs.
_V9_SUPPLEMENT_DIRS = [
    # v7 (condition-refine)
    "CVE-2019-12900--bzip2-nselectors-oob-backport",
    "CVE-2019-3863--libssh2-flush-oob-backport",
    "CVE-2025-69693--ffmpeg-rv60dec-qp-oob-backport",
    # v8 (real-diff)
    "CVE-2017-12652--libpng-chunk-length-limit-backport",
    "CVE-2020-15503--libraw-kodak-thumb-oob-backport",
    "CVE-2025-5917--libarchive-ustar-name-off-by-one-backport",
    # v9 (real-diff, localization + edit-precision diverse)
    "CVE-2015-8784--libtiff-next-decode-oob-write-backport",
    "CVE-2017-12898--tcpdump-nfs-oob-read-backport",
    "CVE-2017-13024--tcpdump-mobility-oob-read-backport",
    "CVE-2018-13785--libpng-png-check-chunk-length-row-factor-overflow-backport",
    "CVE-2019-18218--file-cdf-vector-element-limit-backport",
    "CVE-2021-23017--nginx-resolver-dns-off-by-one-backport",
    "CVE-2021-28677--pillow-flidecode-copy-oob-read-backport",
    "CVE-2021-3520--lz4-negative-outputsize-backport",
    "CVE-2021-3575--openjpeg-sycc420-to-rgb-oob-read-backport",
    "CVE-2023-3603--libssh-sftp-read-null-check-backport",
    "CVE-2024-25629--c-ares-read-line-null-embedded-backport",
    "CVE-2024-37407--libarchive-zip-empty-name-oob-backport",
    "CVE-2024-49766--werkzeug-safe-join-windows-abspath-backport",
    "CVE-2025-57052--cjson-array-index-cursor-backport",
    "CVE-2026-7135--gpac-elng-box-read-size-overflow-backport",
]

SEQ_LEN_BUDGET = 16384


def _code_only(body: str, in_block: bool = False) -> tuple[str, bool]:
    out: list[str] = []
    i, n = 0, len(body)
    while i < n:
        if in_block:
            end = body.find("*/", i)
            if end == -1:
                return "".join(out), True
            i, in_block = end + 2, False
            continue
        two = body[i : i + 2]
        if two == "/*":
            in_block = True
            i += 2
            continue
        if two == "//":
            break
        ch = body[i]
        if ch in ('"', "'"):
            j = i + 1
            while j < n:
                if body[j] == "\\" and j + 1 < n:
                    j += 2
                    continue
                if body[j] == ch:
                    j += 1
                    break
                j += 1
            i = j
            continue
        out.append(ch)
        i += 1
    return "".join(out), in_block


def _fix_symbols(fix_diff: str) -> set[str]:
    syms: set[str] = set()
    minus_nums: set[str] = set()
    plus_nums: set[str] = set()
    new_blk = old_blk = False
    for ln in fix_diff.splitlines():
        if ln.startswith(("diff ", "@@", "+++", "---")):
            new_blk = old_blk = False
            continue
        side = ln[:1]
        if side == " ":
            _, new_blk = _code_only(ln[1:], new_blk)
            _, old_blk = _code_only(ln[1:], old_blk)
            continue
        if side == "+":
            body, new_blk = _code_only(ln[1:], new_blk)
        elif side == "-":
            body, old_blk = _code_only(ln[1:], old_blk)
        else:
            continue
        for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", body):
            if "_" in tok or tok.isupper() or tok != tok.lower() or len(tok) >= 6:
                syms.add(tok)
        nums = {n for n in re.findall(r"\b\d+\b", body) if len(n) >= 2}
        (plus_nums if side == "+" else minus_nums).update(nums)
    syms |= minus_nums ^ plus_nums
    return syms


def _mentions(text: str, sym: str) -> bool:
    if sym.isdigit():
        return re.search(rf"(?<!\d){re.escape(sym)}(?!\d)", text) is not None
    return sym in text


def _scrub_summary(summary: str, fix_diff: str) -> str:
    syms = _fix_symbols(fix_diff)
    out = []
    for s in re.split(r"(?<=[.])\s+", summary):
        if _REMEDIATION_RE.search(s):
            continue
        if any(_mentions(s, sym) for sym in syms):
            continue
        out.append(s)
    return " ".join(out).strip()


def _fence_lang(filename: str) -> str:
    ext = Path(filename).suffix
    return {
        ".c": "c",
        ".h": "c",
        ".cpp": "cpp",
        ".py": "python",
        ".go": "go",
        ".rs": "rust",
        ".java": "java",
        ".rb": "ruby",
    }.get(ext, "")


def _build_record(ae: dict, split: str) -> dict | None:
    cve_id = ae["cve_id"]
    fix_diff = ae["fix_diff"]
    included = ae.get("included_source_files") or [ae["file"]]
    src_header = ", ".join(included)
    fence = _fence_lang(included[0])

    vuln = _scrub_summary(ae["vuln_raw"], fix_diff)
    if not vuln:
        print(
            f"  WARN {cve_id}: description empty after scrub — using raw",
            file=sys.stderr,
        )
        vuln = ae["vuln_raw"]

    user = (
        f"# CVE\n{cve_id}: {vuln}\n\n"
        f"# Vulnerable source ({src_header})\n```{fence}\n{ae['pre_fix_source']}\n```"
    )

    label_file_count = sum(1 for ln in fix_diff.splitlines() if ln.startswith("+++ "))

    return {
        "messages": [
            {"role": "system", "content": _AUTHORING_SYSTEM},
            {"role": "user", "content": user},
            {"role": "assistant", "content": fix_diff},
        ],
        "task": "author-from-vuln",
        "split": split,
        "provenance": {
            "bundle_id": None,
            "cve_id": cve_id,
            "attr_path": ae.get("attr_path", ""),
            "split_family": re.sub(r"[^a-z0-9]", "", ae.get("attr_path", "").lower()),
            "fix_commit": (ae.get("fix_commit") or {}).get("commit_sha"),
            "steward_signed": False,
            "kind": "hand-authored-training-example",
            "authoring_validation_tier": "hand-authored",
            "cert_green": False,
            "backport_validated": False,
            "label_file_count": label_file_count,
            "included_source_files": included,
            "omitted_source_files": [],
            "input_window_truncated": bool(ae.get("input_window_truncated", False)),
            "authoring_multifile_status": "single-file"
            if label_file_count <= 1
            else "multifile-v1",
            "eligible_under_multifile_v1": label_file_count <= 3,
            "label_grounding_source": ae.get("label_source", "upstream-fix.patch"),
        },
    }


def _tier(prov: dict) -> str:
    if prov.get("cert_green"):
        return "cert-green"
    if (
        prov.get("kind") == "hand-authored-training-example"
        or prov.get("authoring_validation_tier") == "hand-authored"
    ):
        return "hand-authored"
    return "behavioral-only"


def _est_tokens(rec: dict) -> int:
    txt = "".join(m["content"] for m in rec["messages"])
    return len(txt) // 4


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--upload", action="store_true", help="push to HF dataset repo")
    ap.add_argument(
        "--traces-root",
        type=Path,
        default=Path("traces/example"),
        help="root of CVE-* bundles",
    )
    ap.add_argument(
        "--v6-jsonl",
        type=Path,
        default=Path("exports/authoring-v6/authoring.jsonl"),
        help="v6 base JSONL to extend",
    )
    ap.add_argument(
        "--out",
        type=Path,
        default=Path("exports/authoring-v9"),
        help="output directory",
    )
    args = ap.parse_args()

    if not args.v6_jsonl.is_file():
        print(f"error: v6 JSONL not found: {args.v6_jsonl}")
        sys.exit(2)

    # Load v6 records.
    v6_records = [
        json.loads(ln) for ln in args.v6_jsonl.read_text().splitlines() if ln.strip()
    ]
    print(f"v6 base: {len(v6_records)} records")

    # Build supplement records for the hand-authored examples.
    supplement: list[dict] = []
    for cve_dir in _V9_SUPPLEMENT_DIRS:
        ae_path = args.traces_root / cve_dir / "authoring-example.json"
        if not ae_path.is_file():
            print(f"  MISSING {ae_path} — skipping", file=sys.stderr)
            continue
        ae = json.loads(ae_path.read_text())
        # All supplement examples go to "train".
        rec = _build_record(ae, split="train")
        if rec is None:
            continue
        supplement.append(rec)
        print(f"  + {ae['cve_id']} ({cve_dir})")

    print(f"supplement: {len(supplement)} records")

    examples = v6_records + supplement
    examples.sort(key=lambda e: (e["split"], e["provenance"].get("cve_id") or ""))

    args.out.mkdir(parents=True, exist_ok=True)

    # Full JSONL (with provenance + split) — internal/reference artifact.
    jsonl_path = args.out / "authoring.jsonl"
    with jsonl_path.open("w") as fh:
        for ex in examples:
            fh.write(json.dumps(ex, sort_keys=True) + "\n")

    # Messages-only split files (training-ready), mirroring the v8 dataset repo.
    splits: dict[str, int] = {}
    for split in ("train", "dev", "test"):
        recs = [e for e in examples if e["split"] == split]
        splits[split] = len(recs)
        split_path = args.out / f"authoring.{split}.jsonl"
        with split_path.open("w") as fh:
            for ex in recs:
                fh.write(json.dumps({"messages": ex["messages"]}) + "\n")

    # Rich manifest (mirrors the v8 dataset-repo manifest shape).
    tiers: dict[str, int] = {}
    tiers_by_split: dict[str, dict[str, int]] = {}
    over_seq_len: list[dict] = []
    tok_vals: list[int] = []
    for ex in examples:
        t = _tier(ex["provenance"])
        tiers[t] = tiers.get(t, 0) + 1
        tiers_by_split.setdefault(ex["split"], {})
        tiers_by_split[ex["split"]][t] = tiers_by_split[ex["split"]].get(t, 0) + 1
        est = _est_tokens(ex)
        tok_vals.append(est)
        if est > SEQ_LEN_BUDGET:
            over_seq_len.append(
                {
                    "cve": ex["provenance"].get("cve_id"),
                    "est_tokens": est,
                    "split": ex["split"],
                }
            )

    manifest = {
        "base_model": "Qwen2.5-Coder-14B",
        "version": "v9",
        "base_version": "v6",
        "supplement_dirs": _V9_SUPPLEMENT_DIRS,
        "est_token_stats": {
            "max": max(tok_vals) if tok_vals else 0,
            "mean": sum(tok_vals) // len(tok_vals) if tok_vals else 0,
        },
        "files": [
            "authoring.train.jsonl",
            "authoring.dev.jsonl",
            "authoring.test.jsonl",
        ],
        "over_seq_len": over_seq_len,
        "schema_version": "1.0.0",
        "seq_len_budget": SEQ_LEN_BUDGET,
        "splits": splits,
        "task": "author-from-vuln-sft",
        "tiers": tiers,
        "tiers_by_split": tiers_by_split,
        "total": len(examples),
        "v6_count": len(v6_records),
        "supplement_count": len(supplement),
        "validation_errors": [],
    }
    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"wrote {jsonl_path} ({len(examples)} records)")
    print(f"splits: {splits}")
    print(f"tiers: {tiers}")

    if args.upload:
        from huggingface_hub import HfApi

        api = HfApi()
        repo_id = "adastracomputing/authoring-lora-data-v9"
        api.create_repo(repo_id, repo_type="dataset", exist_ok=True, private=True)
        api.upload_folder(
            folder_path=str(args.out),
            repo_id=repo_id,
            repo_type="dataset",
            allow_patterns=[
                "authoring.jsonl",
                "authoring.train.jsonl",
                "authoring.dev.jsonl",
                "authoring.test.jsonl",
                "manifest.json",
            ],
        )
        print(f"uploaded to {repo_id}")


if __name__ == "__main__":
    main()
