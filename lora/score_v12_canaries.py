#!/usr/bin/env python3
"""Score adapter canary responses against reference diffs (patch-line comparison).

Usage: score_v12_canaries.py <authoring.canary.jsonl> <responses.jsonl> [prior-responses.jsonl]

Canaries come from the adastracomputing/authoring-lora-data-v6 dataset repo;
responses come from the adapter model repo (canary-responses.jsonl). The
optional third argument prints a prior adapter's patch-lines for comparison.
"""
import json, re, sys

def extract_diff(text):
    """Pull the first fenced diff/patch block, else the whole text."""
    m = re.search(r"```(?:diff|patch)?\s*\n(.*?)```", text, re.DOTALL)
    if m:
        return m.group(1)
    return text

def patch_lines(diff_text):
    """Extract functional +/- lines, stripping trailing whitespace.
    Exclude diff/index/---/+++/@@ header lines."""
    out = []
    for ln in diff_text.splitlines():
        s = ln.rstrip()
        if s.startswith(("diff ", "index ", "--- ", "+++ ", "@@")):
            continue
        if s.startswith("+") or s.startswith("-"):
            out.append(s)
    return out

def load_refs(canary_path):
    refs = {}
    with open(canary_path) as f:
        for line in f:
            r = json.loads(line)
            cve = r["provenance"]["cve_id"]
            attr = r["provenance"]["attr_path"]
            asst = [m["content"] for m in r["messages"] if m["role"] == "assistant"][0]
            user = [m["content"] for m in r["messages"] if m["role"] == "user"][0]
            refs[cve] = {"attr": attr, "asst": asst, "user": user}
    return refs

def load_responses(path):
    """Return dict cve_id -> generated text. Handles a few schemas."""
    out = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            # find cve id
            cve = r.get("cve_id") or r.get("provenance", {}).get("cve_id")
            gen = (r.get("response") or r.get("generated") or r.get("output")
                   or r.get("completion") or r.get("assistant"))
            if gen is None and "messages" in r:
                asst = [m["content"] for m in r["messages"] if m["role"] == "assistant"]
                gen = asst[-1] if asst else None
            out[cve] = {"gen": gen, "raw": r}
    return out

def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__.strip())
    canary_path = sys.argv[1]
    v12_path = sys.argv[2]
    v11_path = sys.argv[3] if len(sys.argv) > 3 else None
    refs = load_refs(canary_path)
    v12 = load_responses(v12_path)
    v11 = load_responses(v11_path) if v11_path else {}

    order = ["CVE-2022-37434", "CVE-2024-47081", "CVE-2026-42250", "CVE-2026-48526"]
    for cve in order:
        ref = refs[cve]
        print("=" * 80)
        print(f"CANARY {cve}  ({ref['attr']})")
        print("-" * 80)
        ref_pl = patch_lines(extract_diff(ref["asst"]))
        print("REFERENCE patch-lines:")
        for l in ref_pl:
            print("   ", repr(l))
        gen = v12.get(cve, {}).get("gen")
        if gen is None:
            print(">>> NO v1.2 RESPONSE for", cve, " raw keys:", list(v12.get(cve, {}).get("raw", {}).keys()))
            continue
        gen_pl = patch_lines(extract_diff(gen))
        match = (gen_pl == ref_pl)
        print(f"\nv1.2 RESULT: {'PASS' if match else 'FAIL'}")
        print("v1.2 patch-lines:")
        for l in gen_pl:
            print("   ", repr(l))
        if v11:
            g11 = v11.get(cve, {}).get("gen")
            if g11 is not None:
                pl11 = patch_lines(extract_diff(g11))
                print("v1.1 patch-lines (compare):")
                for l in pl11:
                    print("   ", repr(l))
        print("\n----- FULL v1.2 GENERATED (verbatim) -----")
        print(gen)
        print("----- END -----")

if __name__ == "__main__":
    main()
