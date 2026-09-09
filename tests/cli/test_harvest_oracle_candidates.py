"""Tests for scripts/harvest_oracle_candidates.py.

Builds a small fake nixpkgs tree under tmp_path with hand-written fixture
patches covering the shapes the real scan hits: a clean git format-patch
verbatim cherry-pick, a hand-adapted backport with a "based on ... adjusted
to apply to" style header, a large multi-file patch, and a patch whose
filename carries two CVE ids. Asserts parsing, classification, ranking
order, and that the written manifest files round-trip.
"""

from __future__ import annotations

import json
from pathlib import Path

from scripts import harvest_oracle_candidates as hoc


# ─── fixture patch bodies ──────────────────────────────────────────────────

VERBATIM_PATCH = """\
From e47e56d226519635768e6aab2f38f0ab037c09e5 Mon Sep 17 00:00:00 2001
From: Alice Example <alice@example.com>
Date: Thu, 12 Mar 2026 20:28:43 +0900
Subject: [PATCH] Fix heap buffer overflow

Overflow fix, verbatim cherry-pick of the upstream commit.
---
 src/jv.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/src/jv.c b/src/jv.c
index 1111111..2222222 100644
--- a/src/jv.c
+++ b/src/jv.c
@@ -10,7 +10,7 @@ int foo(void) {
-  old_line_one();
-  old_line_two();
+  new_line_one();
+  new_line_two();
   return 0;
 }
"""

ADAPTED_PATCH = """\
Based on upstream https://example.com/commit/deadbeef
adjusted to apply to 5.47.0

diff --git a/src/plot.lisp b/src/plot.lisp
index 3333333..4444444 100644
--- a/src/plot.lisp
+++ b/src/plot.lisp
@@ -5,3 +5,3 @@
-(setq out-file "plot.ps")
+(setq out-file (format nil "~a.ps" (random-name 16)))
"""

LARGE_MULTIFILE_PATCH = """\
From aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa Mon Sep 17 00:00:00 2001
From: Bob Example <bob@example.com>
Date: Mon, 1 Jan 2026 00:00:00 +0000
Subject: [PATCH] Large refactor touching many files

---
 a.c | 2 +-
 b.c | 2 +-
 c.c | 2 +-
 3 files changed, 3 insertions(+), 3 deletions(-)

diff --git a/a.c b/a.c
index 1111111..2222222 100644
--- a/a.c
+++ b/a.c
@@ -1,3 +1,3 @@
-old_a1();
-old_a2();
+new_a1();
+new_a2();
diff --git a/b.c b/b.c
index 3333333..4444444 100644
--- a/b.c
+++ b/b.c
@@ -1,3 +1,3 @@
-old_b1();
-old_b2();
+new_b1();
+new_b2();
diff --git a/c.c b/c.c
index 5555555..6666666 100644
--- a/c.c
+++ c.c
@@ -1,3 +1,3 @@
-old_c1();
-old_c2();
+new_c1();
+new_c2();
"""

DOUBLE_CVE_PATCH = """\
Backport of the upstream fix, rebased onto our tree.

diff --git a/x.c b/x.c
index 7777777..8888888 100644
--- a/x.c
+++ b/x.c
@@ -1,2 +1,2 @@
-old_x();
+new_x();
"""


# ─── fake nixpkgs tree builder ──────────────────────────────────────────────


def _build_fake_nixpkgs(root: Path) -> Path:
    """Build a fake nixpkgs source dir with 4 CVE patches:

      - by-name/jq/jq/CVE-2026-32316.patch     (verbatim cherry-pick)
      - by-name/ma/maxima/5.47.0-CVE-2024-34490.patch (hand adaptation)
      - development/big/CVE-2026-99999.patch   (large multi-file, verbatim header)
      - by-name/kr/krb5/CVE-2026-40355-and-CVE-2026-40356.patch (two ids)

    Returns the fake nixpkgs root (root / "nixpkgs-source").
    """
    nixpkgs_dir = root / "nixpkgs-source"
    pkgs = nixpkgs_dir / "pkgs"

    jq_dir = pkgs / "by-name" / "jq" / "jq"
    jq_dir.mkdir(parents=True)
    (jq_dir / "package.nix").write_text(
        '{ }: {\n  version = "1.8.1";\n  patches = [ ./CVE-2026-32316.patch ];\n}\n'
    )
    (jq_dir / "CVE-2026-32316.patch").write_text(VERBATIM_PATCH)

    maxima_dir = pkgs / "by-name" / "ma" / "maxima"
    maxima_dir.mkdir(parents=True)
    (maxima_dir / "package.nix").write_text(
        '{ }: {\n  version = "5.47.0";\n'
        "  patches = [ ./5.47.0-CVE-2024-34490.patch ];\n}\n"
    )
    (maxima_dir / "5.47.0-CVE-2024-34490.patch").write_text(ADAPTED_PATCH)

    big_dir = pkgs / "development" / "big"
    big_dir.mkdir(parents=True)
    (big_dir / "default.nix").write_text(
        '{ }: {\n  version = "9.9.9";\n  patches = [ ./CVE-2026-99999.patch ];\n}\n'
    )
    (big_dir / "CVE-2026-99999.patch").write_text(LARGE_MULTIFILE_PATCH)

    krb5_dir = pkgs / "by-name" / "kr" / "krb5"
    krb5_dir.mkdir(parents=True)
    (krb5_dir / "package.nix").write_text(
        '{ }: {\n  version = "1.21";\n'
        "  patches = [ ./CVE-2026-40355-and-CVE-2026-40356.patch ];\n}\n"
    )
    (krb5_dir / "CVE-2026-40355-and-CVE-2026-40356.patch").write_text(DOUBLE_CVE_PATCH)

    return nixpkgs_dir


# ─── resolve_nixpkgs_dir ────────────────────────────────────────────────────


def test_resolve_nixpkgs_dir_explicit(tmp_path: Path) -> None:
    target = tmp_path / "explicit-nixpkgs"
    target.mkdir()
    assert hoc.resolve_nixpkgs_dir(target) == target


def test_resolve_nixpkgs_dir_from_nix_path(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "from-nix-path"
    target.mkdir()
    monkeypatch.setenv("NIX_PATH", f"nixpkgs={target}:nixos-config=/etc/nixos/x.nix")
    assert hoc.resolve_nixpkgs_dir(None) == target


def test_resolve_nixpkgs_dir_missing_raises(monkeypatch) -> None:
    monkeypatch.setenv("NIX_PATH", "nixos-config=/etc/nixos/x.nix")
    try:
        hoc.resolve_nixpkgs_dir(None)
        assert False, "expected SystemExit"
    except SystemExit:
        pass


# ─── parse_cve_ids ──────────────────────────────────────────────────────────


def test_parse_cve_ids_single() -> None:
    assert hoc.parse_cve_ids("CVE-2026-32316.patch") == ["CVE-2026-32316"]


def test_parse_cve_ids_double_dedup_sorted() -> None:
    ids = hoc.parse_cve_ids("CVE-2026-40355-and-CVE-2026-40356.patch")
    assert ids == ["CVE-2026-40355", "CVE-2026-40356"]


def test_parse_cve_ids_case_insensitive() -> None:
    assert hoc.parse_cve_ids("fix-cve-2022-29360.patch") == ["CVE-2022-29360"]


# ─── parse_patch ────────────────────────────────────────────────────────────


def test_parse_patch_verbatim_format_patch() -> None:
    parsed = hoc.parse_patch(VERBATIM_PATCH.encode("utf-8"))
    assert parsed["is_format_patch"] is True
    assert parsed["upstream_commit"] == "e47e56d226519635768e6aab2f38f0ab037c09e5"
    assert parsed["n_files"] == 1
    assert parsed["n_hunks"] == 1
    assert parsed["added_lines"] == 2
    assert parsed["removed_lines"] == 2
    assert parsed["adaptation_signals"] == []


def test_parse_patch_adapted() -> None:
    parsed = hoc.parse_patch(ADAPTED_PATCH.encode("utf-8"))
    assert parsed["is_format_patch"] is False
    assert parsed["upstream_commit"] is None
    assert parsed["n_files"] == 1
    assert parsed["n_hunks"] == 1
    assert parsed["added_lines"] == 1
    assert parsed["removed_lines"] == 1
    assert any(s.startswith("version-target:") for s in parsed["adaptation_signals"])


def test_parse_patch_large_multifile() -> None:
    parsed = hoc.parse_patch(LARGE_MULTIFILE_PATCH.encode("utf-8"))
    assert parsed["is_format_patch"] is True
    assert parsed["n_files"] == 3
    assert parsed["n_hunks"] == 3
    assert parsed["added_lines"] == 6
    assert parsed["removed_lines"] == 6
    assert parsed["adaptation_signals"] == []


def test_parse_patch_backport_signal() -> None:
    parsed = hoc.parse_patch(DOUBLE_CVE_PATCH.encode("utf-8"))
    assert "backport" in parsed["adaptation_signals"]
    assert "rebased" in parsed["adaptation_signals"]


def test_parse_patch_empty_bytes_is_unknown_shaped() -> None:
    parsed = hoc.parse_patch(b"")
    assert parsed["n_files"] == 0
    assert parsed["n_hunks"] == 0
    assert parsed["is_format_patch"] is False
    assert (
        hoc.classify(
            parsed["is_format_patch"], parsed["adaptation_signals"], parsed["n_hunks"]
        )
        == "unknown"
    )


# ─── classify ───────────────────────────────────────────────────────────────


def test_classify_verbatim() -> None:
    assert hoc.classify(True, [], 1) == "likely-verbatim"


def test_classify_adaptation_via_signals() -> None:
    assert hoc.classify(True, ["backport"], 1) == "likely-adaptation"


def test_classify_adaptation_via_missing_format_header() -> None:
    assert hoc.classify(False, [], 1) == "likely-adaptation"


def test_classify_unknown_when_no_hunks() -> None:
    assert hoc.classify(False, [], 0) == "unknown"


# ─── derive_package_name / parse_pinned_version ────────────────────────────


def test_derive_package_name_by_name(tmp_path: Path) -> None:
    nixpkgs_dir = _build_fake_nixpkgs(tmp_path)
    patch_path = nixpkgs_dir / "pkgs" / "by-name" / "jq" / "jq" / "CVE-2026-32316.patch"
    pkgs_root = nixpkgs_dir / "pkgs"
    assert hoc.derive_package_name(patch_path, nixpkgs_dir, pkgs_root) == "jq"


def test_derive_package_name_ancestor_default_nix(tmp_path: Path) -> None:
    nixpkgs_dir = _build_fake_nixpkgs(tmp_path)
    patch_path = nixpkgs_dir / "pkgs" / "development" / "big" / "CVE-2026-99999.patch"
    pkgs_root = nixpkgs_dir / "pkgs"
    assert hoc.derive_package_name(patch_path, nixpkgs_dir, pkgs_root) == "big"


def test_derive_package_name_fallback_to_parent_dir(tmp_path: Path) -> None:
    nixpkgs_dir = _build_fake_nixpkgs(tmp_path)
    # a patch with no package.nix/default.nix anywhere above it
    orphan_dir = nixpkgs_dir / "pkgs" / "misc" / "orphan-pkg"
    orphan_dir.mkdir(parents=True)
    (orphan_dir / "CVE-2020-00001.patch").write_text(DOUBLE_CVE_PATCH)
    pkgs_root = nixpkgs_dir / "pkgs"
    patch_path = orphan_dir / "CVE-2020-00001.patch"
    assert hoc.derive_package_name(patch_path, nixpkgs_dir, pkgs_root) == "orphan-pkg"


def test_parse_pinned_version_found(tmp_path: Path) -> None:
    nixpkgs_dir = _build_fake_nixpkgs(tmp_path)
    pkgs_root = nixpkgs_dir / "pkgs"
    patch_path = (
        nixpkgs_dir
        / "pkgs"
        / "by-name"
        / "ma"
        / "maxima"
        / "5.47.0-CVE-2024-34490.patch"
    )
    anchor = hoc.find_anchor_dir(patch_path, pkgs_root)
    assert hoc.parse_pinned_version(anchor) == "5.47.0"


def test_parse_pinned_version_none_when_no_anchor() -> None:
    assert hoc.parse_pinned_version(None) is None


# ─── harvest / ranking ──────────────────────────────────────────────────────


def test_harvest_returns_all_candidates(tmp_path: Path) -> None:
    nixpkgs_dir = _build_fake_nixpkgs(tmp_path)
    candidates = hoc.harvest(nixpkgs_dir)
    assert len(candidates) == 4
    all_ids = {cve for c in candidates for cve in c["cve_ids"]}
    assert "CVE-2026-32316" in all_ids
    assert "CVE-2024-34490" in all_ids
    assert "CVE-2026-40355" in all_ids
    assert "CVE-2026-40356" in all_ids


def test_harvest_double_cve_filename_captures_both(tmp_path: Path) -> None:
    nixpkgs_dir = _build_fake_nixpkgs(tmp_path)
    candidates = hoc.harvest(nixpkgs_dir)
    krb5 = next(c for c in candidates if c["package"] == "krb5")
    assert krb5["cve_ids"] == ["CVE-2026-40355", "CVE-2026-40356"]


def test_harvest_ranks_small_adaptation_above_verbatim(tmp_path: Path) -> None:
    nixpkgs_dir = _build_fake_nixpkgs(tmp_path)
    candidates = hoc.harvest(nixpkgs_dir)
    by_pkg = {c["package"]: c for c in candidates}

    maxima = by_pkg["maxima"]
    jq = by_pkg["jq"]
    big = by_pkg["big"]

    assert maxima["classification"] == "likely-adaptation"
    assert jq["classification"] == "likely-verbatim"
    assert big["classification"] == "likely-verbatim"

    assert maxima["rank_score"] > jq["rank_score"]
    assert maxima["rank_score"] > big["rank_score"]

    # verbatim ranking: small single-file verbatim still beats large
    # multi-file verbatim (both classification 0, but size penalty differs)
    assert jq["rank_score"] > big["rank_score"]


def test_harvest_all_fixture_patches_are_wired(tmp_path: Path) -> None:
    nixpkgs_dir = _build_fake_nixpkgs(tmp_path)
    candidates = hoc.harvest(nixpkgs_dir)
    assert all(c["wired"] for c in candidates)


def test_patch_is_wired_true_when_referenced(tmp_path: Path) -> None:
    nixpkgs_dir = _build_fake_nixpkgs(tmp_path)
    maxima_dir = nixpkgs_dir / "pkgs" / "by-name" / "ma" / "maxima"
    patch = maxima_dir / "5.47.0-CVE-2024-34490.patch"
    assert hoc.patch_is_wired(patch, maxima_dir) is True


def test_patch_is_wired_false_when_orphaned(tmp_path: Path) -> None:
    nixpkgs_dir = _build_fake_nixpkgs(tmp_path)
    # drop an orphaned patch into maxima that no .nix references
    maxima_dir = nixpkgs_dir / "pkgs" / "by-name" / "ma" / "maxima"
    orphan = maxima_dir / "CVE-2099-00001-orphan.patch"
    orphan.write_text(ADAPTED_PATCH)
    assert hoc.patch_is_wired(orphan, maxima_dir) is False


def test_patch_is_wired_false_when_no_anchor() -> None:
    assert hoc.patch_is_wired(Path("/nope/x.patch"), None) is False


def test_harvest_unwired_patch_sinks_below_wired(tmp_path: Path) -> None:
    # an orphaned small adaptation (would otherwise rank near the top) must
    # sink below every wired candidate — no derivation applies it, so it has
    # no pinned base to adjudicate against and cannot be an oracle.
    nixpkgs_dir = _build_fake_nixpkgs(tmp_path)
    orphan_dir = nixpkgs_dir / "pkgs" / "by-name" / "or" / "orphanpkg"
    orphan_dir.mkdir(parents=True)
    # package.nix that does NOT reference the patch
    (orphan_dir / "package.nix").write_text('{ }: {\n  version = "1.0";\n}\n')
    (orphan_dir / "CVE-2099-12345.patch").write_text(ADAPTED_PATCH)

    candidates = hoc.harvest(nixpkgs_dir)
    orphan = next(c for c in candidates if c["package"] == "orphanpkg")
    assert orphan["wired"] is False
    assert orphan["classification"] == "likely-adaptation"
    wired = [c for c in candidates if c["wired"]]
    assert wired, "fixture should have wired candidates"
    assert orphan["rank_score"] < min(c["rank_score"] for c in wired)
    # it is still listed, not dropped
    assert orphan in candidates


def test_header_reports_wired_counts(tmp_path: Path) -> None:
    nixpkgs_dir = _build_fake_nixpkgs(tmp_path)
    candidates = hoc.harvest(nixpkgs_dir)
    header = hoc.build_header(nixpkgs_dir, candidates)
    assert header["wired_count"] == 4
    assert header["unwired_count"] == 0


def test_harvest_is_sorted_best_first(tmp_path: Path) -> None:
    nixpkgs_dir = _build_fake_nixpkgs(tmp_path)
    candidates = hoc.harvest(nixpkgs_dir)
    scores = [c["rank_score"] for c in candidates]
    assert scores == sorted(scores, reverse=True)


def test_harvest_limit_truncates(tmp_path: Path) -> None:
    nixpkgs_dir = _build_fake_nixpkgs(tmp_path)
    candidates = hoc.harvest(nixpkgs_dir, limit=2)
    assert len(candidates) == 2


def test_patch_sha256_matches_bytes(tmp_path: Path) -> None:
    nixpkgs_dir = _build_fake_nixpkgs(tmp_path)
    candidates = hoc.harvest(nixpkgs_dir)
    maxima = next(c for c in candidates if c["package"] == "maxima")
    patch_path = nixpkgs_dir / maxima["patch_path"]
    assert maxima["patch_sha256"] == hoc.sha256_hex(patch_path.read_bytes())


def test_patch_path_is_relative_posix(tmp_path: Path) -> None:
    nixpkgs_dir = _build_fake_nixpkgs(tmp_path)
    candidates = hoc.harvest(nixpkgs_dir)
    for c in candidates:
        assert not c["patch_path"].startswith("/")
        assert c["patch_path"].startswith("pkgs/")


# ─── manifest write / round-trip ────────────────────────────────────────────


def test_write_manifest_round_trips(tmp_path: Path) -> None:
    nixpkgs_dir = _build_fake_nixpkgs(tmp_path)
    candidates = hoc.harvest(nixpkgs_dir)
    header = hoc.build_header(nixpkgs_dir, candidates)

    out_dir = tmp_path / "reports"
    jsonl_path, md_path = hoc.write_manifest(out_dir, header, candidates)

    assert jsonl_path.is_file()
    assert md_path.is_file()

    lines = jsonl_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1 + len(candidates)

    header_obj = json.loads(lines[0])
    assert header_obj["kind"] == "harvest-header"
    assert header_obj["total_patches_scanned"] == 4
    assert header_obj["nixpkgs_ref"] == nixpkgs_dir.name

    body_objs = [json.loads(l) for l in lines[1:]]
    for obj in body_objs:
        assert obj["kind"] == "oracle-candidate"

    # ranking order preserved on disk
    scores = [obj["rank_score"] for obj in body_objs]
    assert scores == sorted(scores, reverse=True)

    md_text = md_path.read_text(encoding="utf-8")
    assert "Adaptation-oracle candidates" in md_text
    assert "likely-adaptation" in md_text


def test_write_manifest_classification_counts(tmp_path: Path) -> None:
    nixpkgs_dir = _build_fake_nixpkgs(tmp_path)
    candidates = hoc.harvest(nixpkgs_dir)
    header = hoc.build_header(nixpkgs_dir, candidates)
    counts = header["classification_counts"]
    assert counts["likely-verbatim"] == 2  # jq, big
    assert counts["likely-adaptation"] == 2  # maxima, krb5(double-cve/backport)
    assert sum(counts.values()) == 4


def test_main_writes_files_and_returns_zero(tmp_path: Path) -> None:
    nixpkgs_dir = _build_fake_nixpkgs(tmp_path)
    out_dir = tmp_path / "out"
    rc = hoc.main(
        [
            "harvest_oracle_candidates.py",
            "--nixpkgs",
            str(nixpkgs_dir),
            "--out",
            str(out_dir),
        ]
    )
    assert rc == 0
    assert (out_dir / "oracle-candidates.jsonl").is_file()
    assert (out_dir / "oracle-candidates.md").is_file()


# --- regression: signals must not come from commit trailers ----------------
#
# skypilot CVE-2026-13482 is a clean `git format-patch` cherry-pick whose
# commit message carries `Co-Authored-By: Claude Opus 4.8 (1M context)`. The
# old bare-word "context" signal fired on that trailer and promoted the patch
# into `likely-adaptation`, where a human would have wasted an adjudication
# pass on a verbatim copy.


def test_co_authored_by_trailer_does_not_manufacture_a_signal():
    header = (
        "[PATCH] mark non-security hashes\n"
        "\n"
        "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>\n"
    )
    assert hoc._find_adaptation_signals(header) == []


def test_other_trailers_are_stripped_too():
    header = "fix overflow\n\nSigned-off-by: A Maintainer (rebased tree) <a@b.c>\n"
    assert hoc._find_adaptation_signals(header) == []


def test_bare_context_word_is_not_a_signal():
    # Prose mentioning "context" in passing is not a claim of adaptation.
    assert hoc._find_adaptation_signals("resets the security context\n") == []


def test_context_phrase_is_a_signal():
    for header in (
        "backport with context lines adjusted\n",
        "adjusted the context to apply here\n",
        "refreshed context lines\n",
    ):
        signals = hoc._find_adaptation_signals(header)
        assert any(s.startswith("context-phrase:") for s in signals), header


def test_real_adaptation_header_still_detected():
    # python-multipart CVE-2026-40347-part-2: the shape an oracle needs.
    header = (
        "Based on upstream d4452a78bbde94995dd3c0d1b4aff3610a5c472f, adjusted\n"
        "to apply to 0.0.22\n"
    )
    signals = hoc._find_adaptation_signals(header)
    assert any(s.startswith("version-target:") for s in signals), signals


# --- regression: live_at_ref must survive package relocation ---------------
#
# A history entry records the path at FIRST ADD. nixpkgs relocates packages
# constantly (the by-name migration moved thousands), so comparing full paths
# marked the registered maxima oracle as deleted: added under
# pkgs/applications/science/math/maxima/, now at pkgs/by-name/ma/maxima/.


def test_live_at_ref_matches_across_a_package_move(monkeypatch, tmp_path):
    moved_old = "pkgs/applications/science/math/maxima/5.47.0-CVE-2024-34490.patch"
    moved_new = "pkgs/by-name/ma/maxima/5.47.0-CVE-2024-34490.patch"

    def fake_git(repo, *args):
        if args[0] == "ls-tree":
            return (moved_new + "\n").encode()
        if args[0] == "show":
            target = args[1]
            if target.endswith(".patch"):
                return b"--- a/f\n+++ b/f\n@@ -1 +1 @@\n-a\n+b\n"
            return b'version = "5.47.0";\n'
        return b""

    monkeypatch.setattr(hoc, "_git", fake_git)
    entry = {"path": moved_old, "commit": "0" * 40, "date": "2024-01-01T00:00:00Z"}
    live = {Path(moved_new).name}
    cand = hoc.build_candidate_from_history(tmp_path, entry, live)
    assert cand is not None
    assert cand["live_at_ref"] is True, "relocated patch must still count as live"


# --- payload verification against upstream ---------------------------------
#
# Codifies the 2026-08-09 lesson: header wording is not admissible; a
# maintainer patch is a genuine adaptation only if its PAYLOAD differs from the
# named upstream commit. Real regressions from that pass are pinned below.

_UP = """From abc Mon Sep 17 00:00:00 2001
Subject: [PATCH] fix overflow

diff --git a/f.c b/f.c
index 111..222 100644
--- a/f.c
+++ b/f.c
@@ -10,3 +10,3 @@ void f(void)
-  int n = read_len();
+  size_t n = read_len();
   use(n);
"""


def test_verbatim_copy_detected_despite_different_headers_and_offsets():
    # Same payload, but a different apply location, index line, and a
    # maintainer header claiming adaptation. Must still read as a copy.
    maint = """Adapted by a maintainer to apply without <commit>.

Index: old/sub/f.c
--- a/sub/f.c
+++ b/sub/f.c
@@ -812,3 +812,3 @@
-  int n = read_len();
+  size_t n = read_len();
   use(n);
"""
    r = hoc.verify_against_upstream(maint, _UP)
    assert r["verdict"] == "verbatim-copy"
    assert r["identical"] is True
    assert r["overlap"] == 1.0


def test_genuine_adaptation_detected():
    # A different fix shape (hand-expanded), low payload overlap.
    maint = """Based on upstream abc, adapted for the 1.x tree.

--- a/f.c
+++ b/f.c
@@ -10,3 +10,4 @@
-  int n = read_len();
+  unsigned long n = read_len();
+  if (n > CAP) return -1;
   use(n);
"""
    r = hoc.verify_against_upstream(maint, _UP)
    assert r["verdict"] == "genuine-adaptation"
    assert r["identical"] is False
    assert r["overlap"] < hoc.PROVENANCE_REVIEW_OVERLAP


def test_provenance_ambiguous_when_overlap_is_very_high():
    # Payload nearly identical — one extra line against a large shared base, so
    # overlap stays high. Could be a branch variant or a squash, so flag for
    # provenance review rather than trusting it as an adaptation.
    shared = "".join(f"+  a{i} = f{i}();\n" for i in range(20))
    up = f"--- a/f.c\n+++ b/f.c\n@@ -1,20 +1,20 @@\n{shared}"
    maint = f"Based on abc, minor adjust.\n--- a/f.c\n+++ b/f.c\n@@ -1,20 +1,21 @@\n{shared}+  extra = g();\n"
    r = hoc.verify_against_upstream(maint, up)
    assert r["verdict"] == "provenance-ambiguous", r
    assert r["overlap"] >= hoc.PROVENANCE_REVIEW_OVERLAP
    assert r["identical"] is False


def test_context_only_change_is_not_a_payload_difference():
    # The maintainer touched only a surrounding context line. Payload is
    # unchanged, so this is a verbatim copy for adjudication purposes.
    maint = _UP.replace("   use(n);", "   use_v2(n); /* renamed in 1.x */")
    r = hoc.verify_against_upstream(maint, _UP)
    assert r["verdict"] == "verbatim-copy"


def test_format_patch_signature_is_not_a_removed_line():
    with_sig = _UP + "-- \n2.39.1\n"
    r = hoc.verify_against_upstream(with_sig, _UP)
    assert r["verdict"] == "verbatim-copy", r


def test_empty_when_a_side_has_no_payload():
    r = hoc.verify_against_upstream("just a prose note, no diff\n", _UP)
    assert r["verdict"] == "empty"


def test_verify_pair_cli(tmp_path, capsys):
    import json as _json

    a = tmp_path / "maint.patch"
    b = tmp_path / "up.patch"
    a.write_text(_UP)
    b.write_text(_UP)
    rc = hoc.main(["prog", "--verify-pair", str(a), str(b)])
    assert rc == 0
    out = _json.loads(capsys.readouterr().out)
    assert out["verdict"] == "verbatim-copy"
    assert out["maintainer_patch"] == str(a)
