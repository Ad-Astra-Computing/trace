"""The rationale-binding gate: claims must cite lines the payload adds.

Written against the failure that motivated it. On the assimp CVE-2026-82591
adaptation canary the Patcher's rationale claimed a `mVertices.resize(...)`
trim, an index validation and a zero-count guard that its payload does not
contain, and the Reviewer accepted the bundle anyway. Every test here drives
`check_binding` / `check_bundle` rather than asserting on internal state.
"""

from __future__ import annotations

import pytest

from tools.trace_cli import rationale_binding as rb


NESTED_PATCH_DIFF = """\
diff --git a/pkgs/by-name/as/assimp/CVE-2026-82591.patch b/pkgs/by-name/as/assimp/CVE-2026-82591.patch
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/pkgs/by-name/as/assimp/CVE-2026-82591.patch
@@ -0,0 +1,12 @@
+--- a/code/AssetLib/MD5/MD5Loader.cpp
++++ b/code/AssetLib/MD5/MD5Loader.cpp
+@@ -60,6 +60,7 @@
+ #include <memory>
++#include <limits>
+ #include <vector>
+@@ -400,7 +401,9 @@
+     std::vector<aiVector3D> mVertices;
+-    mVertices.reserve(numOrigVerts);
++    if (numOrigVerts > std::numeric_limits<size_t>::max() / 3) {
++        throw DeadlyImportError("MD5: vertex count overflow");
++    }
diff --git a/pkgs/by-name/as/assimp/package.nix b/pkgs/by-name/as/assimp/package.nix
index 2222222..3333333 100644
--- a/pkgs/by-name/as/assimp/package.nix
+++ b/pkgs/by-name/as/assimp/package.nix
@@ -20,6 +20,7 @@
   patches = [
+    ./CVE-2026-82591.patch
   ];
"""

FLAT_PATCH_DIFF = """\
diff --git a/code/AssetLib/MD5/MD5Loader.cpp b/code/AssetLib/MD5/MD5Loader.cpp
index 4444444..5555555 100644
--- a/code/AssetLib/MD5/MD5Loader.cpp
+++ b/code/AssetLib/MD5/MD5Loader.cpp
@@ -60,6 +60,7 @@
 #include <memory>
+#include <limits>
 #include <vector>
"""


def _rationale(why_minimal: str) -> str:
    return (
        "## Upstream reference\nUpstream fix: https://example.invalid/commit/abc\n\n"
        "## Why this version\nSource-backport, no bump.\n\n"
        f"## Why minimal\n{why_minimal}\n\n"
        "## Alternatives rejected\n- Verbatim transcription — does not apply.\n"
        "- Version bump — not authorized.\n\n"
        "## Downstream risk\nreverse_closure_count == 0.\n"
    )


GOOD_CLAIMS = """\
- [CLAIM-1] Includes <limits> for the overflow guards.
  - Diff Line: `+#include <limits>`
- [CLAIM-2] Rejects a vertex count that would overflow when tripled.
  - Diff Line: `+    if (numOrigVerts > std::numeric_limits<size_t>::max() / 3) {`
  - Diff Line: `+        throw DeadlyImportError("MD5: vertex count overflow");`
"""


class TestBoundRationale:
    def test_every_claim_citing_a_real_added_line_is_bound(self):
        result = rb.check_binding(_rationale(GOOD_CLAIMS), NESTED_PATCH_DIFF)
        assert result.verdict == rb.VERDICT_BOUND
        assert result.ok
        assert result.problems == []
        assert [c.claim_id for c in result.claims] == [1, 2]
        assert all(c.bound for c in result.claims)

    def test_the_flat_payload_shape_binds_the_same_way(self):
        rationale = _rationale(
            "- [CLAIM-1] Includes <limits>.\n  - Diff Line: `+#include <limits>`\n"
        )
        result = rb.check_binding(rationale, FLAT_PATCH_DIFF)
        assert result.verdict == rb.VERDICT_BOUND

    def test_a_citation_written_without_the_plus_prefix_still_binds(self):
        rationale = _rationale(
            "- [CLAIM-1] Includes <limits>.\n  - Diff Line: `#include <limits>`\n"
        )
        result = rb.check_binding(rationale, NESTED_PATCH_DIFF)
        assert result.verdict == rb.VERDICT_BOUND
        assert result.claims[0].citations[0].match_kind == "exact"

    def test_a_citation_whose_indentation_drifted_binds_as_normalized(self):
        rationale = _rationale(
            "- [CLAIM-1] Guards the count.\n"
            "  - Diff Line: `+if (numOrigVerts > std::numeric_limits<size_t>::max() / 3) {`\n"
        )
        result = rb.check_binding(rationale, NESTED_PATCH_DIFF)
        assert result.verdict == rb.VERDICT_BOUND
        assert result.claims[0].citations[0].match_kind == "whitespace-normalized"


class TestUnboundRationale:
    def test_the_assimp_phantom_trim_claim_is_caught(self):
        """The claim that sank the canary: a trim the payload never makes."""
        rationale = _rationale(
            GOOD_CLAIMS + "- [CLAIM-3] Trims mVertices back to the real vertex count.\n"
            "  - Diff Line: `+    mVertices.resize(iNewIndex);`\n"
        )
        result = rb.check_binding(rationale, NESTED_PATCH_DIFF)
        assert result.verdict == rb.VERDICT_UNBOUND
        assert not result.ok
        assert not result.claims[2].bound
        assert any("mVertices.resize(iNewIndex)" in p for p in result.problems)

    def test_a_claim_with_no_citation_is_a_phantom_claim(self):
        rationale = _rationale(
            GOOD_CLAIMS + "- [CLAIM-3] Also validates every face index.\n"
        )
        result = rb.check_binding(rationale, NESTED_PATCH_DIFF)
        assert result.verdict == rb.VERDICT_UNBOUND
        assert any("carries no `Diff Line:` citation" in p for p in result.problems)

    def test_citing_a_context_line_does_not_count_as_a_change(self):
        rationale = _rationale(
            "- [CLAIM-1] Handles the vertex vector.\n"
            "  - Diff Line: `+    std::vector<aiVector3D> mVertices;`\n"
        )
        result = rb.check_binding(rationale, NESTED_PATCH_DIFF)
        assert result.verdict == rb.VERDICT_UNBOUND

    def test_citing_a_removed_line_does_not_count_as_a_change(self):
        rationale = _rationale(
            "- [CLAIM-1] Replaces the reserve call.\n"
            "  - Diff Line: `+    mVertices.reserve(numOrigVerts);`\n"
        )
        result = rb.check_binding(rationale, NESTED_PATCH_DIFF)
        assert result.verdict == rb.VERDICT_UNBOUND

    def test_citing_the_package_nix_wiring_is_not_a_source_change(self):
        """`package.nix` is recipe metadata, never applied by patchPhase."""
        rationale = _rationale(
            "- [CLAIM-1] Wires the patch in.\n"
            "  - Diff Line: `+    ./CVE-2026-82591.patch`\n"
        )
        result = rb.check_binding(rationale, NESTED_PATCH_DIFF)
        assert result.verdict == rb.VERDICT_UNBOUND
        assert any("cites the `package.nix` wiring" in p for p in result.problems)
        assert result.claims[0].citations[0].match_kind == "wiring"

    def test_wiring_and_absent_lines_are_told_apart_in_the_message(self):
        """An operator fixes these two differently, so they must read differently.

        A wiring citation means the claim is true but out of contract. An absent
        citation means the claim describes work the payload does not do.
        """
        rationale = _rationale(
            "- [CLAIM-1] Wires the patch in.\n"
            "  - Diff Line: `+    ./CVE-2026-82591.patch`\n"
            "- [CLAIM-2] Trims the vector back.\n"
            "  - Diff Line: `+    mVertices.resize(iNewIndex);`\n"
        )
        problems = rb.check_binding(rationale, NESTED_PATCH_DIFF).problems
        assert any("claim 1 cites the `package.nix` wiring" in p for p in problems)
        assert any("claim 2 cites a line the patch does not add" in p for p in problems)

    def test_flat_shape_wiring_is_diagnosed_the_same_way(self):
        flat = FLAT_PATCH_DIFF + (
            "diff --git a/pkgs/by-name/as/assimp/package.nix"
            " b/pkgs/by-name/as/assimp/package.nix\n"
            "index 2222222..3333333 100644\n"
            "--- a/pkgs/by-name/as/assimp/package.nix\n"
            "+++ b/pkgs/by-name/as/assimp/package.nix\n"
            "@@ -20,6 +20,7 @@\n"
            "   patches = [\n"
            "+    ./CVE-2026-82591.patch\n"
            "   ];\n"
        )
        rationale = _rationale(
            "- [CLAIM-1] Wires the patch in.\n"
            "  - Diff Line: `+    ./CVE-2026-82591.patch`\n"
        )
        result = rb.check_binding(rationale, flat)
        assert result.verdict == rb.VERDICT_UNBOUND
        assert any("cites the `package.nix` wiring" in p for p in result.problems)

    def test_a_timestamped_file_header_still_reads_as_package_nix(self):
        """`diff -u` writes `+++ path\tTIMESTAMP`, which is a valid header."""
        stamped = NESTED_PATCH_DIFF.replace(
            "+++ b/pkgs/by-name/as/assimp/package.nix",
            "+++ b/pkgs/by-name/as/assimp/package.nix\t2026-09-09 12:00:00.000000000 +0000",
        )
        rationale = _rationale(
            "- [CLAIM-1] Wires the patch in.\n"
            "  - Diff Line: `+    ./CVE-2026-82591.patch`\n"
        )
        result = rb.check_binding(rationale, stamped)
        assert result.verdict == rb.VERDICT_UNBOUND
        assert any("cites the `package.nix` wiring" in p for p in result.problems)

    def test_a_payload_with_no_source_patch_at_all_is_unbound(self):
        only_wiring = NESTED_PATCH_DIFF.split(
            "diff --git a/pkgs/by-name/as/assimp/package.nix"
        )[1]
        only_wiring = "diff --git a/pkgs/by-name/as/assimp/package.nix" + only_wiring
        result = rb.check_binding(_rationale(GOOD_CLAIMS), only_wiring)
        assert result.verdict == rb.VERDICT_UNBOUND
        assert any("no extractable source patch" in p for p in result.problems)


class TestPayloadParsing:
    """The added-line set is read hunk-aware, not by prefix."""

    PRE_INCREMENT = (
        "diff --git a/src/file.c b/src/file.c\n"
        "--- a/src/file.c\n"
        "+++ b/src/file.c\n"
        "@@ -1,2 +1,3 @@\n"
        " int a;\n"
        "+++index;\n"
        " int b;\n"
    )

    def test_an_added_line_that_starts_with_plus_plus_is_citable(self):
        """`++index;` at column zero renders as `+++index;` in a diff."""
        rationale = _rationale(
            "- [CLAIM-1] Advances the index.\n  - Diff Line: `+++index;`\n"
        )
        result = rb.check_binding(rationale, self.PRE_INCREMENT)
        assert result.verdict == rb.VERDICT_BOUND

    def test_the_file_header_path_is_not_an_added_line(self):
        rationale = _rationale(
            "- [CLAIM-1] Touches the file.\n  - Diff Line: `+ b/src/file.c`\n"
        )
        assert (
            rb.check_binding(rationale, self.PRE_INCREMENT).verdict
            == rb.VERDICT_UNBOUND
        )


class TestMalformedClaimList:
    def test_duplicate_claim_ids_are_refused(self):
        rationale = _rationale(
            "- [CLAIM-1] One.\n  - Diff Line: `+#include <limits>`\n"
            "- [CLAIM-1] Two.\n  - Diff Line: `+#include <limits>`\n"
        )
        result = rb.check_binding(rationale, NESTED_PATCH_DIFF)
        assert result.verdict == rb.VERDICT_UNBOUND
        assert any("duplicate claim ids" in p for p in result.problems)

    def test_claim_ids_out_of_order_are_refused(self):
        rationale = _rationale(
            "- [CLAIM-2] One.\n  - Diff Line: `+#include <limits>`\n"
            "- [CLAIM-3] Two.\n  - Diff Line: `+#include <limits>`\n"
        )
        result = rb.check_binding(rationale, NESTED_PATCH_DIFF)
        assert result.verdict == rb.VERDICT_UNBOUND
        assert any("1..N in order" in p for p in result.problems)

    def test_a_citation_before_any_claim_is_refused(self):
        with pytest.raises(rb.RationaleBindingError):
            rb.parse_claims(_rationale("  - Diff Line: `+#include <limits>`\n"))


class TestNotApplicable:
    def test_a_legacy_prose_rationale_is_not_applicable(self):
        """Every corpus bundle predates v5; the gate does not reach back."""
        rationale = _rationale(
            "Two bundle-level changes only: one new patch file and one edit to\n"
            "`package.nix` appending it to the existing `patches` list.\n"
        )
        result = rb.check_binding(rationale, NESTED_PATCH_DIFF)
        assert result.verdict == rb.VERDICT_NOT_APPLICABLE
        assert result.ok
        assert result.claims == []

    def test_a_rationale_with_no_why_minimal_section_is_not_applicable(self):
        result = rb.check_binding("## Upstream reference\nabc\n", NESTED_PATCH_DIFF)
        assert result.verdict == rb.VERDICT_NOT_APPLICABLE

    def test_claims_are_read_only_from_why_minimal(self):
        rationale = (
            "## Why minimal\nPlain prose.\n\n"
            "## Downstream risk\n- [CLAIM-1] Not a claim here.\n"
        )
        result = rb.check_binding(rationale, NESTED_PATCH_DIFF)
        assert result.verdict == rb.VERDICT_NOT_APPLICABLE


class TestCoverageIsRecordedNotGated:
    def test_added_lines_no_claim_cites_are_recorded_without_failing(self):
        rationale = _rationale(
            "- [CLAIM-1] Includes <limits>.\n  - Diff Line: `+#include <limits>`\n"
        )
        result = rb.check_binding(rationale, NESTED_PATCH_DIFF)
        assert result.verdict == rb.VERDICT_BOUND
        assert any("numeric_limits" in line for line in result.uncited_added_lines)

    def test_the_uncited_remainder_is_syntax_not_behavior(self):
        """Why coverage does not gate: a closing brace is an added line too."""
        result = rb.check_binding(_rationale(GOOD_CLAIMS), NESTED_PATCH_DIFF)
        assert result.verdict == rb.VERDICT_BOUND
        assert [line.strip() for line in result.uncited_added_lines] == ["}"]


class TestBundleOnDisk:
    def test_a_bundle_binds_from_its_files(self, tmp_path):
        (tmp_path / "patch-rationale.md").write_text(_rationale(GOOD_CLAIMS))
        (tmp_path / "patch.diff").write_text(NESTED_PATCH_DIFF)
        assert rb.check_bundle(tmp_path).verdict == rb.VERDICT_BOUND

    def test_a_refusal_bundle_has_no_claim_to_bind(self, tmp_path):
        assert rb.check_bundle(tmp_path).verdict == rb.VERDICT_NOT_APPLICABLE

    def test_the_serialized_record_carries_the_verdict_and_problems(self, tmp_path):
        (tmp_path / "patch-rationale.md").write_text(
            _rationale(
                "- [CLAIM-1] Trims the vector.\n  - Diff Line: `+    mVertices.resize(iNewIndex);`\n"
            )
        )
        (tmp_path / "patch.diff").write_text(NESTED_PATCH_DIFF)
        d = rb.check_bundle(tmp_path).to_dict()
        assert d["schema_version"] == rb.SCHEMA_VERSION
        assert d["verdict"] == rb.VERDICT_UNBOUND
        assert d["claims"][0]["bound"] is False
        assert d["claims"][0]["citations"][0]["match_kind"] == "none"
        assert d["problems"]


class TestSubcommand:
    """`trace bundle rationale-binding` — the way anyone recomputes the verdict.

    The check writes nothing into the bundle: it is re-derivable at any time
    from `patch-rationale.md` and `patch.diff`, both of which the manifest
    already covers, so there is no third artifact to keep honest.
    """

    @staticmethod
    def _bundle(tmp_path, why_minimal):
        (tmp_path / "patch-rationale.md").write_text(_rationale(why_minimal))
        (tmp_path / "patch.diff").write_text(NESTED_PATCH_DIFF)
        return tmp_path

    def test_a_bound_rationale_exits_zero(self, tmp_path, capsys):
        from tools.trace_cli.cli import main

        code = main(
            ["bundle", "rationale-binding", str(self._bundle(tmp_path, GOOD_CLAIMS))]
        )
        assert code == rb.EXIT_OK
        assert "bound" in capsys.readouterr().out

    def test_an_unbound_rationale_exits_non_zero_and_names_the_claim(
        self, tmp_path, capsys
    ):
        from tools.trace_cli.cli import main

        bundle = self._bundle(
            tmp_path,
            "- [CLAIM-1] Trims the vector.\n  - Diff Line: `+    mVertices.resize(iNewIndex);`\n",
        )
        code = main(["bundle", "rationale-binding", str(bundle)])
        assert code == rb.EXIT_UNBOUND
        captured = capsys.readouterr()
        assert "UNBOUND" in captured.out
        assert "mVertices.resize(iNewIndex)" in captured.err

    def test_the_json_form_emits_the_full_record(self, tmp_path, capsys):
        import json

        from tools.trace_cli.cli import main

        code = main(
            [
                "bundle",
                "rationale-binding",
                "--json",
                str(self._bundle(tmp_path, GOOD_CLAIMS)),
            ]
        )
        assert code == rb.EXIT_OK
        doc = json.loads(capsys.readouterr().out)
        assert doc["verdict"] == rb.VERDICT_BOUND
        assert len(doc["claims"]) == 2

    def test_a_missing_directory_is_a_usage_error(self, tmp_path):
        from tools.trace_cli.cli import main

        assert (
            main(["bundle", "rationale-binding", str(tmp_path / "nope")])
            == rb.EXIT_USAGE
        )


class TestLegacyCompatibilityIsKeyedOnThePrompt:
    """A v5 Patcher must not escape the gate by writing prose.

    Compatibility for the corpus is real — every signed bundle predates the
    claim contract — but it is keyed on the prompt the bundle's own replay
    record names, so it cannot be inherited by a run that contracted for
    claims and did not write them.
    """

    @staticmethod
    def _bundle(tmp_path, prompt_path, why_minimal):
        import json

        (tmp_path / "patch-rationale.md").write_text(_rationale(why_minimal))
        (tmp_path / "patch.diff").write_text(NESTED_PATCH_DIFF)
        if prompt_path is not None:
            (tmp_path / "replay.json").write_text(
                json.dumps(
                    {
                        "roles": [
                            {
                                "role": "patcher",
                                "invocations": [
                                    {
                                        "prompt": {
                                            "path": prompt_path,
                                            "sha256": "0" * 64,
                                        }
                                    }
                                ],
                            }
                        ],
                    }
                )
            )
        return tmp_path

    PROSE = "Two bundle-level changes only: a new patch file and the wiring.\n"

    def test_a_v5_rationale_with_no_claim_list_is_unbound(self, tmp_path):
        bundle = self._bundle(tmp_path, "prompts/patcher.v5.md", self.PROSE)
        result = rb.check_bundle(bundle)
        assert result.verdict == rb.VERDICT_UNBOUND
        assert any("contracts for a" in p for p in result.problems)

    def test_a_v4_rationale_with_no_claim_list_stays_not_applicable(self, tmp_path):
        bundle = self._bundle(tmp_path, "prompts/patcher.v4.md", self.PROSE)
        assert rb.check_bundle(bundle).verdict == rb.VERDICT_NOT_APPLICABLE

    def test_a_bundle_with_no_replay_record_stays_not_applicable(self, tmp_path):
        bundle = self._bundle(tmp_path, None, self.PROSE)
        assert rb.check_bundle(bundle).verdict == rb.VERDICT_NOT_APPLICABLE

    def test_a_v5_rationale_that_does_carry_claims_binds(self, tmp_path):
        bundle = self._bundle(tmp_path, "prompts/patcher.v5.md", GOOD_CLAIMS)
        assert rb.check_bundle(bundle).verdict == rb.VERDICT_BOUND

    def test_the_last_patcher_invocation_is_the_one_that_counts(self, tmp_path):
        """A bundle re-run on v5 after a v4 attempt is held to the v5 contract."""
        import json

        bundle = self._bundle(tmp_path, "prompts/patcher.v4.md", self.PROSE)
        (bundle / "replay.json").write_text(
            json.dumps(
                {
                    "roles": [
                        {
                            "role": "patcher",
                            "invocations": [
                                {
                                    "prompt": {
                                        "path": "prompts/patcher.v4.md",
                                        "sha256": "0" * 64,
                                    }
                                },
                                {
                                    "prompt": {
                                        "path": "prompts/patcher.v5.md",
                                        "sha256": "1" * 64,
                                    }
                                },
                            ],
                        }
                    ],
                }
            )
        )
        assert rb.check_bundle(bundle).verdict == rb.VERDICT_UNBOUND

    def test_an_unreadable_replay_record_does_not_crash_the_gate(self, tmp_path):
        bundle = self._bundle(tmp_path, "prompts/patcher.v5.md", GOOD_CLAIMS)
        (bundle / "replay.json").write_text("{not json")
        assert rb.check_bundle(bundle).verdict == rb.VERDICT_BOUND

    def test_the_adaptation_lane_prompt_is_the_one_that_contracts_for_claims(self):
        from tools.trace_cli.execute import PATCHER_PROMPT_PATH_ADAPT

        assert f"prompts/{PATCHER_PROMPT_PATH_ADAPT.name}" in rb.CLAIM_REQUIRING_PROMPTS
