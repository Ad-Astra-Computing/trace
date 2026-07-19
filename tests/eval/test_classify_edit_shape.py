"""Unit tests for the edit-shape classifier (fold vs clip vs security-guard-add)."""
from eval.classify_edit_shape import classify_diff


def _diff(body: str) -> str:
    return "--- a/f.c\n+++ b/f.c\n@@ -1,3 +1,3 @@\n" + body


def test_operator_refine_is_condition_fold():
    d = _diff("   ctx\n-    if (n > MAX)\n+    if (n >= MAX)\n   ctx2\n")
    r = classify_diff(d)
    assert r["shape"] == "condition-fold"
    assert r["subshape"] == "operator-refine"


def test_conjunct_add_is_condition_fold():
    d = _diff("-    if (state->head != Z_NULL)\n"
              "+    if (state->head != Z_NULL && len < state->head->extra_max)\n")
    r = classify_diff(d)
    assert r["shape"] == "condition-fold"
    assert r["subshape"] == "conjunct-add"


def test_bound_arith_fold():
    d = _diff("-    if (copy > have)\n+    if (copy > have - len)\n")
    r = classify_diff(d)
    assert r["shape"] == "condition-fold"
    assert r["subshape"] == "bound-arith-fold"


def test_guard_clip_is_not_fold():
    # a fresh guard block with a clamp body, no paired conditional removal
    d = _diff("     foo();\n+    if (len > MAX)\n+        len = MAX;\n     bar();\n")
    r = classify_diff(d)
    assert r["shape"] == "guard-clip"


def test_security_guard_add_raises():
    d = _diff("     key = load()\n+    if len(key) == 0:\n"
              "+        raise InvalidKeyError(\"key must not be empty\")\n     use(key)\n")
    r = classify_diff(d)
    assert r["shape"] == "security-guard-add"


def test_comment_only_addition_is_other():
    d = _diff("     foo()\n+    # a clarifying comment\n     bar()\n")
    r = classify_diff(d)
    assert r["shape"] == "other"


def test_empty_diff_is_other():
    assert classify_diff("")["shape"] == "other"


def test_same_operator_punctuation_change_is_not_fold():
    # Perl `open $_ or return` → `open '<', $_ or return`: the `or` is unchanged and the
    # only added token is a string/char literal — not a condition change.
    d = _diff("-        open FILE, $_ or return;\n+        open FILE, '<', $_ or return;\n")
    assert classify_diff(d)["shape"] == "other"


def test_operand_identifier_change_is_fold():
    # sqlite zA1 → zA2: same operator, but a real comparison OPERAND changed.
    d = _diff("-    if (sqlite3_stricmp(zA1, zB) == 0)\n"
              "+    if (sqlite3_stricmp(zA2, zB) == 0)\n")
    assert classify_diff(d)["shape"] == "condition-fold"


def test_comparison_inside_string_is_not_fold():
    d = _diff('-    char prompt[500] = "/ > ";\n+    char prompt[MAX] = "/ > ";\n')
    assert classify_diff(d)["shape"] == "other"
