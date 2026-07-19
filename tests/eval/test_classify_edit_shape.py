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
