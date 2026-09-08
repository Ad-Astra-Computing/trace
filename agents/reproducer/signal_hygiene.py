"""Detect an arm that emitted its SIGNAL without having run.

svgo CVE-2026-73650 (DECISIONS 2026-09-08) is the motivating case. The fixture
invoked `svgo --enable=removeScripts`, a flag svgo 4 does not have, so svgo
errored and wrote no output. The patched arm's predicate is the payload ABSENT,
`grep` over a file that was never created returns non-zero, the negation passed,
and the arm printed SIGNAL_PATCHED over a fixture that had never executed.

reproducer prompt v21 tells the model not to write that fixture. This module is
the control rather than the advice: it reads the build record the probe already
has and looks, in each arm that emitted its signal, for the marks a run leaves
when it did not happen. Two families, both narrow on purpose:

  * a predicate helper read a file that is not there (`grep: out.svg: No such
    file or directory`). Keyed on the coreutils-style `<tool>: <path>: ...` prefix,
    so a tool's own diagnostic about a deliberately absent fixture, or a traversal
    target the patched arm expects to be missing, does not match.
  * the program looks to have refused the invocation (`unknown option`,
    `usage: ...`, `command not found`).

Neither gates on its own, and that is deliberate. A healthy fixture may `cat` an
optional file that is not there, or print usage while still doing its work, or
carry either string from some other step of the build; refusing on one mark alone
would block real bundles. Together in the same arm they are the svgo signature:
the program refused the invocation AND the predicate then read the output it never
wrote. That pair gates. A lone mark is recorded and shown to the operator, who has
the log in front of them. The asymmetry is on purpose, since a false positive here
blocks honest work while a false negative only costs what we had before this
existed, which is nothing.

Only arms that emitted their SIGNAL are scanned. A failing arm's markers are
often the honest explanation of why it failed, and it is claiming nothing.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

# `grep: namespaced-out.svg: No such file or directory`, and friends. The tool
# name is anchored to a known reader so a message from the package under test
# does not match; the point is a PREDICATE that read nothing.
_MISSING_READ = re.compile(
    r"^\s*(grep|cat|head|tail|stat|wc|diff|cmp|sed|awk|od|xxd|cut|sort|"
    r"sha256sum|md5sum|readlink|realpath): [^\n]*: No such file or directory\s*$",
    re.MULTILINE,
)

_REFUSED_INVOCATION = (
    re.compile(r"\b(?:unknown|unrecognized|unrecognised|invalid|illegal) (?:option|flag)\b", re.IGNORECASE),
    re.compile(r"^\s*usage: ", re.IGNORECASE | re.MULTILINE),
    re.compile(r"\bcommand not found\b", re.IGNORECASE),
)


@dataclass(frozen=True)
class ArmMarks:
    """What one arm's output says about whether it ran."""

    missing_read: tuple[str, ...] = ()
    refused_invocation: tuple[str, ...] = ()
    truncated: bool = False

    def __bool__(self) -> bool:
        return bool(self.missing_read or self.refused_invocation)

    @property
    def damning(self) -> bool:
        """Enough to reject the arm.

        Both marks together is the svgo failure exactly: it refused the
        invocation, then its predicate read the output it never wrote. A
        missing read in a TRUNCATED log counts too, because the refusal
        happens at invocation and truncation keeps only the tail, so the
        corroborating mark may simply have been cut. Fail closed there and
        let the operator record an override if the log says otherwise.
        """
        return bool(self.missing_read and (self.refused_invocation or self.truncated))


def scan_arm(text: str, *, truncated: bool = False) -> ArmMarks:
    """Marks in one arm's captured output that it never ran."""
    if not text:
        return ArmMarks(truncated=truncated)
    missing_read = tuple(
        f"a predicate helper read a missing file: {m.group(0).strip()}"
        for m in _MISSING_READ.finditer(text)
    )
    refused: list[str] = []
    for pattern in _REFUSED_INVOCATION:
        m = pattern.search(text)
        if not m:
            continue
        line = next(
            (ln.strip() for ln in text.splitlines() if pattern.search(ln)),
            m.group(0).strip(),
        )
        refused.append(f"the program may have refused the invocation: {line}")
    return ArmMarks(
        missing_read=missing_read,
        refused_invocation=tuple(refused),
        truncated=truncated,
    )


def scan_build(build_json: dict, *, signals: dict[str, bool]) -> dict[str, ArmMarks]:
    """Marks per arm, for arms whose SIGNAL is present.

    `signals` maps arm name ("unpatched" / "patched") to whether that arm's
    SIGNAL substring was found. An arm that emitted nothing is claiming nothing,
    so it is not scanned.
    """
    out: dict[str, ArmMarks] = {}
    for arm, emitted in signals.items():
        if not emitted:
            continue
        section = build_json.get(arm)
        if not isinstance(section, dict):
            continue
        text = section.get("stdout_stderr") or ""
        marks = scan_arm(text, truncated=_looks_truncated(section, text))
        if marks:
            out[arm] = marks
    return out


def _looks_truncated(section: dict, text: str) -> bool:
    """Builder keeps the tail of a long arm and records the full log's digest.
    A digest that does not match the text we were given means we are reading a
    tail, and an early marker may have been cut."""
    recorded = section.get("stdout_stderr_log_sha256")
    if not isinstance(recorded, str) or not recorded:
        return False
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest() != recorded


def refuses(marks: dict[str, ArmMarks]) -> bool:
    """Whether these marks are enough to reject the fixture.

    Only when one arm carries both marks. See the module docstring for why a
    single mark is shown but not gated on.
    """
    return any(m.damning for m in marks.values())


def describe(marks: dict[str, ArmMarks]) -> str:
    """One line an operator can act on."""
    if not marks:
        return "no arm emitted its signal over a run that did not happen"
    parts = []
    for arm, m in sorted(marks.items()):
        detail = list(m.missing_read + m.refused_invocation)
        if m.truncated and m.missing_read and not m.refused_invocation:
            detail.append(
                "the arm's log is truncated, so a refusal at invocation may have been cut"
            )
        parts.append(f"{arm}: {'; '.join(detail)}")
    lead = (
        "signal emitted over a run that shows it never happened"
        if refuses(marks)
        else "advisory, one mark only, look at the arm's log before trusting its signal"
    )
    return lead + " -- " + " | ".join(parts)
