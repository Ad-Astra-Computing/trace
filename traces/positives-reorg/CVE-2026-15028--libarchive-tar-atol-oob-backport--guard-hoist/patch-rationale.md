## Upstream reference

Upstream fix commit: https://github.com/libarchive/libarchive commit
`c16162083a247efd4a2bc71401489bec3090ae7c` ("tar: fix 1-byte OOB read in
number parsing (tar_atol_base_n)"), authored as
`f93abd161ec37326c566f4f0efcd44fe7a66dd95` on PR #3253. Release URL:
https://github.com/libarchive/libarchive/commit/c16162083a247efd4a2bc71401489bec3090ae7c.

This is a **semantic adaptation**, not a verbatim transcription: the
preflight `patch -p1` dry-run reported `applies_verbatim: false`
(`Hunk #1 FAILED at 3517`). The base divergence is that the upstream fix
uses the overflow-checked-arithmetic helpers `archive_ckd_mul_i64` and
`archive_ckd_add_i64`, which do not exist in the pinned libarchive 3.8.7
source (`tar_atol_base_n` in `source-context/` uses the older
`l > limit || (l == limit && digit >= last_digit_limit)` overflow idiom
with a `maxval` sentinel). The adaptation carries the same
security-relevant behavior — read each digit only while bytes remain —
using the pinned base's own overflow-check idiom.

## Why this version

Resolver authorized `patch_strategy = "source-backport"`
(`eligibility.verdict = eligible-requires-human-review`,
`human_review_trigger = source-backport-experimental`); no fixed release
of libarchive exists yet, so the version stays at 3.8.7 and the fix is
wired in as an in-tree patch. `src.url` and `src.hash` are unchanged.

## Why minimal

Two hunks, both required:

1. **`CVE-2026-15028.patch` (new file)** — the adapted upstream fix. It
   grounds strictly against the pinned source in
   `source-context/libarchive/archive_read_support_format_tar.c` lines
   containing `if (char_cnt != 0) { digit = *p - '0'; while (digit >= 0
   && digit < base  && char_cnt != 0) { if (l>limit || (l == limit &&
   digit >= last_digit_limit)) { return maxval; ... } l = (l * base) +
   digit; digit = *++p - '0'; char_cnt--; } }`. Every `-` (removed) line
   in the hunk matches those bytes verbatim (including the double space
   in `base  &&` and the `l>limit` spacing that the pinned source uses).
   The transformation converts the `if / inner while` into a single
   `while (char_cnt != 0)` that reads the digit, breaks on non-digit,
   checks overflow (using the base's existing `limit`/`last_digit_limit`
   idiom and returning `maxval`), accumulates, then advances `p` and
   decrements `char_cnt` — matching upstream's control flow exactly, with
   no `archive_ckd_*` helper introduced (they are absent from the pinned
   source; introducing them would violate the source-context grounding
   rule).
2. **`package.nix`** — add `patches = [ ./CVE-2026-15028.patch ];`. No
   `patches` list exists yet in the pinned expression, so this
   introduces one; nothing else in the file changes.

## Alternatives rejected

- **Verbatim transcription of the upstream fix** — rejected: the
  preflight dry-run failed (`Hunk #1 FAILED at 3517`) because the
  upstream context uses `archive_ckd_mul_i64`/`archive_ckd_add_i64`
  which are absent from libarchive 3.8.7. A verbatim patch would not
  apply, and even if forced, would reference undefined symbols.
- **Version bump to a tagged release containing the fix** — rejected:
  no such tagged release exists; the resolver authorized source-backport
  precisely because `current_version == target_version == 3.8.7`.
- **Introducing the `archive_ckd_*` helpers as part of this patch** —
  rejected: those helpers are not present in `source-context/`, so
  adding them would violate rule 9 (no symbols absent from the pinned
  source). The pinned base already provides an equivalent overflow-
  detection idiom (`l > limit || (l == limit && digit >= last_digit_limit)`);
  using it keeps the adaptation minimal and grounded.

## Downstream risk

`impact.json.reverse_closure_count = 6000`, bucket `>5000`,
`exceeds_threshold = true`. Critical downstreams named:
`cmake`, `systemd`, `samba` (with `kmod` also in the sample). This is a
very high-blast-radius rebuild; the patch is deliberately confined to a
single function (`tar_atol_base_n`) whose behavior on well-formed inputs
is unchanged (the digit-loop still terminates on non-digit or exhausted
count, still applies the same overflow ceiling, still returns the same
sign-adjusted value). The only observable change is that a numeric field
ending exactly at the caller-supplied boundary no longer performs a
1-byte read past the buffer. Maintainer: `jcumming`.
