# RFC 0002 — Agent-grade findings: confidence + assertion level on stored & exported findings

- **Status:** Draft PR **with a working reference implementation** (this branch). Two follow-ups
  (provenance, ATT&CK technique) left as open questions.
- **Touches:** `issen-timeline` (`FindingRow`, `scan_findings` schema, insert/query),
  `issen-cli` (`timeline --flagged --format json` export, `scanning.rs` converters)
- **Motivated by:** DFIR field reflex — *attribution is the highest-hallucination-risk step in IR; carry
  explicit confidence and derivation, never a bare label.*

## Problem (corrected from the first draft)

An LLM consuming `issen timeline --flagged --format json` gets, per finding, only
`severity / rule_name / description / matched_indicator / tags`. There is **no confidence and no
derivation level** in the stored `scan_findings` schema or the JSON envelope. So an agent cannot tell a
directly-observed YARA hit from a low-certainty inferred framework attribution — exactly the input that
produces over-confident attribution.

> **Correction vs the first draft of this RFC (caught in different-lineage review):** I originally framed
> this as "the confidence `issen_correlation::model::Finding` already computes is *dropped* at
> `scanning.rs`." That is inaccurate — `scanning.rs` converts `issen_signatures::ScanFinding` (which has
> no confidence field), a **different lineage** from correlation `Finding`. The honest statement is
> narrower and is what this PR fixes: **the scan-findings storage + export path has no confidence/
> assertion columns at all.** Correlation's `confidence: u8` / `AssertionLevel { Observed, Correlated,
> Inferred }` is the *vocabulary this PR mirrors*, and wiring correlation-derived findings into these new
> columns is the natural follow-up (see open questions) — not something silently lost today.

## What this PR does (the actual diff)

Additive and nullable throughout — `None`/`NULL` is first-class, never a fabricated default.

1. `issen_timeline::findings::FindingRow` gains `confidence: Option<u8>` and
   `assertion_level: Option<String>`.
2. `scan_findings` gains the columns via `ALTER TABLE … ADD COLUMN IF NOT EXISTS` (same path upgrades
   databases created before the columns existed). `insert_findings` (staging temp table + Appender +
   `INSERT…SELECT`) and `query_findings` (both SELECT lists + row mapping) carry them.
3. `timeline --flagged --format json` (`show_flagged_json`) emits `confidence` and `assertion_level`
   (`null` when absent).
4. The existing signature/timestomp converters set them to `None` (a raw IOC hit has no calibrated
   score — honest NULL), with a comment marking correlation-population as follow-up.
5. Tests: a round-trip test asserting `Some(35)/"inferred"` and `None/None` both survive storage→query
   (NULL must not collapse to a default).

```rust
pub struct FindingRow {
    // … existing fields …
    pub confidence: Option<u8>,
    pub assertion_level: Option<String>,
}
```

```json
{ "rule_name": "registry_resident_ps_stager", "severity": "high",
  "confidence": null, "assertion_level": null, "tags": ["attack.t1059.001"] }
```

## Verification

Built and tested on a pinned-`1.96.0` toolchain (matching CI): `cargo test -p issen-timeline` green
incl. the new round-trip test; `cargo test -p issen-report -p issen-cli` green (all `FindingRow`
construction sites updated); `cargo clippy … -D warnings` clean on the touched crates; the added lines
pass `cargo fmt --check`. (Note: the base tree has *pre-existing* fmt diffs in files this PR does not
touch — `issen-mem/tests/zz_scratch_netscan.rs`, `issen-signatures/.../sigma.rs`, unrelated lines in
`issen-report/src/lib.rs` — so a workspace-wide `cargo fmt --check` is already red independent of this PR.)

## Open questions

1. **Populate from correlation findings.** The real value lands when correlation-derived findings carry
   their `confidence`/`assertion_level` into `scan_findings`. Is there a single sink where correlation
   `Finding`s become `FindingRow`s, or do they flow through a different table today?
2. **Provenance + ATT&CK technique** (the other two fields the first draft proposed) — add as a second
   PR, or fold in here? Provenance shape: `{source, artifact_path, evidence_ids}` vs richer (USN/MFT
   record)?
3. `assertion_level` as free-text `Option<String>` vs a stored enum — string keeps the migration trivial
   and matches DuckDB VARCHAR; an enum would need a check constraint. Preference?
