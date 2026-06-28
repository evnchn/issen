# RFC 0002 — Agent-grade findings: carry confidence, provenance, and technique to the export boundary

- **Status:** Draft / RFC
- **Touches:** `issen-timeline` (`FindingRow`, `scan_findings` schema), `issen-cli` (`scanning.rs`,
  `timeline --flagged --format json`)
- **Motivated by:** DFIR field reflex — *attribution is the highest-hallucination-risk step in IR; carry
  explicit confidence and lineage, never a bare label.*

## Problem

The correlation layer already models calibrated confidence. `issen_correlation::model::Finding`
(`crates/issen-correlation/src/model.rs:196`) carries:

```rust
pub struct Finding {
    pub rule_id: String,
    pub title: String,
    pub severity: String,
    pub evidence_ids: Vec<String>,
    pub summary: Option<String>,
    pub explanation: Option<String>,
    pub confidence: u8,                  // analyst confidence 0–100
    pub assertion_level: AssertionLevel, // Observed | Correlated | Inferred
    pub evidence_rendered: Vec<String>,
}
```

But the **stored / exported** finding row throws most of that away. `issen_timeline::findings::FindingRow`
(`crates/issen-timeline/src/findings.rs:11`) is:

```rust
pub struct FindingRow {
    pub evidence_source_id: String,
    pub artifact_path: String,
    pub engine: String,
    pub severity: String,        // <- severity survives…
    pub rule_name: String,
    pub description: String,
    pub matched_indicator: Option<String>,
    pub tags: String,            // JSON Vec<String>
}                                // …but confidence, assertion_level, provenance: GONE
```

So the JSON an agent reads via `issen timeline --flagged --format json` has **severity but no
confidence, no assertion level, and no machine-readable provenance** (which bytes/offset/artifact
support the claim). An LLM consuming `severity: "high", rule_name: "powershell_empire_stager"` has no
signal that this is an `Inferred` framework guess at confidence 35 vs an `Observed` fact at 95 — exactly
the input that produces over-confident attribution. The data exists one layer up; it is dropped at the
`scan_finding_to_finding_row` boundary (`crates/issen-cli/src/scanning.rs:68`).

## Proposal

Carry the confidence/assertion/provenance through to the row and the JSON export.

1. Extend `FindingRow` and the `scan_findings` DuckDB schema (additive, nullable columns — old DBs still
   read):

```rust
pub struct FindingRow {
    // … existing fields …
    pub confidence: Option<u8>,            // 0–100, from correlation Finding
    pub assertion_level: Option<String>,   // "observed" | "correlated" | "inferred"
    pub attack_technique: Option<String>,  // e.g. "T1059.001"
    pub provenance: Option<String>,        // JSON: {source, artifact_path, offset?, evidence_ids}
}
```

```sql
ALTER TABLE scan_findings ADD COLUMN IF NOT EXISTS confidence       UTINYINT;
ALTER TABLE scan_findings ADD COLUMN IF NOT EXISTS assertion_level  VARCHAR;
ALTER TABLE scan_findings ADD COLUMN IF NOT EXISTS attack_technique VARCHAR;
ALTER TABLE scan_findings ADD COLUMN IF NOT EXISTS provenance       VARCHAR;
```

2. Populate them at `scan_finding_to_finding_row` and wherever correlation findings land, defaulting to
   `None` for engines that genuinely don't compute a confidence (YARA hit = `Observed`/None is honest;
   don't fabricate a number).

3. Emit them in the `--format json` / `findings_list` envelope. A consuming agent then sees:

```json
{
  "rule_name": "powershell_empire_stager",
  "severity": "high",
  "confidence": 35,
  "assertion_level": "inferred",
  "attack_technique": "T1059.001",
  "provenance": {"source": "registry", "artifact_path": "SOFTWARE\\...\\Run", "evidence_ids": ["ev_4471"]}
}
```

## Why

This is the single cheapest guardrail against an agent laundering a low-confidence inference into a
confident report. The honest answer "`inferred`, 35" is already computed — we just have to stop
discarding it at the storage boundary. Pairs directly with RFC 0001's `findings_list` tool.

## Scope / non-goals

- Not changing how confidence is *computed* — only carrying what correlation already produces.
- `None` is a first-class value: an engine with no calibrated confidence must export `null`, never a
  made-up default (a fabricated `confidence: 50` would be worse than absent).

## Open questions

1. Provenance richness: is `{source, artifact_path, evidence_ids}` enough, or do agents need the raw
   byte offset / `$UsnJrnl` USN / MFT record number where applicable?
2. `attack_technique`: single ID, or `Vec<String>` for findings spanning multiple techniques?
3. Should `severity` and `confidence` stay independent (they are orthogonal — a low-severity finding can
   be high-confidence), or does the report layer want a combined rank? (I think: keep orthogonal.)
