# RFC 0004 — Clock anchoring and skew propagation across the timeline

- **Status:** Draft / RFC (subtlest of this set — see "Honest caveats")
- **Builds on:** `issen-correlation`'s `skew.rs` (`detect_time_skew`, `SkewFinding`) — this is *additive*,
  not a replacement
- **Motivated by:** DFIR field reflex #3 — *a documented clock defect must propagate as a correction to
  every downstream timestamp, not sit as a footnote.* A host on UTC-7 vs a network capture on UTC-6 puts
  every host-artifact absolute time +1h off true UTC unless the skew is applied, not just noted.

## What already exists (so this isn't a duplicate)

`crates/issen-correlation/src/skew.rs` already **detects** suspicious divergence: it groups `Evidence` by
artifact path and emits a `SkewFinding { path, source_a, timestamp_a, source_b, timestamp_b, delta_secs }`
when `|Δt| > threshold` (default 300s). That is an *anti-forensics signal* — "these two sources disagree."

What it does **not** do: pick a **reference clock** (a ground truth — PCAP capture time, NTP/w32time,
acquisition metadata) and **apply** a correction so that every absolute timestamp the timeline reports is
expressed against that reference. Detection ≠ correction. The reflex that bit a real case was emitting
host-clock UTC as ground truth after merely *noting* the skew.

## Proposal

Two additive pieces:

1. **A clock anchor on ingest.** `issen <evidence> --clock-anchor <source>=<offset>` (repeatable), where
   `source` is an evidence source label and `offset` is its known delta from the reference (e.g.
   `host=-3600s`, or `host@2020-09-19T03:00:00Z=+3600s` for a point measurement). Anchors are persisted
   in a `clock_anchors` table next to the timeline.

```rust
// illustrative
pub struct ClockAnchor {
    pub source: String,            // evidence source label this applies to
    pub offset_secs: i64,          // add this to the source's local stamps to reach reference UTC
    pub reference: ClockReference, // Pcap | Ntp | AcquisitionMeta | Manual
    pub measured_at: Option<DateTime<Utc>>,
}
```

2. **Propagation + honesty in output.** Timeline rows expose both the raw stamp and a
   `reference_time` (raw + applicable anchor offset). Any absolute time with **no** anchor for its source
   is tagged `clock: host-local, skew unverified` rather than silently presented as truth — so an agent
   reading the JSON (RFC 0001/0002) can see which times are anchored and which are not. Optionally
   `--require-anchor` refuses to print bare absolute times for un-anchored sources.

`skew.rs` becomes the *detector that suggests where an anchor is needed*: a `SkewFinding` with a known
ground-truth source on one side is exactly the measurement that seeds a `ClockAnchor`.

## Why

Timeline correctness is the substrate every other finding sits on; a uniform +1h shift silently corrupts
ordering against an independent reference (the PCAP), which is the one thing that breaks an attack
narrative an agent then reasons over. Making "is this time anchored?" a first-class, machine-readable
property is the agentic-DFIR move — the agent stops trusting un-anchored absolutes.

## Honest caveats (why this is the least-baked of the four)

- The hardest part is **inferring** offsets, not applying them — and that stays manual/heuristic here.
  This RFC only proposes the *plumbing* to apply and surface a known offset, plus the honesty tag. That
  is still strictly better than today (note-and-forget), but it is not auto-skew-correction.
- Per-source single offset assumes a constant skew; clock drift over a long capture is out of scope for v1.

## Open questions

1. Is `--clock-anchor` an ingest-time flag, or a post-hoc `issen anchor add` so it can be set after
   seeing `skew.rs` output without re-ingesting?
2. Should `reference_time` be a stored column (denormalized, fast) or computed at query time from
   `clock_anchors` (always correct if an anchor is revised)? Leaning query-time.
3. Does the report layer want to *refuse* to render an un-anchored absolute time by default, or only when
   `--require-anchor` is set? (Default-refuse is safer but noisier on single-host cases with no reference.)
