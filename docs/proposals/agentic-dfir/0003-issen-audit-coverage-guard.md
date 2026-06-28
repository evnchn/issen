# RFC 0003 — `issen audit`: artifact-class coverage and the negative-claim guard

- **Status:** Draft / RFC
- **Adds:** an `Audit` variant to `Commands` (`crates/issen-cli/src/lib.rs:153`), a pure read-only view
  over the timeline DB (never ingests)
- **Motivated by:** DFIR field reflex #1 — *every "none / not found / not present" claim gets a second
  method before it ships.* Absence-of-evidence is the classic IR trap.

## Problem

An agent (or a tired human) asks "was data exfiltrated?", searches the live timeline, finds no exfil
archive, and writes "no exfil". But the canonical failure case — `secret.zip` created → exfiltrated →
**deleted** — never appears in the live filesystem at all. The answer lives in the `$UsnJrnl:$J` change
journal, `$LogFile`, MFT unallocated records, prefetch, shellbags/jumplists. issen *has parsers for many
of these* (`crates/parsers/issen-parser-{logfile,prefetch,shellbags,amcache,srum,...}`), but nothing tells
the consumer **which artifact classes were actually parsed for this evidence set vs which are silently
absent.** A "no findings" is indistinguishable from a "never looked."

There is no `audit`/`coverage` subcommand today (the `Commands` enum has Timeline, Scan, Memory, Report,
Srum, Frequency, Processes, Session, … but no coverage view).

## Proposal

`issen audit <db>` — a read-only pass over the timeline DB that reports, per artifact class, whether it
was ingested, keyed to the intrusion kill chain so gaps are legible as *investigative* gaps, not just
missing tables.

```
$ issen audit case.duckdb
Kill-chain coverage (artifact classes seen in this timeline):

  COLLECTION    ✔ LNK (142)   ✔ shellbags (38)   ✔ jumplists (11)
  EXECUTION     ✔ prefetch (220)   ✔ amcache (1.4k)   ✗ shimcache (0)
  STAGING       ✗ archive-creation events   ✗ $UsnJrnl ($J)         <-- exfil staging is BLIND here
  EXFIL         ✔ SRUM net (903)   ✗ browser uploads
  CLEANUP       ✔ $Recycle.Bin (4)   ✗ $LogFile delete records

  3 kill-chain stages have an unparsed artifact class. A "nothing found" in
  STAGING/CLEANUP is NOT yet supported by evidence — parse $UsnJrnl + $LogFile
  before asserting no exfil.

  --json for machine-readable output (for the MCP findings consumer / RFC 0001).
```

The coverage map is a static table of `(kill_chain_stage, artifact_class, parser_crate,
duckdb_event_type/source)` checked against `SELECT DISTINCT source/event_type` actually present in the DB.

```rust
// illustrative
struct CoverageRow { stage: KillChainStage, class: &'static str, parser: &'static str, source_key: &'static str }
enum Presence { Parsed(u64), AbsentButSupported, NotApplicable }
// audit = for each CoverageRow, count rows matching source_key in the timeline → Presence
```

## Why this is agentic-DFIR tooling

It converts the silent absence-of-evidence trap into an explicit, machine-readable signal an agent must
reckon with *before* it concludes "negative." It is the programmatic form of the reflex "which artifact
classes haven't I touched?" — and it composes with RFC 0001: an agent calls `audit` first, sees STAGING
is blind, and knows to go pull `$UsnJrnl` before answering an exfil question. It turns "I didn't find X"
into the honest "X is not yet supported by the evidence I parsed."

## Scope / non-goals

- Read-only. Does **not** re-ingest or fetch missing artifacts — it *reports the gap*, the operator/agent
  decides whether to parse more. (A future `--suggest` could print the exact parse command per gap.)
- The kill-chain mapping is opinionated and will need a forensicator's eye — the brick here is the
  *mechanism*; the per-class stage assignment is the part most worth arguing about.

## Open questions

1. Where should the canonical coverage table live — hard-coded in `issen-cli`, or a data file alongside
   the rules so it is editable without a rebuild?
2. Kill-chain model: stick to a simple collection→execution→staging→exfil→cleanup, or map straight onto
   MITRE ATT&CK tactics (the correlation layer already speaks technique IDs)?
3. Should `audit` exit non-zero when a stage is fully blind, so CI / an agent harness can gate on it?
