# RFC 0001 — `issen-mcp`: an agent-facing MCP server over the triage DB

- **Status:** Draft / RFC (no code yet — proposing the surface before building)
- **Layer:** front-end (`-mcp`), per the fleet naming table in `CLAUDE.md`
- **Depends on:** existing read-only query surface in `issen-cli` (`timeline`, `report`, `info`)

## Problem

issen turns disk + memory evidence into a correlated DuckDB super-timeline and a set of
findings. Today every way to *consume* that output is a human-shaped CLI invocation:
`issen timeline --sql …`, `issen timeline --flagged --format json`, `issen report`. An LLM
agent running an investigation has to shell out, format flags by hand, and screen-scrape text.

`CLAUDE.md` already reserves a fleet slot for the answer:

> `-mcp` | front-end: MCP server (agent-facing) | browser-forensic-mcp

…but `issen` itself ships no such crate. `grep -ri 'mcp\|model context\|jsonrpc' crates --include='*.rs'`
returns nothing. So the agent-facing front-door the architecture anticipates is simply not built yet
for this repo.

## Proposal

Add an `issen-mcp` crate (binary `is4n6-mcp`, following the `<x>4n6` front-end convention) that speaks
the Model Context Protocol over stdio and exposes the **already-guarded, read-only** capabilities as
tools. No new analysis logic — it is a thin transport over the existing query layer (Humble Object:
all decisions stay in the libs, the server is the irreducible transport shell `CLAUDE.md` asks for).

Initial tool surface (each maps 1:1 to an existing capability):

| MCP tool | Backed by | Notes |
|---|---|---|
| `timeline_query` | `issen timeline` typed-query path | structured filters: `event_type`, `source`, `from`/`to`, `around`/`window`, `field`, paging |
| `timeline_sql` | `issen timeline --sql` | the existing read-only SELECT/WITH guard — mutating keywords already refused |
| `findings_list` | `issen timeline --flagged --format json` | `min_severity` filter; jsonguard-sanitized output |
| `report_render` | `issen report` | returns the structured report, not the HTML shell |
| `db_info` | `issen info` | schema/metadata for orientation |

Sketch of the tool registration (illustrative, names from the current CLI):

```rust
// crates/issen-mcp/src/tools.rs  (illustrative)
fn tools() -> Vec<Tool> {
    vec![
        Tool::new("timeline_query")
            .desc("Query the super-timeline with structured filters (read-only).")
            .arg("event_type", ArgType::StringArray, /*required=*/ false)
            .arg("from", ArgType::String, false)   // ISO 8601 or date
            .arg("to", ArgType::String, false)
            .arg("around", ArgType::String, false)  // pivot ± window
            .arg("limit", ArgType::U64, false),
        Tool::new("timeline_sql")
            .desc("Run a guarded read-only SQL SELECT/WITH over the timeline DB.")
            .arg("query", ArgType::String, true),
        // findings_list / report_render / db_info …
    ]
}
```

## Why this is the high-leverage agentic move

It turns issen from *a tool a human drives* into *a tool an agent drives* with the smallest possible
trusted surface: read-only, no ingest, no mutation, every tool already exists and is already guarded.
An agent can pivot around a timestamp, stack rare events, and pull findings without a human translating
intent into flags — the "human in the loop, not in the hot loop" shape.

## Scope / non-goals

- **Read-only only.** Ingest (`issen <evidence>`) stays a human-initiated, side-effecting command; it is
  deliberately *not* an MCP tool in v1. Evidence acquisition is not something to hand an autonomous agent.
- No write-back to the DB. No feed mutation. No remote dispatch (`remote-access`) exposure.
- Transport is stdio MCP first; HTTP/SSE later if needed.

## Open questions (for the maintainer)

1. Binary/crate name: `issen-mcp` crate is unambiguous, but is `is4n6-mcp` the right binary, or should
   the MCP mode be a subcommand of the main `issen` binary (`issen mcp`) instead of a separate crate?
2. Which Rust MCP library — `rmcp` (official-ish), `mcp-sdk`, or a hand-rolled minimal stdio JSON-RPC
   loop to avoid a heavy dep given the `deny.toml` / supply-chain posture here?
3. Should `findings_list` carry confidence/provenance? That depends on RFC 0002 — these two compose.
4. Auth/sandboxing expectations when the agent is untrusted: is read-only-DB-handle enough, or is a
   path allowlist for `--sql`-reachable tables wanted?

## Prior art in this repo (re-anchored after a code review pass)

This is **not greenfield** — it should reference, not reinvent, two things already in the tree:

- `docs/plans/archive/2026-06-15-findevil-mcp-fleet-design.md` already designs a thin, **read-only,
  agent-facing MCP server** for this fleet (typed tools, an allowlist, testable dispatch — the same
  shape proposed here). This RFC is best read as *applying that already-designed `-mcp` pattern to
  issen specifically*.
- `north-star-advisor/docs/architecture/INTELLIGENCE_LAYER.md` specs `issen-intel`, a local-first,
  grounded-generation AI layer. `issen-mcp` is **complementary, not overlapping**: the MCP server is
  the *interface an external agent drives*; `issen-intel` is the *AI brain*. They compose.

(Accuracy note: the only `agent` matches in the Rust today are SSH/HTTP **user-agent** strings, not an
agent interface — the gap this addresses is real.)
