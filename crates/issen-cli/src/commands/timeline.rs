use std::io;
use std::path::Path;

use anyhow::{Context, Result};
use issen_core::timeline::event::TimelineEvent;
use issen_correlation::temporal_rule::{
    bundled_temporal_rules, evaluate_temporal, TemporalFinding,
};
use issen_timeline::findings;
use issen_timeline::query::{TimelineQuery, TimelineRow};
use issen_timeline::store::TimelineStore;

use super::timeline_format;

/// Run the timeline command: query events, show findings, or export.
#[allow(clippy::too_many_arguments)]
pub fn run(
    db_path: &Path,
    event_type: Option<&str>,
    source: Option<&str>,
    limit: u64,
    descending: bool,
    export_sqlite: Option<&Path>,
    flagged: bool,
    min_severity: &str,
    format: &str,
    narrative: bool,
) -> Result<()> {
    let store = TimelineStore::open(db_path)
        .with_context(|| format!("Failed to open database: {}", db_path.display()))?;

    // Handle --narrative: a pure view over the persisted DB — load events,
    // run the bundled temporal rules, emit the narrative. Never ingests.
    if narrative {
        return run_narrative(&store, db_path);
    }

    // Handle --flagged: show scan findings instead of timeline events.
    if flagged {
        return show_flagged(&store, min_severity, format);
    }

    // Handle SQLite export.
    if let Some(sqlite_path) = export_sqlite {
        let count = store
            .export_sqlite(sqlite_path)
            .context("Failed to export to SQLite")?;
        println!("Exported {count} events to {}", sqlite_path.display());
        return Ok(());
    }

    // Build query.
    let mut query = TimelineQuery::new().limit(limit);

    if let Some(et) = event_type {
        query = query.event_type(et);
    }
    if let Some(s) = source {
        query = query.source(s);
    }
    if descending {
        query = query.descending();
    }

    let rows = store.query(&query).context("Query failed")?;

    if format == "json" {
        let arr: Vec<serde_json::Value> = rows
            .iter()
            .map(|r| {
                serde_json::json!({
                    "timestamp": r.timestamp_display,
                    "event_type": r.event_type,
                    "source": r.source,
                    "description": r.description,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&arr)?);
        return Ok(());
    }

    if format == "csv" {
        let stdout = io::stdout();
        let mut out = stdout.lock();
        timeline_format::write_csv(&rows, &mut out).context("CSV export failed")?;
        return Ok(());
    }

    if format == "bodyfile" {
        let stdout = io::stdout();
        let mut out = stdout.lock();
        timeline_format::write_bodyfile(&rows, &mut out).context("Bodyfile export failed")?;
        return Ok(());
    }

    if rows.is_empty() {
        println!("No events found.");
        return Ok(());
    }

    // Print events in a simple table format.
    println!(
        "{:<26} {:<16} {:<14} DESCRIPTION",
        "TIMESTAMP", "EVENT_TYPE", "SOURCE"
    );
    println!("{}", "-".repeat(80));

    for row in &rows {
        print_row(row);
    }

    println!("\n{} event(s) displayed.", rows.len());

    Ok(())
}

/// `--narrative`: render the temporal-rule narrative as a pure view over the
/// persisted DuckDB. Loads events, evaluates the bundled rules, and prints the
/// same narrative `supertimeline` emits — without re-parsing any evidence.
fn run_narrative(store: &TimelineStore, db_path: &Path) -> Result<()> {
    let (events, findings) = collect_narrative_findings(store)?;
    super::supertimeline::emit_narrative(&events, &findings, db_path);
    Ok(())
}

/// Load the persisted timeline and evaluate the bundled temporal rules over it.
///
/// The decision core of the `--narrative` view (Humble Object): it returns the
/// events and findings so it can be unit-tested without capturing stdout, while
/// [`run_narrative`] stays a thin load-evaluate-print shell.
fn collect_narrative_findings(
    store: &TimelineStore,
) -> Result<(Vec<TimelineEvent>, Vec<TemporalFinding>)> {
    let events = store
        .load_timeline_events()
        .context("Failed to load events from the timeline database")?;
    let rules = bundled_temporal_rules();
    let findings: Vec<TemporalFinding> = rules
        .iter()
        .flat_map(|rule| evaluate_temporal(rule, &events))
        .collect();
    Ok((events, findings))
}

/// Show scan findings from the scan_findings table.
fn show_flagged(store: &TimelineStore, min_severity: &str, format: &str) -> Result<()> {
    let conn = store.connection();

    // Ensure the table exists (it may not if no scanning was done).
    findings::create_findings_table(conn).context("Failed to access findings table")?;

    let severity_filter = if min_severity == "informational" {
        None
    } else {
        Some(min_severity)
    };

    let rows =
        findings::query_findings(conn, severity_filter).context("Failed to query findings")?;

    if format == "json" {
        return show_flagged_json(store, &rows);
    }

    if rows.is_empty() {
        println!("No scan findings found.");
        if severity_filter.is_some() {
            println!("Try lowering --min-severity to see more results.");
        }
        return Ok(());
    }

    // Show summary counts.
    let counts = findings::count_by_severity(conn).context("Failed to count findings")?;
    let total = findings::total_findings(conn).context("Failed to count total")?;

    println!("Scan findings: {total} total");
    for (sev, cnt) in &counts {
        println!("  {sev}: {cnt}");
    }
    println!();

    // Print findings table.
    println!(
        "{:<10} {:<10} {:<30} DESCRIPTION",
        "SEVERITY", "ENGINE", "RULE"
    );
    println!("{}", "-".repeat(90));

    for row in &rows {
        let desc = if row.description.len() > 40 {
            format!("{}...", &row.description[..37])
        } else {
            row.description.clone()
        };
        println!(
            "{:<10} {:<10} {:<30} {}",
            row.severity, row.engine, row.rule_name, desc
        );
    }

    println!("\n{} finding(s) displayed.", rows.len());

    Ok(())
}

/// Output scan findings as a JSON object.
fn show_flagged_json(store: &TimelineStore, rows: &[findings::FindingRow]) -> Result<()> {
    let conn = store.connection();
    let counts = findings::count_by_severity(conn).context("Failed to count findings")?;
    let total = findings::total_findings(conn).context("Failed to count total")?;

    // Build by_severity map.
    let by_severity: serde_json::Map<String, serde_json::Value> = counts
        .into_iter()
        .map(|(sev, cnt)| (sev, serde_json::Value::from(cnt)))
        .collect();

    // Build findings array, deserializing tags from JSON string to array.
    let findings_arr: Vec<serde_json::Value> = rows
        .iter()
        .map(|row| {
            let tags: serde_json::Value = serde_json::from_str(&row.tags)
                .unwrap_or_else(|_| serde_json::Value::Array(vec![]));

            serde_json::json!({
                "evidence_source_id": row.evidence_source_id,
                "artifact_path": row.artifact_path,
                "engine": row.engine,
                "severity": row.severity,
                "rule_name": row.rule_name,
                "description": row.description,
                "matched_indicator": row.matched_indicator,
                "tags": tags,
                // Agent-facing fields: `null` when the producing engine supplies
                // no calibrated score / derivation level (never a fabricated default).
                "confidence": row.confidence,
                "assertion_level": row.assertion_level,
            })
        })
        .collect();

    let output = serde_json::json!({
        "total": total,
        "by_severity": by_severity,
        "findings": findings_arr,
    });

    println!("{}", serde_json::to_string_pretty(&output)?);

    Ok(())
}

fn print_row(row: &TimelineRow) {
    // Truncate description to 40 chars for display.
    let desc = if row.description.len() > 40 {
        format!("{}...", &row.description[..37])
    } else {
        row.description.clone()
    };

    println!(
        "{:<26} {:<16} {:<14} {}",
        row.timestamp_display, row.event_type, row.source, desc
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use issen_core::artifacts::ArtifactType;
    use issen_core::timeline::event::{EventType, TimelineEvent};
    use issen_timeline::store::TimelineStore;

    #[test]
    fn narrative_flags_hollow_process_pair() {
        // The narrative-over-DB view (issen #110 Phase 1) loads persisted
        // events and runs the bundled temporal rules. A 4688 process-creation
        // from the Event Log with NO Prefetch FileModify within 5s must fire
        // `temporal.hollow-process` — proving the view sees real DB events, not
        // a hardcoded file set.
        let store = TimelineStore::in_memory().expect("store");
        let exec = TimelineEvent::new(
            10_000_000_000,
            "2026-01-01T00:00:10Z".to_string(),
            EventType::ProcessExec,
            ArtifactType::EventLog,
            "Security.evtx".to_string(),
            "evil.exe created (4688)".to_string(),
            "CASE-001".to_string(),
        );
        store.insert_batch(&[exec]).expect("ingest");

        let (events, findings) = collect_narrative_findings(&store).expect("narrative");
        assert_eq!(events.len(), 1, "one event ingested");
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "temporal.hollow-process"),
            "expected temporal.hollow-process finding; got {:?}",
            findings
                .iter()
                .map(|f| f.rule_id.as_str())
                .collect::<Vec<_>>()
        );
    }
}
