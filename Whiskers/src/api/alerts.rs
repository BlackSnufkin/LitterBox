//! `GET /api/alerts/fibratus/since?from=<ISO8601>&until=<ISO8601>`
//!
//! Pulls Fibratus rule-match alerts from the Windows Application event
//! log within the requested UTC window. Fibratus, when configured with
//! `alertsenders.eventlog: {enabled: true, format: json}`, writes each
//! rule match as a record under `Provider Name="Fibratus"` whose
//! `<EventData><Data>...</Data></EventData>` field carries the alert as
//! a JSON string.
//!
//! We shell out to the built-in `wevtutil` CLI rather than linking
//! against the Win32 Event Log API:
//!   - no Rust dependency on the heavyweight `windows` crate
//!   - wevtutil ships on every supported Windows version
//!   - the XPath query Fibratus needs is well-supported and trivial
//!
//! Whiskers does NO parsing of the JSON `<Data>` payload. We just
//! extract the `<TimeCreated>`, `<EventID>`, and `<Data>` text per
//! event and ship them back. LitterBox parses on its side, matching
//! DetonatorAgent's split.

use std::process::Stdio;

use axum::extract::Query;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use tokio::process::Command;

use crate::api::info::has_fibratus;

#[derive(Debug, Deserialize)]
pub struct FibratusAlertsQuery {
    /// Inclusive lower bound on `TimeCreated/@SystemTime`, ISO8601 / RFC3339.
    pub from: String,
    /// Inclusive upper bound. Optional; we substitute "now" if missing.
    pub until: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct FibratusAlert {
    pub time_created: String,
    pub event_id: u32,
    /// Raw JSON string from the event's `<Data>` field. Whiskers does not
    /// parse this; LitterBox does.
    pub data: String,
}

#[derive(Debug, Serialize)]
pub struct FibratusAlertsResponse {
    pub supported: bool,
    pub events: Vec<FibratusAlert>,
}

pub async fn since(
    Query(q): Query<FibratusAlertsQuery>,
) -> Result<Json<FibratusAlertsResponse>, (StatusCode, Json<serde_json::Value>)> {
    if !has_fibratus() {
        return Ok(Json(FibratusAlertsResponse {
            supported: false,
            events: Vec::new(),
        }));
    }

    // Match DetonatorAgent's FibratusEdrPlugin.cs format exactly:
    //   start: yyyy-MM-ddTHH:mm:ss.000000000Z  (rounded DOWN to the second
    //          so we catch events that fired in the same second as run_start)
    //   end:   yyyy-MM-ddTHH:mm:ss.fffffffffZ  (full 9-digit precision)
    let from_xpath = parse_iso_round_down(&q.from)
        .ok_or_else(|| bad_request("invalid `from` timestamp (expected ISO8601)"))?;
    let until_owned;
    let until_xpath = match q.until.as_deref() {
        Some(u) => parse_iso_full_precision(u)
            .ok_or_else(|| bad_request("invalid `until` timestamp (expected ISO8601)"))?,
        None => {
            // No explicit upper bound → use "now". Format with full precision.
            until_owned = format_full_precision(chrono::Utc::now());
            until_owned
        }
    };

    // XPath shape (incl. spaces around operators) mirrors DetonatorAgent's
    // FibratusEdrPlugin.cs verbatim — that exact query is known to work
    // against the Application log on recent Windows builds.
    let xpath = format!(
        "*[System[Provider[@Name='Fibratus'] and TimeCreated[@SystemTime >= '{from_xpath}' and @SystemTime <= '{until_xpath}']]]"
    );
    let from = from_xpath.clone();
    let until = until_xpath.clone();

    tracing::info!(from, until, "Querying Fibratus alerts from Application log");

    let output = Command::new("wevtutil.exe")
        .arg("qe")
        .arg("Application")
        .arg(format!("/q:{xpath}"))
        .arg("/f:xml")
        .arg("/e:Events")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await;

    let output = match output {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(error = %e, "wevtutil spawn failed");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": format!("wevtutil spawn failed: {e}"),
                })),
            ));
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        tracing::error!(stderr, "wevtutil exited non-zero");
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("wevtutil exited {:?}", output.status.code()),
                "stderr": stderr,
            })),
        ));
    }

    let xml = String::from_utf8_lossy(&output.stdout);
    let events = parse_events(&xml);
    tracing::info!(count = events.len(), "Fibratus alerts returned");
    Ok(Json(FibratusAlertsResponse { supported: true, events }))
}

/// Parse an inbound RFC3339 timestamp, then format as the round-DOWN
/// (zero-fractional) UTC form DetonatorAgent uses for `from`:
///   `yyyy-MM-ddTHH:mm:ss.000000000Z`
fn parse_iso_round_down(raw: &str) -> Option<String> {
    let dt = chrono::DateTime::parse_from_rfc3339(raw).ok()?;
    let utc = dt.with_timezone(&chrono::Utc);
    Some(utc.format("%Y-%m-%dT%H:%M:%S.000000000Z").to_string())
}

/// Parse an inbound RFC3339 timestamp, format with full 9-digit
/// fractional-second precision in UTC.
fn parse_iso_full_precision(raw: &str) -> Option<String> {
    let dt = chrono::DateTime::parse_from_rfc3339(raw).ok()?;
    Some(format_full_precision(dt.with_timezone(&chrono::Utc)))
}

fn format_full_precision(dt: chrono::DateTime<chrono::Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%S%.9fZ").to_string()
}

/// Extract per-event `(time_created, event_id, data)` tuples from a
/// `<Events>...<Event>...</Event>...</Events>` XML blob. We don't need a
/// full XML parser for this — the format wevtutil emits is deterministic,
/// and we want exactly three fields per event. Quick string-scanning
/// keeps the binary lean.
fn parse_events(xml: &str) -> Vec<FibratusAlert> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while let Some(start_rel) = xml[cursor..].find("<Event ") {
        let event_start = cursor + start_rel;
        let event_end_rel = match xml[event_start..].find("</Event>") {
            Some(p) => p,
            None => break,
        };
        let event_end = event_start + event_end_rel + "</Event>".len();
        let event_block = &xml[event_start..event_end];
        cursor = event_end;

        let time_created = extract_attr(event_block, "<TimeCreated", "SystemTime")
            .unwrap_or_default();
        let event_id = extract_text_between(event_block, "<EventID", ">", "</EventID>")
            .and_then(|s| s.trim().parse::<u32>().ok())
            .unwrap_or(0);
        // Fibratus's eventlog sender writes the JSON as ONE `<Data>` element
        // with no Name attribute. Be permissive about the open-tag attrs
        // since some Windows builds add them; we just want the inner text.
        let data = extract_text_between(event_block, "<Data", ">", "</Data>")
            .unwrap_or_default();
        if data.is_empty() {
            continue;
        }
        out.push(FibratusAlert {
            time_created,
            event_id,
            data: xml_unescape(&data),
        });
    }
    out
}

/// Find an attribute value inside an element's open tag, accepting both
/// single- and double-quoted forms. wevtutil's XML output uses single
/// quotes (e.g. `<TimeCreated SystemTime='2026-04-30T...'/>`); our test
/// fixtures used double; we tolerate either.
fn extract_attr(haystack: &str, open_marker: &str, attr: &str) -> Option<String> {
    let tag_start = haystack.find(open_marker)?;
    let tag_end = haystack[tag_start..].find('>')?;
    let tag = &haystack[tag_start..tag_start + tag_end];
    for quote in &['"', '\''] {
        let attr_marker = format!("{attr}={quote}");
        if let Some(rel) = tag.find(&attr_marker) {
            let aval_start = rel + attr_marker.len();
            if let Some(end_rel) = tag[aval_start..].find(*quote) {
                return Some(tag[aval_start..aval_start + end_rel].to_string());
            }
        }
    }
    None
}

/// Pull the text between an open tag and its close tag.
/// `extract_text_between(haystack, "<EventID", ">", "</EventID>")` returns
/// the content between the first `<EventID...>` open and `</EventID>`.
fn extract_text_between(
    haystack: &str,
    open_marker: &str,
    open_end: &str,
    close_marker: &str,
) -> Option<String> {
    let mstart = haystack.find(open_marker)?;
    let after_marker = &haystack[mstart..];
    let open_end_rel = after_marker.find(open_end)?;
    let body_start = mstart + open_end_rel + open_end.len();
    let body_end_rel = haystack[body_start..].find(close_marker)?;
    Some(haystack[body_start..body_start + body_end_rel].to_string())
}

/// Decode the XML escape sequences wevtutil emits inside `<Data>` blobs.
/// Fibratus's JSON commonly contains `&quot;`, `&amp;`, `&lt;`, `&gt;`
/// after passing through the event log writer; LitterBox needs a clean
/// JSON string to parse.
fn xml_unescape(s: &str) -> String {
    s.replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

fn bad_request(msg: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "error": msg })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_minimal_event_block() {
        let xml = r#"<Events>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Fibratus" />
    <EventID Qualifiers="8192">62873</EventID>
    <TimeCreated SystemTime="2026-04-30T12:34:56.789Z" />
  </System>
  <EventData>
    <Data>{&quot;title&quot;: &quot;rule X&quot;, &quot;severity&quot;: &quot;high&quot;}</Data>
  </EventData>
</Event>
</Events>"#;
        let events = parse_events(xml);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].time_created, "2026-04-30T12:34:56.789Z");
        assert_eq!(events[0].event_id, 62873);
        assert!(events[0].data.contains("rule X"));
        assert!(events[0].data.contains("\"severity\""));
    }

    #[test]
    fn skips_events_with_empty_data() {
        let xml = r#"<Events>
<Event><System><EventID>1</EventID></System><EventData></EventData></Event>
</Events>"#;
        assert!(parse_events(xml).is_empty());
    }

    #[test]
    fn parses_wevtutil_style_single_quotes() {
        // wevtutil's actual output uses single-quoted attributes.
        let xml = r#"<Events>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Fibratus'/>
    <EventID Qualifiers='8192'>18100</EventID>
    <TimeCreated SystemTime='2026-04-30T11:34:56.7890123Z'/>
  </System>
  <EventData>
    <Data>{&quot;title&quot;: &quot;Suspicious DLL load&quot;}</Data>
  </EventData>
</Event>
</Events>"#;
        let events = parse_events(xml);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].time_created, "2026-04-30T11:34:56.7890123Z");
        assert_eq!(events[0].event_id, 18100);
        assert!(events[0].data.contains("Suspicious DLL load"));
    }

    #[test]
    fn iso_round_down_zeroes_fractional() {
        let s = parse_iso_round_down("2026-04-30T12:34:56.789012+00:00").unwrap();
        assert_eq!(s, "2026-04-30T12:34:56.000000000Z");
    }

    #[test]
    fn iso_full_precision_keeps_nanos() {
        let s = parse_iso_full_precision("2026-04-30T12:34:56.789012+00:00").unwrap();
        assert!(s.starts_with("2026-04-30T12:34:56."));
        assert!(s.ends_with("Z"));
        assert!(s.contains("789012"));
    }
}
