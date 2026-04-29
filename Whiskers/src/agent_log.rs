//! Bounded ring buffer of agent log lines, surfaced via `GET /api/logs/agent`.
//!
//! Implemented as a `tracing_subscriber::Layer` so every `tracing::info!` /
//! `warn!` / `error!` emitted anywhere in the agent gets captured here AND
//! printed to stdout. Caps at `MAX_LINES` to bound memory.

use std::sync::Mutex;

use chrono::Utc;
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

const MAX_LINES: usize = 1000;

/// Append-only ring buffer. Pushes drop the oldest entry once `MAX_LINES`
/// is reached, so memory is bounded regardless of how long the agent runs.
pub struct AgentLog {
    inner: Mutex<std::collections::VecDeque<String>>,
}

impl AgentLog {
    pub fn new() -> Self {
        AgentLog {
            inner: Mutex::new(std::collections::VecDeque::with_capacity(MAX_LINES)),
        }
    }

    pub fn push(&self, line: String) {
        let mut buf = self.inner.lock().unwrap();
        if buf.len() >= MAX_LINES {
            buf.pop_front();
        }
        buf.push_back(line);
    }

    pub fn snapshot(&self) -> Vec<String> {
        self.inner.lock().unwrap().iter().cloned().collect()
    }

    pub fn clear(&self) {
        self.inner.lock().unwrap().clear();
    }
}

/// Tracing layer that mirrors every event into an `AgentLog`. Clone the
/// `Arc` and install via `tracing_subscriber::registry().with(...)`.
pub struct AgentLogLayer {
    log: std::sync::Arc<AgentLog>,
}

impl AgentLogLayer {
    pub fn new(log: std::sync::Arc<AgentLog>) -> Self {
        AgentLogLayer { log }
    }
}

impl<S: Subscriber> Layer<S> for AgentLogLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        // Format the event into a single line: "[timestamp] [LEVEL] target: message"
        let metadata = event.metadata();
        let level = metadata.level();
        let target = metadata.target();

        // Pull the `message` field out of the event.
        let mut message = String::new();
        struct Visitor<'a>(&'a mut String);
        impl tracing::field::Visit for Visitor<'_> {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    *self.0 = format!("{value:?}");
                    // Strip surrounding quotes that Debug formatting adds.
                    if self.0.starts_with('"') && self.0.ends_with('"') && self.0.len() >= 2 {
                        *self.0 = self.0[1..self.0.len() - 1].to_string();
                    }
                } else if !self.0.is_empty() {
                    self.0.push_str(&format!(" {}={value:?}", field.name()));
                } else {
                    self.0.push_str(&format!("{}={value:?}", field.name()));
                }
            }
        }
        event.record(&mut Visitor(&mut message));

        let line = format!(
            "[{}] [{}] {}: {}",
            Utc::now().format("%Y-%m-%d %H:%M:%S%.3f UTC"),
            level,
            target,
            message,
        );
        self.log.push(line);
    }
}
