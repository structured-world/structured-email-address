//! Native twin of `npm/scripts/parity.mjs`: read one JSON case per stdin line
//! and print the answer the WebAssembly module would give, as JSON with sorted
//! keys. Cases:
//!
//! - `{"op":"parse","config":<resolved config>,"input":"..."}`
//! - `{"op":"smtp","input":"..."}`
//! - `{"op":"skeleton","input":"..."}`
//!
//! Both npm backends must print byte-identical output; see the `npm` CI job.
//! Run: cargo run -p structured-email-address-wasm --example parity < cases.jsonl

use std::io::{self, BufRead, Write};

use serde::Deserialize;
use structured_email_address::Config;
use structured_email_address_wasm::model::{self, JsConfig};

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
enum Case {
    Parse { config: JsConfig, input: String },
    Smtp { input: String },
    Skeleton { input: String },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    for line in stdin.lock().lines() {
        let line = line?;
        if line.is_empty() {
            continue;
        }
        // Through `Value`, whose map is ordered by key, so field order is not
        // part of what the harnesses have to agree on.
        let value = match serde_json::from_str(&line)? {
            Case::Parse { config, input } => {
                let config = Config::try_from(config)?;
                serde_json::to_value(model::parse(&input, &config))?
            }
            Case::Smtp { input } => structured_email_address::is_smtp_mailbox(&input).into(),
            Case::Skeleton { input } => {
                structured_email_address::confusable_skeleton(&input).into()
            }
        };
        writeln!(out, "{value}")?;
    }
    out.flush()?;
    Ok(())
}
