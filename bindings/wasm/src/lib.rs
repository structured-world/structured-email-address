//! WebAssembly exports behind `@structured-world/structured-email-address-wasm`.
//!
//! The JavaScript wrapper validates options and resolves defaults before it
//! calls in, and turns the plain objects returned here into its public types.

pub mod model;

use serde::Serialize;
use structured_email_address::Config;
use wasm_bindgen::prelude::*;

use crate::model::JsConfig;

/// Plain JavaScript objects, never `Map`s, for the structs serialized here.
fn to_js<T: Serialize>(value: &T) -> Result<JsValue, JsError> {
    value
        .serialize(&serde_wasm_bindgen::Serializer::new())
        .map_err(|e| JsError::new(&e.to_string()))
}

fn config(value: JsValue) -> Result<Config, JsError> {
    let js: JsConfig = serde_wasm_bindgen::from_value(value)
        .map_err(|e| JsError::new(&format!("invalid config: {e}")))?;
    Config::try_from(js).map_err(|e| JsError::new(&e))
}

/// Parse one address; returns `{ ok, value }` or `{ ok, error }`.
#[wasm_bindgen]
pub fn parse(input: &str, config_value: JsValue) -> Result<JsValue, JsError> {
    to_js(&model::parse(input, &config(config_value)?))
}

/// Parse many addresses against one configuration, built once.
#[wasm_bindgen(js_name = parseBatch)]
pub fn parse_batch(inputs: Vec<String>, config_value: JsValue) -> Result<JsValue, JsError> {
    let config = config(config_value)?;
    let outcomes: Vec<_> = inputs
        .iter()
        .map(|input| model::parse(input, &config))
        .collect();
    to_js(&outcomes)
}

/// See [`structured_email_address::is_smtp_mailbox`].
#[wasm_bindgen(js_name = isSmtpMailbox)]
pub fn is_smtp_mailbox(input: &str) -> bool {
    structured_email_address::is_smtp_mailbox(input)
}

/// See [`structured_email_address::confusable_skeleton`].
#[wasm_bindgen(js_name = confusableSkeleton)]
pub fn confusable_skeleton(input: &str) -> String {
    structured_email_address::confusable_skeleton(input)
}
