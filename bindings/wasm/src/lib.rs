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

/// A configuration built once and kept in the module, so a parser reused for
/// many addresses does not rebuild it, provider registry included, per call.
#[wasm_bindgen]
pub struct CompiledConfig {
    config: Config,
}

#[wasm_bindgen]
impl CompiledConfig {
    /// Build from a resolved configuration object.
    #[wasm_bindgen(constructor)]
    pub fn new(config: JsValue) -> Result<CompiledConfig, JsError> {
        let js: JsConfig = serde_wasm_bindgen::from_value(config)
            .map_err(|e| JsError::new(&format!("invalid config: {e}")))?;
        let config = Config::try_from(js).map_err(|e| JsError::new(&e))?;
        Ok(Self { config })
    }

    /// Parse one address; returns `{ ok, value }` or `{ ok, error }`.
    pub fn parse(&self, input: &str) -> Result<JsValue, JsError> {
        to_js(&model::parse(input, &self.config))
    }

    /// Parse many addresses; one outcome per input, in order.
    #[wasm_bindgen(js_name = parseBatch)]
    pub fn parse_batch(&self, inputs: Vec<String>) -> Result<JsValue, JsError> {
        let outcomes: Vec<_> = inputs
            .iter()
            .map(|input| model::parse(input, &self.config))
            .collect();
        to_js(&outcomes)
    }
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
