pub mod convert;
pub mod dae;
pub mod error;
pub mod singbox;

pub use error::{AppError, Result};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn dae_to_singbox(dae_text: &str) -> std::result::Result<String, JsError> {
    let dae_config = dae::parser::parse(dae_text)?;
    let sing_config = convert::dae_to_sing::convert(&dae_config)?;
    serde_json::to_string_pretty(&sing_config).map_err(|e| JsError::from(AppError::from(e)))
}

#[wasm_bindgen]
pub fn singbox_to_dae(singbox_json: &str) -> std::result::Result<String, JsError> {
    let json = singbox::jsonc::strip_jsonc(singbox_json);
    let sing_config: singbox::config::SingBoxConfig =
        serde_json::from_str(&json).map_err(|e| JsError::from(AppError::from(e)))?;
    let dae_config = convert::sing_to_dae::convert(&sing_config)?;
    Ok(dae::serializer::serialize(&dae_config))
}
