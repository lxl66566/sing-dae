pub mod convert;
pub mod dae;
pub mod error;
pub mod singbox;

#[cfg(feature = "comment-defaults")]
mod comment_defaults;

pub use error::{AppError, Result};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn dae_to_singbox(dae_text: &str) -> std::result::Result<String, JsError> {
    #[cfg(feature = "comment-defaults")]
    let comment_defaults = comment_defaults::extract_dae_comment_json(dae_text);

    let dae_config = dae::parser::parse(dae_text)?;
    let sing_config = convert::dae_to_sing::convert(&dae_config)?;
    let value = serde_json::to_value(&sing_config).map_err(|e| JsError::from(AppError::from(e)))?;

    #[cfg(feature = "comment-defaults")]
    let value = match comment_defaults {
        Some(overrides) => comment_defaults::deep_merge(value, overrides),
        None => value,
    };

    serde_json::to_string_pretty(&value).map_err(|e| JsError::from(AppError::from(e)))
}

#[wasm_bindgen]
pub fn singbox_to_dae(singbox_json: &str) -> std::result::Result<String, JsError> {
    #[cfg(feature = "comment-defaults")]
    let comment_defaults = comment_defaults::extract_singbox_comment_dae(singbox_json);

    let json = singbox::jsonc::strip_jsonc(singbox_json);
    let sing_config: singbox::config::SingBoxConfig =
        serde_json::from_str(&json).map_err(|e| JsError::from(AppError::from(e)))?;
    let dae_config = convert::sing_to_dae::convert(&sing_config)?;

    #[cfg(feature = "comment-defaults")]
    let dae_config = {
        let mut cfg = dae_config;
        if let Some(overrides) = comment_defaults {
            comment_defaults::merge_dae_config(&mut cfg, &overrides);
        }
        cfg
    };

    Ok(dae::serializer::serialize(&dae_config))
}
