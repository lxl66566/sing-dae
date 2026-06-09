pub mod convert;
pub mod dae;
pub mod error;
pub mod singbox;

#[cfg(feature = "comment-defaults")]
mod comment_defaults;

pub use error::{AppError, Result};

#[derive(Debug, Clone, Default)]
pub struct ConvertOptions {
    pub prerelease: bool,
}

pub fn dae_to_singbox(dae_text: &str) -> Result<String> {
    dae_to_singbox_with_opts(dae_text, &ConvertOptions::default())
}

pub fn dae_to_singbox_with_opts(
    dae_text: &str,
    opts: &ConvertOptions,
) -> Result<String> {
    let value = dae_to_singbox_value_with_opts(dae_text, opts)?;
    serde_json::to_string_pretty(&value).map_err(Into::into)
}

pub fn dae_to_singbox_value(dae_text: &str) -> Result<serde_json::Value> {
    dae_to_singbox_value_with_opts(dae_text, &ConvertOptions::default())
}

pub fn dae_to_singbox_value_with_opts(
    dae_text: &str,
    opts: &ConvertOptions,
) -> Result<serde_json::Value> {
    let dae_config = dae::parser::parse(dae_text)?;
    let sing_config = convert::dae_to_sing::convert(&dae_config, opts)?;
    let mut value = serde_json::to_value(&sing_config)?;

    #[cfg(feature = "comment-defaults")]
    if let Some(overrides) = comment_defaults::extract_dae_comment_json(dae_text) {
        value = comment_defaults::deep_merge(value, overrides);
    }

    Ok(value)
}

pub fn singbox_to_dae(singbox_json: &str) -> Result<String> {
    singbox_to_dae_with_opts(singbox_json, &ConvertOptions::default())
}

pub fn singbox_to_dae_with_opts(
    singbox_json: &str,
    opts: &ConvertOptions,
) -> Result<String> {
    let dae_config = singbox_to_dae_value_with_opts(singbox_json, opts)?;
    Ok(dae::serializer::serialize(&dae_config))
}

pub fn singbox_to_dae_value(singbox_json: &str) -> Result<dae::ast::DaeConfig> {
    singbox_to_dae_value_with_opts(singbox_json, &ConvertOptions::default())
}

pub fn singbox_to_dae_value_with_opts(
    singbox_json: &str,
    _opts: &ConvertOptions,
) -> Result<dae::ast::DaeConfig> {
    #[cfg(feature = "comment-defaults")]
    let comment_defaults = comment_defaults::extract_singbox_comment_dae(singbox_json);

    let json = singbox::jsonc::strip_jsonc(singbox_json);
    let sing_config: singbox::config::SingBoxConfig = serde_json::from_str(&json)?;
    let mut dae_config = convert::sing_to_dae::convert(&sing_config)?;

    #[cfg(feature = "comment-defaults")]
    if let Some(overrides) = comment_defaults {
        comment_defaults::merge_dae_config(&mut dae_config, &overrides);
    }

    Ok(dae_config)
}

#[cfg(feature = "wasm")]
mod wasm_exports {
    use wasm_bindgen::prelude::*;

    use crate::ConvertOptions;

    #[wasm_bindgen]
    pub fn dae_to_singbox(dae_text: &str) -> std::result::Result<String, JsError> {
        crate::dae_to_singbox(dae_text).map_err(JsError::from)
    }

    #[wasm_bindgen]
    pub fn dae_to_singbox_with_opts(
        dae_text: &str,
        prerelease: bool,
    ) -> std::result::Result<String, JsError> {
        let opts = ConvertOptions { prerelease };
        crate::dae_to_singbox_with_opts(dae_text, &opts).map_err(JsError::from)
    }

    #[wasm_bindgen]
    pub fn singbox_to_dae(singbox_json: &str) -> std::result::Result<String, JsError> {
        crate::singbox_to_dae(singbox_json).map_err(JsError::from)
    }

    #[wasm_bindgen]
    pub fn singbox_to_dae_with_opts(
        singbox_json: &str,
        prerelease: bool,
    ) -> std::result::Result<String, JsError> {
        let opts = ConvertOptions { prerelease };
        crate::singbox_to_dae_with_opts(singbox_json, &opts).map_err(JsError::from)
    }
}
