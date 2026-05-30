use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Serialize error: {0}")]
    Serialize(String),

    #[error("Conversion error: {0}")]
    Conversion(String),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

impl From<pest::error::Error<crate::dae::parser::Rule>> for AppError {
    fn from(err: pest::error::Error<crate::dae::parser::Rule>) -> Self {
        Self::Parse(err.to_string())
    }
}

pub type Result<T> = std::result::Result<T, AppError>;
