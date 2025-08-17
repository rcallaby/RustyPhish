use thiserror::Error;

#[derive(Error, Debug)]
pub enum PhishingDetectorError {
    #[error("Failed to parse email: {0}")]
    ParseError(String),
    #[error("Feature extraction failed: {0}")]
    FeatureExtractionError(String),
    #[error("Classification failed: {0}")]
    ClassificationError(String),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("Regex error: {0}")]
    RegexError(#[from] regex::Error),
    #[error("URL parsing error: {0}")]
    UrlError(#[from] url::ParseError),
}