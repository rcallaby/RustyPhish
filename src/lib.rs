pub mod email_parser;
pub mod feature_extractor;
pub mod classifier;
pub mod heuristics;
pub mod ml_model;
pub mod logger;
pub mod errors;
pub mod ffi;

use errors::PhishingDetectorError;

pub fn analyze_email(email_content: &str) -> Result<String, PhishingDetectorError> {
    logger::init_logger();
    let email = email_parser::parse_email(email_content)?;
    let features = feature_extractor::extract_features(&email)?;
    let result = classifier::classify(&features)?;
    Ok(serde_json::to_string(&result)?)
}