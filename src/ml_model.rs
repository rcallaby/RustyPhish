use crate::{feature_extractor::Features, errors::PhishingDetectorError};

pub struct MlResult {
    pub probability: f32,
    pub is_phishing: bool,
}

pub fn predict(features: &Features) -> Result<MlResult, PhishingDetectorError> {
    // Simulated ML model (replace with real model integration, e.g., ONNX)
    let probability = (features.keyword_score * 0.2 + features.suspicious_urls as f32 * 0.3
        + if features.has_urgent_language { 0.3 } else { 0.0 }) * 100.0;
    let is_phishing = probability > 50.0;

    Ok(MlResult {
        probability,
        is_phishing,
    })
}