use crate::{feature_extractor::Features, heuristics, ml_model, errors::PhishingDetectorError};

#[derive(Debug, serde::Serialize)]
pub struct ClassificationResult {
    pub is_phishing: bool,
    pub confidence: f32,
    pub reasons: Vec<String>,
}

pub fn classify(features: &Features) -> Result<ClassificationResult, PhishingDetectorError> {
    let heuristic_result = heuristics::apply_heuristics(features);
    let ml_result = ml_model::predict(features)?;

    // Combine heuristic and ML scores (weighted average)
    let confidence = (heuristic_result.score * 0.4 + ml_result.probability * 0.6).min(100.0);
    let is_phishing = confidence > 60.0;

    let mut reasons = heuristic_result.reasons;
    reasons.push(format!("ML model probability: {:.2}%", ml_result.probability));

    Ok(ClassificationResult {
        is_phishing,
        confidence,
        reasons,
    })
}