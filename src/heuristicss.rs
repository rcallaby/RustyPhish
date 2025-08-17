use crate::feature_extractor::Features;

pub struct HeuristicResult {
    pub score: f32,
    pub reasons: Vec<String>,
}

pub fn apply_heuristics(features: &Features) -> HeuristicResult {
    let mut score = 0.0;
    let mut reasons = Vec::new();

    if features.has_urgent_language {
        score += 30.0;
        reasons.push("Contains urgent language".to_string());
    }
    if features.suspicious_urls > 0 {
        score += 40.0;
        reasons.push(format!("Found {} suspicious URLs", features.suspicious_urls));
    }
    if !features.sender_domain.contains('.') || features.sender_domain.len() < 3 {
        score += 20.0;
        reasons.push("Invalid or missing sender domain".to_string());
    }
    score += features.keyword_score * 10.0;

    HeuristicResult { score, reasons }
}