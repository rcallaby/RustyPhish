#[cfg(test)]
mod tests {
    use super::*;
    use crate::Email;

    #[test]
    fn test_extract_features_basic() {
        let email = Email {
            sender: "test@domain.com".to_string(),
            subject: "Test".to_string(),
            body: "Body with urgent".to_string(),
            urls: vec!["http://example.com".to_string()],
        };
        let features = extract_features(&email).unwrap();
        assert!(features.has_urgent_language);
        assert_eq!(features.url_count, 1);
        assert_eq!(features.suspicious_urls, 0);
    }

    #[test]
    fn test_extract_features_suspicious() {
        let email = Email {
            sender: "fake@xyz".to_string(),
            subject: "Urgent".to_string(),
            body: "Click http://192.168.1.1".to_string(),
            urls: vec!["http://192.168.1.1".to_string()],
        };
        let features = extract_features(&email).unwrap();
        assert!(features.has_ip_in_url);
        assert!(features.has_urgent_language);
    }
}