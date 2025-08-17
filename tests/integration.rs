#[cfg(test)]
mod tests {
    use crate::{analyze_emails, PhishingDetectorError};
    use serde_json::Value;

    #[test]
    fn test_phishing_with_ip_and_urgent() -> Result<(), PhishingDetectorError> {
        let emails = vec![
            r#"From: alert@bank-secure.xyz
Subject: Urgent Account Verification Required!
Click here: http://192.168.1.1/verify now to avoid suspension."#.to_string(),
        ];
        let results = analyze_emails(emails)?;
        let json: Value = serde_json::from_str(&results[0])?;
        assert!(json["is_phishing"].as_bool().unwrap());
        assert!(json["confidence"].as_f64().unwrap() > 70.0);
        let reasons = json["reasons"].as_array().unwrap();
        assert!(reasons.iter().any(|r| r.as_str().unwrap().contains("IP address in URL")));
        assert!(reasons.iter().any(|r| r.as_str().unwrap().contains("Urgent language")));
        Ok(())
    }

    #[test]
    fn test_legitimate_with_urgent_language() -> Result<(), PhishingDetectorError> {
        let emails = vec![
            r#"From: support@realbank.com
Subject: Important: Update Your Password
Please visit https://realbank.com/settings to update your password as per policy."#.to_string(),
        ];
        let results = analyze_emails(emails)?;
        let json: Value = serde_json::from_str(&results[0])?;
        assert!(!json["is_phishing"].as_bool().unwrap());
        assert!(json["confidence"].as_f64().unwrap() < 50.0);
        Ok(())
    }

    #[test]
    fn test_phishing_with_at_symbol_and_suspicious_tld() -> Result<(), PhishingDetectorError> {
        let emails = vec![
            r#"From: admin@phish.top
Subject: Action Required: Secure Your Account
Login at http://secure@phish.top/login"#.to_string(),
        ];
        let results = analyze_emails(emails)?;
        let json: Value = serde_json::from_str(&results[0])?;
        assert!(json["is_phishing"].as_bool().unwrap());
        let reasons = json["reasons"].as_array().unwrap();
        assert!(reasons.iter().any(|r| r.as_str().unwrap().contains("@ symbol in URL")));
        assert!(reasons.iter().any(|r| r.as_str().unwrap().contains("suspicious URLs")));
        Ok(())
    }

    #[test]
    fn test_empty_email() -> Result<(), PhishingDetectorError> {
        let emails = vec!["".to_string()];
        let results = analyze_emails(emails)?;
        let json: Value = serde_json::from_str(&results[0])?;
        assert!(!json["is_phishing"].as_bool().unwrap()); // Default to non-phishing for empty
        assert_eq!(json["confidence"].as_f64().unwrap(), 0.0);
        Ok(())
    }

    #[test]
    fn test_malformed_headers_no_sender() -> Result<(), PhishingDetectorError> {
        let emails = vec![
            r#"Subject: Verify Now
Body text with http://malicious.ru"#.to_string(),
        ];
        let results = analyze_emails(emails)?;
        let json: Value = serde_json::from_str(&results[0])?;
        assert!(json["is_phishing"].as_bool().unwrap());
        let reasons = json["reasons"].as_array().unwrap();
        assert!(reasons.iter().any(|r| r.as_str().unwrap().contains("Invalid sender domain")));
        Ok(())
    }

    #[test]
    fn test_multiple_urls_mixed_https() -> Result<(), PhishingDetectorError> {
        let emails = vec![
            r#"From: info@legit.com
Subject: Newsletter
Links: https://legit.com, http://insecure.biz, https://safe.com"#.to_string(),
        ];
        let results = analyze_emails(emails)?;
        let json: Value = serde_json::from_str(&results[0])?;
        assert!(json["is_phishing"].as_bool().unwrap()); // Suspicious due to mixed HTTPS and TLD
        let reasons = json["reasons"].as_array().unwrap();
        assert!(reasons.iter().any(|r| r.as_str().unwrap().contains("Low HTTPS usage")));
        assert!(reasons.iter().any(|r| r.as_str().unwrap().contains("suspicious URLs")));
        Ok(())
    }

    #[test]
    fn test_batch_mixed_emails() -> Result<(), PhishingDetectorError> {
        let emails = vec![
            r#"From: fake@malicious.xyz
Subject: Urgent: Verify Account!
Click: http://192.168.1.1/verify"@example.com"#.to_string(),
            r#"From: support@trusted.com
Subject: Welcome
Visit: https://trusted.com"#.to_string(),
            r#"From: promo@offer.ru
Subject: Win Prize Now!
Enter: http://prize.ru/claim"#.to_string(),
        ];
        let results = analyze_emails(emails)?;
        let json1: Value = serde_json::from_str(&results[0])?;
        let json2: Value = serde_json::from_str(&results[1])?;
        let json3: Value = serde_json::from_str(&results[2])?;
        assert!(json1["is_phishing"].as_bool().unwrap());
        assert!(!json2["is_phishing"].as_bool().unwrap());
        assert!(json3["is_phishing"].as_bool().unwrap());
        Ok(())
    }

    #[test]
    fn test_deep_subdomains() -> Result<(), PhishingDetectorError> {
        let emails = vec![
            r#"From: service@google.com.security.update.xyz
Subject: Security Alert
Update at http://sub.sub.sub.google.com.security.update.xyz"#.to_string(),
        ];
        let results = analyze_emails(emails)?;
        let json: Value = serde_json::from_str(&results[0])?;
        assert!(json["is_phishing"].as_bool().unwrap());
        let reasons = json["reasons"].as_array().unwrap();
        assert!(reasons.iter().any(|r| r.as_str().unwrap().contains("Deep subdomains")));
        Ok(())
    }

    #[test]
    fn test_no_urls_high_keywords() -> Result<(), PhishingDetectorError> {
        let emails = vec![
            r#"From: alert@bank.com
Subject: Account Suspended - Verify Now
Immediate action required: Call us to verify."#.to_string(),
        ];
        let results = analyze_emails(emails)?;
        let json: Value = serde_json::from_str(&results[0])?;
        assert!(json["is_phishing"].as_bool().unwrap());
        let reasons = json["reasons"].as_array().unwrap();
        assert!(reasons.iter().any(|r| r.as_str().unwrap().contains("Urgent language")));
        Ok(())
    }

    #[test]
    fn test_legitimate_long_url() -> Result<(), PhishingDetectorError> {
        let emails = vec![
            r#"From: news@newsletter.com
Subject: Weekly Update
Read more: https://newsletter.com/articles/very-long-url-with-parameters?query=long&extra=stuff"#.to_string(),
        ];
        let results = analyze_emails(emails)?;
        let json: Value = serde_json::from_str(&results[0])?;
        assert!(!json["is_phishing"].as_bool().unwrap()); // Long URL but legitimate
        Ok(())
    }
}