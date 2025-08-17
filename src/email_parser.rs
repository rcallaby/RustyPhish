use crate::errors::PhishingDetectorError;

#[derive(Debug, serde::Serialize)]
pub struct Email {
    pub sender: String,
    pub subject: String,
    pub body: String,
    pub urls: Vec<String>,
}

pub fn parse_email(content: &str) -> Result<Email, PhishingDetectorError> {
    let mut sender = String::new();
    let mut subject = String::new();
    let mut body = String::new();
    let mut urls = Vec::new();
    let mut in_body = false;

    for line in content.lines() {
        if line.is_empty() && !in_body {
            in_body = true;
            continue;
        }
        if !in_body {
            if line.starts_with("From: ") {
                sender = line[6..].trim().to_string();
            } else if line.starts_with("Subject: ") {
                subject = line[9..].trim().to_string();
            }
        } else {
            body.push_str(line);
            body.push('\n');
        }
    }

    // Extract URLs using C++ FFI for performance
    urls = crate::ffi::extract_urls(&body)?;

    Ok(Email {
        sender,
        subject,
        body: body.trim().to_string(),
        urls,
    })
}