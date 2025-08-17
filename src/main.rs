use phishing_detector::{analyze_email, PhishingDetectorError};
use std::env;

fn main() -> Result<(), PhishingDetectorError> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <email_content>", args[0]);
        std::process::exit(1);
    }

    let result = analyze_email(&args[1])?;
    println!("{}", result);
    Ok(())
}