use crate::errors::PhishingDetectorError;
use regex::Regex;
use std::ffi::CStr;
use std::os::raw::{c_char, c_int};
use std::ptr;

#[no_mangle]
pub extern "C" fn extract_urls_ffi(input: *const c_char) -> *mut c_char {
    let input = unsafe {
        if input.is_null() {
            return ptr::null_mut();
        }
        CStr::from_ptr(input).to_str().unwrap_or("")
    };

    let urls = match extract_urls(input) {
        Ok(urls) => urls.join("\n"),
        Err(_) => String::new(),
    };

    let c_str = std::ffi::CString::new(urls).unwrap_or_default();
    c_str.into_raw()
}

#[no_mangle]
pub extern "C" fn free_urls_ffi(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = std::ffi::CString::from_raw(ptr);
        }
    }
}

pub fn extract_urls(input: &str) -> Result<Vec<String>, PhishingDetectorError> {
    let re = Regex::new(r"https?://[^\s<>\"']+").map_err(PhishingDetectorError::RegexError)?;
    let urls = re
        .find_iter(input)
        .map(|m| m.as_str().to_string())
        .collect();
    Ok(urls)
}