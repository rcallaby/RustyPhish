fn main() {
    cc::Build::new()
        .file("cpp/url_extractor.cpp")
        .flag_if_supported("-std=c++11")
        .compile("url_extractor");
}