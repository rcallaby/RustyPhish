#include <regex>
#include <string>
#include <cstring>

extern "C" {
    char* extract_urls_ffi(const char* input) {
        if (!input) return nullptr;
        std::string text(input);
        std::regex url_regex(R"(https?://[^\s<>"']+)");
        std::smatch match;
        std::string result;
        auto begin = std::sregex_iterator(text.begin(), text.end(), url_regex);
        auto end = std::sregex_iterator();
        for (auto it = begin; it != end; ++it) {
            if (!result.empty()) result += "\n";
            result += it->str();
        }
        char* c_result = new char[result.size() + 1];
        std::strcpy(c_result, result.c_str());
        return c_result;
    }

    void free_urls_ffi(char* ptr) {
        delete[] ptr;
    }
}