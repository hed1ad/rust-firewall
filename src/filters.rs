use regex::Regex;

pub fn is_malicious(content: &str) -> bool {
    let patterns = vec![
        r"(?i)union\s+select",
        r"(?i)drop\s+table",
        r"(?i)<script>",
        r"(?i)onerror\s*=",
        r"(?i)javascript:"
    ];

    for pat in patterns {
        let re = Regex::new(pat).unwrap();
        if re.is_match(content) {
            return true;
        }
    }

    false
}

