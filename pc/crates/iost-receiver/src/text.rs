//! Untrusted text from the phone (device names, logs) shown in the terminal.

/// Characters that can reorder or hide text: controls, bidi overrides/isolates/marks,
/// zero-width characters, the BOM and soft hyphen (THREAT_MODEL N8).
pub fn is_deceptive(c: char) -> bool {
    c.is_control()
        || matches!(c,
            '\u{00AD}' | '\u{061C}' | '\u{180E}' | '\u{FEFF}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2069}')
}

/// Escape everything a terminal could interpret or that could visually spoof a prompt.
pub fn escape_for_terminal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if is_deceptive(c) {
            out.extend(c.escape_unicode());
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spoofing_characters_are_escaped() {
        assert_eq!(escape_for_terminal("a\u{202E}b"), "a\\u{202e}b");
        assert_eq!(escape_for_terminal("x\u{1b}[31my"), "x\\u{1b}[31my");
        assert_eq!(escape_for_terminal("Ana's 📷"), "Ana's 📷");
        assert!(is_deceptive('\u{200D}') && is_deceptive('\u{2066}') && !is_deceptive('é'));
    }
}
