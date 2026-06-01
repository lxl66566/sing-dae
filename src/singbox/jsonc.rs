/// Strip JSONC (JSON with comments) to valid JSON.
/// Handles:
/// - single-line comments `// ...`
/// - multi-line comments `/* ... */`
/// - trailing commas before `]` or `}`
/// - string literals are preserved (comments inside strings are not stripped)
pub fn strip_jsonc(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let chars: Vec<char> = input.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        match chars[i] {
            '"' => {
                out.push('"');
                i += 1;
                while i < len {
                    if chars[i] == '\\' {
                        out.push(chars[i]);
                        i += 1;
                        if i < len {
                            out.push(chars[i]);
                            i += 1;
                        }
                        continue;
                    }
                    out.push(chars[i]);
                    if chars[i] == '"' {
                        i += 1;
                        break;
                    }
                    i += 1;
                }
            }
            '/' if i + 1 < len && chars[i + 1] == '/' => {
                i += 2;
                while i < len && chars[i] != '\n' {
                    i += 1;
                }
            }
            '/' if i + 1 < len && chars[i + 1] == '*' => {
                i += 2;
                while i + 1 < len && !(chars[i] == '*' && chars[i + 1] == '/') {
                    i += 1;
                }
                if i + 1 < len {
                    i += 2;
                }
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }

    strip_trailing_commas(&out)
}

fn strip_trailing_commas(input: &str) -> String {
    let trimmed = input.as_bytes();
    let len = trimmed.len();
    let mut out = Vec::with_capacity(len);
    let mut i = 0;

    while i < len {
        if trimmed[i] == b'"' {
            out.push(trimmed[i]);
            i += 1;
            while i < len {
                if trimmed[i] == b'\\' {
                    out.push(trimmed[i]);
                    i += 1;
                    if i < len {
                        out.push(trimmed[i]);
                        i += 1;
                    }
                    continue;
                }
                out.push(trimmed[i]);
                if trimmed[i] == b'"' {
                    i += 1;
                    break;
                }
                i += 1;
            }
            continue;
        }

        if trimmed[i] == b',' {
            let mut j = i + 1;
            while j < len && (trimmed[j] == b' ' || trimmed[j] == b'\t' || trimmed[j] == b'\n' || trimmed[j] == b'\r') {
                j += 1;
            }
            if j < len && (trimmed[j] == b']' || trimmed[j] == b'}') {
                i += 1;
                continue;
            }
        }

        out.push(trimmed[i]);
        i += 1;
    }

    String::from_utf8(out).unwrap_or(input.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_single_line_comment() {
        let input = r#"{"a": 1 // comment
}"#;
        assert_eq!(strip_jsonc(input), "{\"a\": 1 \n}");
    }

    #[test]
    fn strip_multi_line_comment() {
        let input = r#"{"a": /* comment */ 1}"#;
        assert_eq!(strip_jsonc(input), "{\"a\":  1}");
    }

    #[test]
    fn strip_trailing_comma_array() {
        let input = r#"{"a": [1, 2,]}"#;
        assert_eq!(strip_jsonc(input), "{\"a\": [1, 2]}");
    }

    #[test]
    fn strip_trailing_comma_object() {
        let input = r#"{"a": 1,}"#;
        assert_eq!(strip_jsonc(input), "{\"a\": 1}");
    }

    #[test]
    fn preserve_comment_in_string() {
        let input = r#"{"url": "http://example.com//path"}"#;
        assert_eq!(strip_jsonc(input), "{\"url\": \"http://example.com//path\"}");
    }

    #[test]
    fn complex_jsonc() {
        let input = r#"{
            // This is a comment
            "log": { "level": "info", },
            /* multi
               line */
            "dns": ["a", "b",]
        }"#;
        let result = strip_jsonc(input);
        assert!(!result.contains("//"));
        assert!(!result.contains("/*"));
        assert!(result.contains("\"log\""));
        assert!(!result.contains(",}"));
        assert!(!result.contains(",]"));
    }
}
