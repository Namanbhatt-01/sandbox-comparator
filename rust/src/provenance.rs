pub fn escape_rfc6901_token(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

pub fn unescape_rfc6901_token(token: &str) -> String {
    token.replace("~1", "/").replace("~0", "~")
}

pub fn truncate_utf8(s: &str, max_chars: usize) -> &str {
    match s.char_indices().nth(max_chars) {
        None => s,
        Some((idx, _)) => &s[..idx],
    }
}

pub fn preview_str(s: &str, max_chars: usize) -> String {
    match s.char_indices().nth(max_chars) {
        None => s.to_string(),
        Some((idx, _)) => format!("{}...", &s[..idx]),
    }
}

pub fn build_rfc6901_pointer(tokens: &[String]) -> String {
    if tokens.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    for t in tokens {
        out.push('/');
        out.push_str(&escape_rfc6901_token(t));
    }
    out
}

pub fn resolve_json_pointer<'a>(
    doc: &'a serde_json::Value,
    pointer: &str,
) -> Result<&'a serde_json::Value, String> {
    if pointer.is_empty() {
        return Ok(doc);
    }
    if !pointer.starts_with('/') {
        return Err(format!("Invalid RFC 6901 pointer: must start with '/': {}", pointer));
    }

    let mut current = doc;
    for raw_part in pointer[1..].split('/') {
        let key = unescape_rfc6901_token(raw_part);
        match current {
            serde_json::Value::Object(map) => {
                if let Some(val) = map.get(&key) {
                    current = val;
                } else {
                    return Err(format!("Key '{}' not found in JSON object", key));
                }
            }
            serde_json::Value::Array(arr) => {
                if let Ok(idx) = key.parse::<usize>() {
                    if idx < arr.len() {
                        current = &arr[idx];
                    } else {
                        return Err(format!("Index {} out of bounds (len: {})", idx, arr.len()));
                    }
                } else {
                    return Err(format!("Cannot index JSON array with non-integer '{}'", key));
                }
            }
            _ => return Err(format!("Cannot traverse into primitive JSON value with key '{}'", key)),
        }
    }

    Ok(current)
}

