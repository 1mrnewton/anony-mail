//! Server-side OTP / verification-code extraction (docs/05 §1, feeding the
//! push payload of docs/06).
//!
//! Scans the subject and the beginning of the plain-text body for the code
//! patterns transactional mail actually uses. Deliberately conservative:
//! a missed code costs one tap in the client, a false positive puts garbage
//! on the user's lock screen.

use std::sync::LazyLock;

use regex::Regex;

/// Only this much of the body is scanned: codes live at the top of OTP mail,
/// and this bounds work on attacker-sized bodies.
const BODY_SCAN_LIMIT: usize = 4096;

/// Normalized code length bounds (digits only, separators stripped).
const MIN_DIGITS: usize = 4;
const MAX_DIGITS: usize = 8;

/// Google-style `G-123456`. The prefix is branding; the digits are the code.
static G_CODE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bG-(\d{6})\b").expect("valid regex"));

/// `<keyword> ... <digits>`: "your verification code is 123456",
/// "PIN: 4821", "one-time password 98217465", "code 123 456".
static KEYWORD_THEN_DIGITS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(?:code|otp|pin|passcode|password|contrase\u{f1}a)\b\D{0,24}?(\d(?:[\d \t-]{2,10}\d)?)\b",
    )
    .expect("valid regex")
});

/// `<digits> ... <keyword>`: "123456 is your verification code".
static DIGITS_THEN_KEYWORD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(\d(?:[\d \t-]{2,10}\d)?)\b[^\r\n]{0,40}?\b(?:code|otp|pin|passcode)\b")
        .expect("valid regex")
});

/// Alphanumeric codes, keyword-anchored only: "your code is 7XK4P9". Requires
/// letters+digits mixed so plain words never match.
static KEYWORD_THEN_ALNUM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i:\b(?:code|otp|passcode)\b)[^\r\nA-Za-z0-9]{1,16}([A-Z0-9]{5,10})\b")
        .expect("valid regex")
});

/// Extract the most likely one-time code from a message's subject and text
/// body. Returns the normalized code (digits, or the matched alphanumeric
/// token) or `None` when nothing trustworthy is found.
pub fn extract(subject: Option<&str>, text_body: Option<&str>) -> Option<String> {
    let subject = subject.unwrap_or("");
    let body = text_body.unwrap_or("");
    let body = &body[..floor_char_boundary(body, BODY_SCAN_LIMIT)];

    // Subject first: OTP senders put the code there for exactly this purpose.
    for haystack in [subject, body] {
        if let Some(code) = scan_anchored(haystack) {
            return Some(code);
        }
    }

    // Fallback: a code standing alone on its own line (or as the entire
    // subject) — common for big centered codes in HTML mail whose text part
    // is just the digits.
    subject
        .lines()
        .chain(body.lines())
        .find_map(standalone_code)
}

/// Keyword-anchored patterns, most specific first.
fn scan_anchored(haystack: &str) -> Option<String> {
    if let Some(caps) = G_CODE.captures(haystack) {
        return Some(caps[1].to_string());
    }
    for re in [&*KEYWORD_THEN_DIGITS, &*DIGITS_THEN_KEYWORD] {
        if let Some(code) = re
            .captures_iter(haystack)
            .filter_map(|caps| normalize_digits(&caps[1]))
            .next()
        {
            return Some(code);
        }
    }
    if let Some(caps) = KEYWORD_THEN_ALNUM.captures(haystack) {
        let token = &caps[1];
        let digits = token.chars().filter(char::is_ascii_digit).count();
        let letters = token.chars().filter(char::is_ascii_alphabetic).count();
        if digits >= 2 && letters >= 1 {
            return Some(token.to_string());
        }
    }
    None
}

/// A line that consists of nothing but a plausible code.
fn standalone_code(line: &str) -> Option<String> {
    let line = line.trim();
    if line.is_empty() || line.len() > MAX_DIGITS {
        return None;
    }
    if !line.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let code = normalize_digits(line)?;
    // A bare 4-digit line in the plausible-year range is far more likely a
    // year (copyright footers, dates) than a code.
    if code.len() == 4 && (1900..=2099).contains(&code.parse::<u32>().ok()?) {
        return None;
    }
    Some(code)
}

/// Strip separators from a digit run ("123 456" / "123-456" → "123456") and
/// keep it only if the result is a sane code length.
fn normalize_digits(raw: &str) -> Option<String> {
    let digits: String = raw.chars().filter(char::is_ascii_digit).collect();
    ((MIN_DIGITS..=MAX_DIGITS).contains(&digits.len())).then_some(digits)
}

/// Largest index `<= max` that lies on a `char` boundary of `s`.
fn floor_char_boundary(s: &str, max: usize) -> usize {
    if max >= s.len() {
        return s.len();
    }
    (0..=max)
        .rev()
        .find(|&i| s.is_char_boundary(i))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(text: &str) -> Option<String> {
        extract(None, Some(text))
    }

    #[test]
    fn keyword_then_digits() {
        assert_eq!(
            body("Your verification code is 123456."),
            Some("123456".into())
        );
        assert_eq!(body("Use code 4821 to continue"), Some("4821".into()));
        assert_eq!(body("PIN: 9134"), Some("9134".into()));
        assert_eq!(
            body("Your one-time password: 98217465"),
            Some("98217465".into())
        );
        assert_eq!(body("code\n123456"), Some("123456".into()));
    }

    #[test]
    fn digits_then_keyword() {
        assert_eq!(body("483920 is your Instagram code"), Some("483920".into()));
        assert_eq!(
            extract(Some("774213 is your verification code"), None),
            Some("774213".into())
        );
    }

    #[test]
    fn google_style_g_code() {
        assert_eq!(
            body("G-482913 is your Google verification code"),
            Some("482913".into())
        );
    }

    #[test]
    fn separated_digit_groups_are_normalized() {
        assert_eq!(body("Your code is 123 456"), Some("123456".into()));
        assert_eq!(body("Your code is 123-456"), Some("123456".into()));
    }

    #[test]
    fn alphanumeric_codes_require_keyword_and_mixed_chars() {
        assert_eq!(body("Your code: 7XK4P9"), Some("7XK4P9".into()));
        assert_eq!(body("Enter the code ABCDEF"), None, "letters only");
        assert_eq!(body("no keyword 7XK4P9 here"), None, "needs the keyword");
    }

    #[test]
    fn standalone_line_code() {
        assert_eq!(
            body("Here is your code:\n\n  482913  \n\nThanks!"),
            Some("482913".into())
        );
        assert_eq!(extract(Some("482913"), None), Some("482913".into()));
    }

    #[test]
    fn subject_wins_over_body() {
        assert_eq!(
            extract(
                Some("Your code is 111111"),
                Some("Previously we sent 222222 as your code")
            ),
            Some("111111".into())
        );
    }

    #[test]
    fn years_and_noise_do_not_match() {
        assert_eq!(body("Meeting on 2026-08-21 at 10:00"), None);
        assert_eq!(body("\u{a9} 2026 Example Corp\n"), None, "footer year");
        assert_eq!(body("Order #123456 shipped"), None, "no code keyword");
        assert_eq!(body("Call us: +1 555 0123 456"), None);
        assert_eq!(body("Your password must be at least 8 characters"), None);
        assert_eq!(body(""), None);
        assert_eq!(extract(None, None), None);
    }

    #[test]
    fn code_length_bounds_hold() {
        assert_eq!(body("Your code is 123"), None, "too short");
        assert_eq!(body("Your code is 123456789"), None, "too long");
    }

    #[test]
    fn truncation_respects_utf8_boundaries() {
        // 3-byte chars guarantee the byte limit falls mid-character.
        let mut long = "\u{20ac}".repeat(BODY_SCAN_LIMIT);
        long.push_str("Your code is 123456");
        assert_eq!(body(&long), None, "code past the scan limit is ignored");
    }
}
