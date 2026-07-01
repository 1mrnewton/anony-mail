/// The subset of SMTP commands an inbound-only receiver needs to understand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Helo(String),
    Ehlo(String),
    /// `MAIL FROM:<path>`. The inner string is the extracted reverse-path;
    /// empty means the null sender (`<>`).
    MailFrom(String),
    /// `RCPT TO:<path>`. The inner string is the extracted forward-path.
    RcptTo(String),
    Data,
    Rset,
    Noop,
    Quit,
    StartTls,
    Vrfy,
    Help,
    /// Any command we don't implement.
    Unknown(String),
}

impl Command {
    /// Parse a single command line (already stripped of the trailing CRLF).
    pub fn parse(line: &str) -> Command {
        let trimmed = line.trim();
        let mut parts = trimmed.splitn(2, char::is_whitespace);
        let verb = parts.next().unwrap_or("").to_ascii_uppercase();
        let rest = parts.next().unwrap_or("").trim();

        match verb.as_str() {
            "HELO" => Command::Helo(rest.to_string()),
            "EHLO" => Command::Ehlo(rest.to_string()),
            "MAIL" => match extract_path(rest, "FROM") {
                Some(addr) => Command::MailFrom(addr),
                None => Command::Unknown(trimmed.to_string()),
            },
            "RCPT" => match extract_path(rest, "TO") {
                Some(addr) => Command::RcptTo(addr),
                None => Command::Unknown(trimmed.to_string()),
            },
            "DATA" => Command::Data,
            "RSET" => Command::Rset,
            "NOOP" => Command::Noop,
            "QUIT" => Command::Quit,
            "STARTTLS" => Command::StartTls,
            "VRFY" => Command::Vrfy,
            "HELP" => Command::Help,
            _ => Command::Unknown(trimmed.to_string()),
        }
    }
}

/// Extract the address from a `MAIL FROM:` / `RCPT TO:` argument string.
///
/// Accepts both angle-bracketed (`FROM:<a@b>`) and bare (`FROM:a@b`) forms and
/// tolerates optional whitespace after the colon and trailing ESMTP params.
/// Returns `None` if the expected `keyword:` token is missing.
fn extract_path(args: &str, keyword: &str) -> Option<String> {
    let lower = args.to_ascii_lowercase();
    let needle = format!("{}:", keyword.to_ascii_lowercase());
    let idx = lower.find(&needle)?;
    let after = args[idx + needle.len()..].trim_start();

    if let Some(open) = after.find('<') {
        let rest = &after[open + 1..];
        let close = rest.find('>')?;
        Some(rest[..close].trim().to_string())
    } else {
        // Bare address form: take up to the first whitespace (params follow).
        Some(after.split_whitespace().next().unwrap_or("").to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_verbs_case_insensitively() {
        assert_eq!(
            Command::parse("ehlo mail.example.com"),
            Command::Ehlo("mail.example.com".into())
        );
        assert_eq!(Command::parse("QUIT"), Command::Quit);
        assert_eq!(Command::parse("data"), Command::Data);
        assert_eq!(Command::parse("NoOp"), Command::Noop);
        assert_eq!(Command::parse("StartTLS"), Command::StartTls);
    }

    #[test]
    fn parses_mail_from_variants() {
        assert_eq!(
            Command::parse("MAIL FROM:<a@b.com>"),
            Command::MailFrom("a@b.com".into())
        );
        assert_eq!(
            Command::parse("MAIL FROM: <a@b.com>"),
            Command::MailFrom("a@b.com".into())
        );
        assert_eq!(
            Command::parse("MAIL FROM:<a@b.com> SIZE=1000"),
            Command::MailFrom("a@b.com".into())
        );
        assert_eq!(
            Command::parse("MAIL FROM:a@b.com"),
            Command::MailFrom("a@b.com".into())
        );
        // Null sender (bounce messages).
        assert_eq!(Command::parse("MAIL FROM:<>"), Command::MailFrom("".into()));
    }

    #[test]
    fn parses_rcpt_to() {
        assert_eq!(
            Command::parse("RCPT TO:<user@domain.com>"),
            Command::RcptTo("user@domain.com".into())
        );
        assert_eq!(
            Command::parse("rcpt to:<USER@Domain.com>"),
            Command::RcptTo("USER@Domain.com".into())
        );
    }

    #[test]
    fn unknown_commands_are_captured() {
        assert_eq!(
            Command::parse("FOOBAR x y"),
            Command::Unknown("FOOBAR x y".into())
        );
    }
}
