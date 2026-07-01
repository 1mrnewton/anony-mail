use chrono::{DateTime, Utc};
use mail_parser::{Addr, MessageParser, MimeHeaders};

use crate::model::{NewAttachment, NewMessage};

/// Parse raw RFC 5322 message bytes into a persistable [`NewMessage`].
///
/// `envelope_from` is the SMTP `MAIL FROM` address, used as a fallback display
/// sender when the message has no parseable `From:` header. Parsing is
/// best-effort: a message that fails to parse still yields a `NewMessage` with
/// empty bodies so nothing delivered to a valid recipient is silently dropped.
pub fn parse_message(raw: &[u8], envelope_from: &str) -> NewMessage {
    let raw_size = raw.len().min(i32::MAX as usize) as i32;

    let Some(message) = MessageParser::default().parse(raw) else {
        return NewMessage {
            mail_from: envelope_from.to_string(),
            subject: None,
            message_date: None,
            text_body: None,
            html_body: None,
            raw_size,
            attachments: Vec::new(),
        };
    };

    let mail_from = message
        .from()
        .and_then(|addr| addr.first())
        .map(format_addr)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| envelope_from.to_string());

    let subject = message.subject().map(str::to_string);

    let message_date = message
        .date()
        .and_then(|d| DateTime::parse_from_rfc3339(&d.to_rfc3339()).ok())
        .map(|d| d.with_timezone(&Utc));

    let text_body = message.body_text(0).map(|c| c.into_owned());
    let html_body = message.body_html(0).map(|c| c.into_owned());

    let attachments = message
        .attachments()
        .filter(|part| !part.is_multipart())
        .map(|part| {
            let content_type = part
                .content_type()
                .map(|ct| match ct.subtype() {
                    Some(sub) => format!("{}/{}", ct.ctype(), sub),
                    None => ct.ctype().to_string(),
                })
                .unwrap_or_else(|| "application/octet-stream".to_string());

            NewAttachment {
                filename: part.attachment_name().map(str::to_string),
                content_type,
                content: part.contents().to_vec(),
            }
        })
        .collect();

    NewMessage {
        mail_from,
        subject,
        message_date,
        text_body,
        html_body,
        raw_size,
        attachments,
    }
}

/// Render an [`Addr`] as a display string: `"Name <email>"`, or just the email
/// (or name) when only one is present.
fn format_addr(addr: &Addr) -> String {
    let name = addr
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let email = addr
        .address
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    match (name, email) {
        (Some(name), Some(email)) => format!("{name} <{email}>"),
        (None, Some(email)) => email.to_string(),
        (Some(name), None) => name.to_string(),
        (None, None) => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_plaintext_message() {
        let raw = b"From: Alice <alice@example.com>\r\n\
Subject: Hello there\r\n\
Date: Sat, 20 Nov 2021 14:22:01 -0800\r\n\
Content-Type: text/plain\r\n\
\r\n\
This is the body.\r\n";

        let parsed = parse_message(raw, "envelope@sender.test");
        assert_eq!(parsed.mail_from, "Alice <alice@example.com>");
        assert_eq!(parsed.subject.as_deref(), Some("Hello there"));
        assert!(parsed.text_body.unwrap().contains("This is the body."));
        assert!(parsed.attachments.is_empty());
        assert!(parsed.message_date.is_some());
    }

    #[test]
    fn falls_back_to_envelope_sender_when_no_from_header() {
        let raw = b"Subject: No from header\r\n\r\nbody\r\n";
        let parsed = parse_message(raw, "envelope@sender.test");
        assert_eq!(parsed.mail_from, "envelope@sender.test");
    }

    #[test]
    fn extracts_attachment_with_filename_and_type() {
        let raw = b"From: bob@example.com\r\n\
Subject: With attachment\r\n\
Content-Type: multipart/mixed; boundary=\"sep\"\r\n\
\r\n\
--sep\r\n\
Content-Type: text/plain\r\n\
\r\n\
see attached\r\n\
--sep\r\n\
Content-Type: text/csv; name=\"data.csv\"\r\n\
Content-Disposition: attachment; filename=\"data.csv\"\r\n\
\r\n\
a,b,c\r\n\
--sep--\r\n";

        let parsed = parse_message(raw, "envelope@sender.test");
        assert_eq!(parsed.attachments.len(), 1);
        let att = &parsed.attachments[0];
        assert_eq!(att.filename.as_deref(), Some("data.csv"));
        assert_eq!(att.content_type, "text/csv");
        assert!(!att.content.is_empty());
    }
}
