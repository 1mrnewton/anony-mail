use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use chrono::Utc;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

use super::commands::Command;
use super::tls::MaybeTlsStream;
use crate::config::Config;
use crate::events::{EventBus, MailEvent};
use crate::mime;
use crate::store::Store;

/// Max length of a single command line (generous vs. the RFC's 512).
const COMMAND_LINE_MAX: usize = 4096;

/// Shared dependencies handed to every SMTP session.
#[derive(Clone)]
pub struct SmtpContext {
    pub store: Arc<dyn Store>,
    pub config: Arc<Config>,
    pub events: EventBus,
    pub tls_acceptor: Option<TlsAcceptor>,
}

/// Drive a single inbound SMTP connection to completion. Errors are logged by
/// the caller; a returned `Ok` simply means the connection closed cleanly.
pub async fn handle(stream: TcpStream, peer: SocketAddr, ctx: SmtpContext) -> io::Result<()> {
    let mut session = Session {
        ctx,
        peer,
        helo: None,
        mail_from: None,
        rcpts: Vec::new(),
        tls_active: false,
    };
    session.run(MaybeTlsStream::Plain(stream)).await
}

struct Session {
    ctx: SmtpContext,
    peer: SocketAddr,
    helo: Option<String>,
    mail_from: Option<String>,
    rcpts: Vec<String>,
    tls_active: bool,
}

enum DataOutcome {
    Complete(Vec<u8>),
    TooLarge,
    ConnectionClosed,
}

#[derive(PartialEq)]
enum LineStatus {
    Line,
    Eof,
    TooLong,
}

enum RecipientCheck {
    Accept,
    NotOurDomain,
    NoMailbox,
    Error,
}

impl Session {
    async fn run(&mut self, stream: MaybeTlsStream) -> io::Result<()> {
        let mut stream = BufReader::new(stream);
        let host = self.ctx.config.smtp_hostname.clone();
        write_line(&mut stream, &format!("220 {host} ESMTP anony-mail")).await?;

        let mut line: Vec<u8> = Vec::new();
        loop {
            match self
                .read_line_timed(&mut stream, &mut line, COMMAND_LINE_MAX)
                .await?
            {
                LineStatus::Eof => break,
                LineStatus::TooLong => {
                    write_line(&mut stream, "500 5.5.2 Line too long").await?;
                    break;
                }
                LineStatus::Line => {}
            }

            let text = String::from_utf8_lossy(strip_eol(&line));
            let command = Command::parse(&text);
            debug!(peer = %self.peer, command = ?command, "smtp command");

            match command {
                Command::Quit => {
                    write_line(&mut stream, "221 2.0.0 Bye").await?;
                    break;
                }
                Command::Ehlo(domain) => {
                    self.helo = Some(domain);
                    self.reset_tx();
                    self.write_ehlo(&mut stream).await?;
                }
                Command::Helo(domain) => {
                    self.helo = Some(domain);
                    self.reset_tx();
                    write_line(&mut stream, &format!("250 {host} Hello")).await?;
                }
                Command::MailFrom(addr) => {
                    if self.helo.is_none() {
                        write_line(&mut stream, "503 5.5.1 Send HELO/EHLO first").await?;
                    } else if self.mail_from.is_some() {
                        write_line(&mut stream, "503 5.5.1 Sender already specified").await?;
                    } else {
                        self.mail_from = Some(addr);
                        self.rcpts.clear();
                        write_line(&mut stream, "250 2.1.0 Sender OK").await?;
                    }
                }
                Command::RcptTo(addr) => {
                    self.handle_rcpt(&mut stream, addr).await?;
                }
                Command::Data => {
                    if self.mail_from.is_none() {
                        write_line(&mut stream, "503 5.5.1 Need MAIL before DATA").await?;
                    } else if self.rcpts.is_empty() {
                        write_line(&mut stream, "554 5.5.1 No valid recipients").await?;
                    } else {
                        write_line(&mut stream, "354 Start mail input; end with <CRLF>.<CRLF>")
                            .await?;
                        match self.read_data(&mut stream).await? {
                            DataOutcome::Complete(data) => {
                                match self.store_message(&data).await {
                                    Ok(count) => {
                                        write_line(
                                            &mut stream,
                                            &format!(
                                                "250 2.0.0 Message accepted ({count} recipient(s))"
                                            ),
                                        )
                                        .await?;
                                    }
                                    Err(e) => {
                                        error!(error = %e, "failed to store inbound message");
                                        write_line(
                                            &mut stream,
                                            "451 4.3.0 Could not store message, try again later",
                                        )
                                        .await?;
                                    }
                                }
                                self.reset_tx();
                            }
                            DataOutcome::TooLarge => {
                                write_line(&mut stream, "552 5.3.4 Message too large").await?;
                                self.reset_tx();
                            }
                            DataOutcome::ConnectionClosed => break,
                        }
                    }
                }
                Command::Rset => {
                    self.reset_tx();
                    write_line(&mut stream, "250 2.0.0 OK").await?;
                }
                Command::Noop => {
                    write_line(&mut stream, "250 2.0.0 OK").await?;
                }
                Command::StartTls => {
                    if self.tls_active {
                        write_line(&mut stream, "503 5.5.1 TLS already active").await?;
                    } else if let Some(acceptor) = self.ctx.tls_acceptor.clone() {
                        write_line(&mut stream, "220 2.0.0 Ready to start TLS").await?;
                        stream.flush().await?;
                        // Discard buffered plaintext (RFC 3207 anti-injection) by
                        // dropping the BufReader and taking the raw socket.
                        let plain = match stream.into_inner() {
                            MaybeTlsStream::Plain(tcp) => tcp,
                            already_tls => {
                                stream = BufReader::new(already_tls);
                                continue;
                            }
                        };
                        match acceptor.accept(plain).await {
                            Ok(tls) => {
                                stream = BufReader::new(MaybeTlsStream::Tls(Box::new(tls)));
                                self.tls_active = true;
                                self.helo = None;
                                self.reset_tx();
                            }
                            Err(e) => {
                                debug!(peer = %self.peer, error = %e, "TLS handshake failed");
                                return Ok(());
                            }
                        }
                    } else {
                        write_line(&mut stream, "502 5.5.1 STARTTLS not supported").await?;
                    }
                }
                Command::Vrfy => {
                    write_line(&mut stream, "252 2.5.2 Cannot VRFY user").await?;
                }
                Command::Help => {
                    write_line(&mut stream, "214 2.0.0 anony-mail inbound-only SMTP").await?;
                }
                Command::Unknown(_) => {
                    write_line(&mut stream, "500 5.5.2 Command not recognized").await?;
                }
            }
        }

        let _ = stream.shutdown().await;
        Ok(())
    }

    fn reset_tx(&mut self) {
        self.mail_from = None;
        self.rcpts.clear();
    }

    async fn write_ehlo<W: AsyncWrite + Unpin>(&self, w: &mut W) -> io::Result<()> {
        let host = &self.ctx.config.smtp_hostname;
        let mut caps = vec![
            format!("{host} at your service"),
            format!("SIZE {}", self.ctx.config.max_message_size),
            "8BITMIME".to_string(),
            "PIPELINING".to_string(),
            "ENHANCEDSTATUSCODES".to_string(),
            "SMTPUTF8".to_string(),
        ];
        if self.ctx.tls_acceptor.is_some() && !self.tls_active {
            caps.insert(1, "STARTTLS".to_string());
        }
        write_multiline(w, 250, &caps).await
    }

    async fn handle_rcpt<W: AsyncWrite + Unpin>(
        &mut self,
        w: &mut W,
        addr: String,
    ) -> io::Result<()> {
        if self.mail_from.is_none() {
            return write_line(w, "503 5.5.1 Need MAIL before RCPT").await;
        }
        if self.rcpts.len() >= self.ctx.config.max_recipients {
            return write_line(w, "452 4.5.3 Too many recipients").await;
        }

        let recipient = addr.trim().to_ascii_lowercase();
        match self.validate_recipient(&recipient).await {
            RecipientCheck::Accept => {
                if !self.rcpts.contains(&recipient) {
                    self.rcpts.push(recipient);
                }
                write_line(w, "250 2.1.5 Recipient OK").await
            }
            RecipientCheck::NotOurDomain => {
                write_line(w, "550 5.7.1 Relaying denied, not a local domain").await
            }
            RecipientCheck::NoMailbox => write_line(w, "550 5.1.1 No such user here").await,
            RecipientCheck::Error => {
                write_line(w, "451 4.3.0 Temporary lookup failure, try again later").await
            }
        }
    }

    async fn validate_recipient(&self, addr: &str) -> RecipientCheck {
        let Some((_, domain)) = addr.rsplit_once('@') else {
            return RecipientCheck::NotOurDomain;
        };
        if domain.is_empty() || !self.ctx.config.accepts_domain(domain) {
            return RecipientCheck::NotOurDomain;
        }
        match self.ctx.store.mailbox_is_active(addr, Utc::now()).await {
            Ok(true) => RecipientCheck::Accept,
            Ok(false) => RecipientCheck::NoMailbox,
            Err(e) => {
                warn!(error = %e, address = %addr, "mailbox lookup failed");
                RecipientCheck::Error
            }
        }
    }

    /// Read the DATA phase, honoring dot-unstuffing and the size limit. On
    /// oversize input we keep draining to the terminator so the protocol stays
    /// in sync, then report `TooLarge`.
    async fn read_data<R: AsyncBufRead + Unpin>(&self, r: &mut R) -> io::Result<DataOutcome> {
        let max = self.ctx.config.max_message_size;
        // Allow a single line up to the whole budget; larger => oversize.
        let line_max = max.saturating_add(4);
        let mut data: Vec<u8> = Vec::new();
        let mut line: Vec<u8> = Vec::new();
        let mut too_large = false;

        loop {
            match self.read_line_timed(r, &mut line, line_max).await? {
                LineStatus::Eof => return Ok(DataOutcome::ConnectionClosed),
                LineStatus::TooLong => {
                    // Free anything buffered and keep draining until terminator.
                    if !too_large {
                        too_large = true;
                        data = Vec::new();
                    }
                }
                LineStatus::Line => {
                    if is_terminator(&line) {
                        return Ok(if too_large {
                            DataOutcome::TooLarge
                        } else {
                            DataOutcome::Complete(data)
                        });
                    }
                    if !too_large {
                        // Dot-unstuffing: a leading '.' on a line is escaped.
                        let content: &[u8] = if line.first() == Some(&b'.') {
                            &line[1..]
                        } else {
                            &line
                        };
                        if data.len() + content.len() > max {
                            too_large = true;
                            data = Vec::new();
                        } else {
                            data.extend_from_slice(content);
                        }
                    }
                }
            }
        }
    }

    /// Parse and persist the raw message for every accepted recipient,
    /// publishing an SSE event per stored copy. Returns the recipient count.
    async fn store_message(&self, raw: &[u8]) -> anyhow::Result<usize> {
        let envelope_from = self.mail_from.clone().unwrap_or_default();
        let parsed = mime::parse_message(raw, &envelope_from);

        for rcpt in &self.rcpts {
            let stored = self.ctx.store.save_message(rcpt, parsed.clone()).await?;
            self.ctx
                .events
                .publish(MailEvent::from_stored(rcpt.clone(), &stored));
            info!(recipient = %rcpt, id = %stored.id, size = stored.raw_size, "stored inbound message");
        }
        Ok(self.rcpts.len())
    }

    async fn read_line_timed<R: AsyncBufRead + Unpin>(
        &self,
        r: &mut R,
        buf: &mut Vec<u8>,
        max: usize,
    ) -> io::Result<LineStatus> {
        match tokio::time::timeout(self.ctx.config.smtp_session_timeout, read_line(r, buf, max))
            .await
        {
            Ok(res) => res,
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "SMTP session timeout",
            )),
        }
    }
}

enum ReadAction {
    Eof,
    Done(usize, LineStatus),
    Consume(usize),
}

/// Read one line (terminated by `\n`) into `buf`, capped at `max` bytes.
///
/// Uses `fill_buf`/`consume` so a single call never buffers more than `max`
/// bytes, guarding against a client that streams without newlines.
async fn read_line<R: AsyncBufRead + Unpin>(
    r: &mut R,
    buf: &mut Vec<u8>,
    max: usize,
) -> io::Result<LineStatus> {
    buf.clear();
    loop {
        let action = {
            let chunk = r.fill_buf().await?;
            if chunk.is_empty() {
                ReadAction::Eof
            } else if let Some(pos) = chunk.iter().position(|&b| b == b'\n') {
                let take = pos + 1;
                if buf.len() + take > max {
                    ReadAction::Done(take, LineStatus::TooLong)
                } else {
                    buf.extend_from_slice(&chunk[..take]);
                    ReadAction::Done(take, LineStatus::Line)
                }
            } else {
                let n = chunk.len();
                if buf.len() + n > max {
                    ReadAction::Done(n, LineStatus::TooLong)
                } else {
                    buf.extend_from_slice(chunk);
                    ReadAction::Consume(n)
                }
            }
        };
        match action {
            ReadAction::Eof => {
                return Ok(if buf.is_empty() {
                    LineStatus::Eof
                } else {
                    LineStatus::Line
                });
            }
            ReadAction::Done(n, status) => {
                Pin::new(&mut *r).consume(n);
                return Ok(status);
            }
            ReadAction::Consume(n) => {
                Pin::new(&mut *r).consume(n);
            }
        }
    }
}

async fn write_line<W: AsyncWrite + Unpin>(w: &mut W, line: &str) -> io::Result<()> {
    w.write_all(line.as_bytes()).await?;
    w.write_all(b"\r\n").await?;
    w.flush().await
}

async fn write_multiline<W: AsyncWrite + Unpin>(
    w: &mut W,
    code: u16,
    lines: &[String],
) -> io::Result<()> {
    for (i, line) in lines.iter().enumerate() {
        let sep = if i + 1 == lines.len() { ' ' } else { '-' };
        w.write_all(format!("{code}{sep}{line}\r\n").as_bytes())
            .await?;
    }
    w.flush().await
}

/// True if `line` is the SMTP end-of-data terminator (a lone `.`).
fn is_terminator(line: &[u8]) -> bool {
    strip_eol(line) == b"."
}

/// Strip a trailing `\r\n` or `\n` from a raw line.
fn strip_eol(line: &[u8]) -> &[u8] {
    let mut end = line.len();
    if end > 0 && line[end - 1] == b'\n' {
        end -= 1;
    }
    if end > 0 && line[end - 1] == b'\r' {
        end -= 1;
    }
    &line[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_eol_handles_crlf_and_lf() {
        assert_eq!(strip_eol(b"hello\r\n"), b"hello");
        assert_eq!(strip_eol(b"hello\n"), b"hello");
        assert_eq!(strip_eol(b"hello"), b"hello");
    }

    #[test]
    fn detects_terminator() {
        assert!(is_terminator(b".\r\n"));
        assert!(is_terminator(b".\n"));
        assert!(is_terminator(b"."));
        assert!(!is_terminator(b"..\r\n"));
        assert!(!is_terminator(b". \r\n"));
    }
}
