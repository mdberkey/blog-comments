//! Anti-spam primitives: signed form tokens, rate limits, honeypot checks and
//! the link/moderation policy. Everything here is pure and unit-testable.

use std::fmt;

use hmac::{Hmac, KeyInit, Mac};
use linkify::{LinkFinder, LinkKind};
use sha2::Sha256;
use subtle::ConstantTimeEq;

pub const MAX_PAGE_CHARS: usize = 200;
pub const MAX_AUTHOR_CHARS: usize = 40;
pub const MAX_BODY_CHARS: usize = 2000;

/// Service side body limit. URL encoded forms can be up to three times larger
/// than the decoded body, so this must comfortably fit a 2,000 character body
/// made of four-byte characters plus the other fields.
pub const MAX_BODY_BYTES: usize = 64 * 1024;
pub const MAX_FORM_FIELDS: usize = 32;

/// Bots submit almost instantly. A human needs at least a couple of seconds to
/// type a comment, so younger tokens are rejected.
pub const MIN_TOKEN_AGE_SECS: i64 = 2;

/// The plan says "valid 30 minutes, rejected over 2 hours". Those are two
/// different lifetimes; the rejection rule is the security-relevant one, so a
/// form stays usable for two hours (long enough for a tab left open) and no
/// longer. Lower it here if that ever feels too generous.
pub const MAX_TOKEN_AGE_SECS: i64 = 2 * 60 * 60;

#[derive(Debug, Clone, Copy)]
pub struct RateLimit {
    pub window_secs: i64,
    pub max: u32,
}

/// Five comments per ten minutes and twenty per day, per hashed address.
pub const RATE_LIMITS: [RateLimit; 2] = [
    RateLimit {
        window_secs: 10 * 60,
        max: 5,
    },
    RateLimit {
        window_secs: 24 * 60 * 60,
        max: 20,
    },
];

/// Keep rate events for the longest window plus a day of slack so pruning can
/// never delete an event that still matters.
pub const RATE_EVENT_RETENTION_SECS: i64 = 2 * 24 * 60 * 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormToken {
    pub ts: String,
    pub token: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionToken {
    pub ts: String,
    pub token: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenError {
    Malformed,
    TooFast,
    Expired,
}

/// Holds the HMAC key. Tokens are stateless: the HMAC binds the page, issue
/// time and nonce, and the timestamp bounds how long the token is accepted.
#[derive(Clone)]
pub struct Signer {
    key: [u8; 32],
}

/// Never print the key.
impl fmt::Debug for Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Signer { key: [redacted] }")
    }
}

impl Signer {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    pub fn issue_comment_token(&self, page: &str, now: i64) -> FormToken {
        let ts = now.to_string();
        let nonce = format!("{:032x}", rand::random::<u128>());
        let mac = self.mac(
            b"comment",
            &[page.as_bytes(), ts.as_bytes(), nonce.as_bytes()],
        );
        FormToken {
            ts,
            token: format!("{nonce}.{}", hex_encode(&mac)),
        }
    }

    pub fn verify_comment_token(
        &self,
        page: &str,
        ts: &str,
        token: &str,
        now: i64,
    ) -> Result<(), TokenError> {
        let (nonce, signature) = token.split_once('.').ok_or(TokenError::Malformed)?;
        if nonce.len() != 32 || signature.len() != 64 || signature.contains('.') {
            return Err(TokenError::Malformed);
        }
        if !nonce.bytes().all(|byte| byte.is_ascii_hexdigit())
            || !signature.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(TokenError::Malformed);
        }
        let timestamp: i64 = ts.parse().map_err(|_| TokenError::Malformed)?;
        let age = now.checked_sub(timestamp).ok_or(TokenError::Malformed)?;
        if age < MIN_TOKEN_AGE_SECS {
            return Err(TokenError::TooFast);
        }
        if age > MAX_TOKEN_AGE_SECS {
            return Err(TokenError::Expired);
        }
        let expected = self.mac(
            b"comment",
            &[page.as_bytes(), ts.as_bytes(), nonce.as_bytes()],
        );
        let provided = hex_decode(signature).ok_or(TokenError::Malformed)?;
        if !constant_time_eq(&expected, &provided) {
            return Err(TokenError::Malformed);
        }
        Ok(())
    }

    pub fn issue_action_token(&self, id: i64, action: &str, now: i64) -> ActionToken {
        let ts = now.to_string();
        let id = id.to_string();
        let mac = self.mac(b"admin", &[id.as_bytes(), action.as_bytes(), ts.as_bytes()]);
        ActionToken {
            ts,
            token: hex_encode(&mac),
        }
    }

    pub fn verify_action_token(
        &self,
        id: i64,
        action: &str,
        ts: &str,
        token: &str,
        now: i64,
    ) -> bool {
        if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return false;
        }
        let timestamp: i64 = match ts.parse() {
            Ok(value) => value,
            Err(_) => return false,
        };
        let Some(age) = now.checked_sub(timestamp) else {
            return false;
        };
        if !(0..=MAX_TOKEN_AGE_SECS).contains(&age) {
            return false;
        }
        let id = id.to_string();
        let expected = self.mac(b"admin", &[id.as_bytes(), action.as_bytes(), ts.as_bytes()]);
        let provided = match hex_decode(token) {
            Some(value) => value,
            None => return false,
        };
        constant_time_eq(&expected, &provided)
    }

    /// HMAC of the client address. The raw address never reaches the database
    /// or the logs.
    pub fn hash_ip(&self, address: &str) -> String {
        hex_encode(&self.mac(b"ip", &[address.as_bytes()]))
    }

    fn mac(&self, domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.key).expect("HMAC accepts keys of any length");
        mac.update(domain);
        for part in parts {
            // Length prefixes make the encoding unambiguous even if a value
            // could contain the separator.
            mac.update(&(part.len() as u64).to_be_bytes());
            mac.update(part);
        }
        let output = mac.finalize().into_bytes();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&output);
        bytes
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.ct_eq(right).into()
}

pub fn is_valid_page(page: &str) -> bool {
    let length = page.chars().count();
    if length == 0 || length > MAX_PAGE_CHARS {
        return false;
    }
    if !page.starts_with('/') || page.contains("..") {
        return false;
    }
    page.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '-' | '.'))
}

pub fn clean_author(raw: &str) -> Result<String, &'static str> {
    let author = raw.trim();
    let length = author.chars().count();
    if length == 0 {
        return Err("add a name");
    }
    if length > MAX_AUTHOR_CHARS {
        return Err("name is too long (40 characters max)");
    }
    if author.chars().any(char::is_control) {
        return Err("name contains unsupported characters");
    }
    Ok(author.to_owned())
}

pub fn clean_body(raw: &str) -> Result<String, &'static str> {
    let normalized = raw.replace("\r\n", "\n").replace('\r', "\n");
    let body = normalized.trim();
    let length = body.chars().count();
    if length == 0 {
        return Err("write a comment");
    }
    if length > MAX_BODY_CHARS {
        return Err("comment is too long (2000 characters max)");
    }
    if body
        .chars()
        .any(|c| c.is_control() && c != '\n' && c != '\t')
    {
        return Err("comment contains unsupported characters");
    }
    Ok(body.to_owned())
}

/// Parse the optional `parent_id` field. An empty value means a top-level
/// comment; anything else must be a positive integer.
pub fn parse_parent_id(raw: &str) -> Result<Option<i64>, &'static str> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    if !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("invalid reply target");
    }
    let id: i64 = raw.parse().map_err(|_| "invalid reply target")?;
    if id <= 0 {
        return Err("invalid reply target");
    }
    Ok(Some(id))
}

pub fn honeypot_tripped(value: &str) -> bool {
    !value.trim().is_empty()
}

/// True when the body contains an explicit http(s) URL. This is the only thing
/// link spam needs, so those comments are held for moderation.
pub fn has_link(body: &str) -> bool {
    let mut finder = LinkFinder::new();
    finder.url_must_have_scheme(true).kinds(&[LinkKind::Url]);
    finder
        .spans(body)
        .filter(|span| span.kind() == Some(&LinkKind::Url))
        .any(|span| is_http_url(span.as_str()))
}

pub fn is_http_url(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

pub fn matches_keyword(keywords: &[String], body: &str) -> bool {
    if keywords.is_empty() {
        return false;
    }
    let lower = body.to_lowercase();
    keywords.iter().any(|keyword| lower.contains(keyword))
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    out
}

pub fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let high = hex_value(pair[0])?;
        let low = hex_value(pair[1])?;
        out.push((high << 4) | low);
    }
    Some(out)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer() -> Signer {
        Signer::new([7u8; 32])
    }

    #[test]
    fn valid_tokens_are_accepted() {
        let signer = signer();
        let now = 1_700_000_000;
        let token = signer.issue_comment_token("/blog/post/", now);
        assert_eq!(
            signer.verify_comment_token("/blog/post/", &token.ts, &token.token, now + 10),
            Ok(())
        );
    }

    #[test]
    fn tokens_are_bound_to_the_page() {
        let signer = signer();
        let now = 1_700_000_000;
        let token = signer.issue_comment_token("/blog/post/", now);
        assert_eq!(
            signer.verify_comment_token("/blog/other/", &token.ts, &token.token, now + 10),
            Err(TokenError::Malformed)
        );
    }

    #[test]
    fn young_future_and_stale_tokens_are_rejected() {
        let signer = signer();
        let now = 1_700_000_000;
        let token = signer.issue_comment_token("/p/", now);
        assert_eq!(
            signer.verify_comment_token("/p/", &token.ts, &token.token, now),
            Err(TokenError::TooFast)
        );
        assert_eq!(
            signer.verify_comment_token("/p/", &token.ts, &token.token, now + 1),
            Err(TokenError::TooFast)
        );
        assert_eq!(
            signer.verify_comment_token("/p/", &token.ts, &token.token, now - 60),
            Err(TokenError::TooFast)
        );
        assert_eq!(
            signer.verify_comment_token("/p/", &token.ts, &token.token, now + 3 * 3600),
            Err(TokenError::Expired)
        );
    }

    #[test]
    fn tampered_tokens_are_rejected() {
        let signer = signer();
        let now = 1_700_000_000;
        let mut token = signer.issue_comment_token("/p/", now);
        let last = token.token.pop().expect("token is not empty");
        token.token.push(if last == 'a' { 'b' } else { 'a' });
        assert_eq!(
            signer.verify_comment_token("/p/", &token.ts, &token.token, now + 10),
            Err(TokenError::Malformed)
        );
    }

    #[test]
    fn action_tokens_are_bound_to_id_and_action() {
        let signer = signer();
        let now = 1_700_000_000;
        let token = signer.issue_action_token(42, "approve", now);
        assert!(signer.verify_action_token(42, "approve", &token.ts, &token.token, now + 5));
        assert!(!signer.verify_action_token(42, "delete", &token.ts, &token.token, now + 5));
        assert!(!signer.verify_action_token(43, "approve", &token.ts, &token.token, now + 5));
        assert!(!signer.verify_action_token(
            42,
            "approve",
            &token.ts,
            &token.token,
            now + MAX_TOKEN_AGE_SECS + 1
        ));
    }

    #[test]
    fn page_validation_rejects_traversal_and_odd_characters() {
        assert!(is_valid_page("/blog/post/"));
        assert!(is_valid_page("/"));
        assert!(!is_valid_page(""));
        assert!(!is_valid_page("blog/post/"));
        assert!(!is_valid_page("/blog/../etc/passwd"));
        assert!(!is_valid_page("/blog/post/?x=1"));
        assert!(!is_valid_page("/blog/post/#c1"));
        assert!(!is_valid_page("/blog/post space/"));
        assert!(!is_valid_page(&format!("/{}", "a".repeat(200))));
    }

    #[test]
    fn author_and_body_are_trimmed_and_bounded() {
        assert_eq!(clean_author("  ada  "), Ok("ada".into()));
        assert!(clean_author("").is_err());
        assert!(clean_author("a\nb").is_err());
        assert!(clean_author(&"a".repeat(41)).is_err());
        assert_eq!(clean_body(" hello\nworld "), Ok("hello\nworld".into()));
        assert!(clean_body("\u{0007}").is_err());
        assert!(clean_body(&"a".repeat(2001)).is_err());
        assert!(clean_body(&"a".repeat(2000)).is_ok());
    }

    #[test]
    fn parses_parent_ids() {
        assert_eq!(parse_parent_id(""), Ok(None));
        assert_eq!(parse_parent_id(" 12 "), Ok(Some(12)));
        assert!(parse_parent_id("-1").is_err());
        assert!(parse_parent_id("1; drop table comments").is_err());
        assert!(parse_parent_id("0").is_err());
    }

    #[test]
    fn detects_links() {
        assert!(has_link("see https://example.com"));
        assert!(has_link("HTTP://EXAMPLE.COM"));
        assert!(!has_link("bare example.com is not a link"));
        assert!(!has_link("javascript:alert(1)"));
    }

    #[test]
    fn hex_round_trip() {
        let bytes = [0u8, 1, 15, 16, 255];
        let encoded = hex_encode(&bytes);
        assert_eq!(encoded, "00010f10ff");
        assert_eq!(hex_decode(&encoded), Some(bytes.to_vec()));
        assert_eq!(hex_decode("abc"), None);
        assert_eq!(hex_decode("zz"), None);
    }
}
