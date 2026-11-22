//! Environment driven configuration.
//!
//! Everything is validated once at startup: a misconfigured service refuses to
//! start instead of failing later on a request path. Secrets are never logged.

use std::env;
use std::error::Error;
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

use argon2::password_hash::phc::PasswordHash;

use crate::spam::hex_decode;

/// Default bind address, also used by the `healthcheck` subcommand.
pub const DEFAULT_BIND_ADDR: &str = "0.0.0.0:8080";
pub const DEFAULT_DATABASE_PATH: &str = "/data/comments.db";
pub const DEFAULT_ADMIN_USER: &str = "admin";

#[derive(Debug)]
pub struct ConfigError {
    message: String,
}

impl ConfigError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for ConfigError {}

#[derive(Clone)]
pub struct Config {
    pub bind_addr: SocketAddr,
    pub database_path: PathBuf,
    /// Absolute base URL of this service, without a trailing slash.
    pub public_url: String,
    /// Path prefix taken from `public_url`, without a trailing slash. Empty
    /// when the service owns the host root, `/comments` when it is mounted
    /// under a subpath.
    pub base_path: String,
    /// Origin of the blog, without a trailing slash. Used for CORS and links.
    pub site_origin: String,
    /// Stylesheet of the blog, linked from the standalone thread page.
    pub site_css_url: String,
    pub admin_user: String,
    pub admin_password_hash: String,
    pub secret_key: [u8; 32],
    pub trust_proxy: bool,
    pub moderate_links: bool,
    /// Comma separated, case-insensitive substrings that force moderation.
    pub pending_keywords: Vec<String>,
}

/// Never print the signing key or the admin hash.
impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("bind_addr", &self.bind_addr)
            .field("database_path", &self.database_path)
            .field("public_url", &self.public_url)
            .field("base_path", &self.base_path)
            .field("site_origin", &self.site_origin)
            .field("site_css_url", &self.site_css_url)
            .field("admin_user", &self.admin_user)
            .field("admin_password_hash", &"[redacted]")
            .field("secret_key", &"[redacted]")
            .field("trust_proxy", &self.trust_proxy)
            .field("moderate_links", &self.moderate_links)
            .field("pending_keywords", &self.pending_keywords)
            .finish()
    }
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let bind_addr = match optional_env("BIND_ADDR") {
            Some(value) => SocketAddr::from_str(&value).map_err(|_| {
                ConfigError::new(format!(
                    "BIND_ADDR must be a socket address such as {DEFAULT_BIND_ADDR}, got {value:?}"
                ))
            })?,
            None => SocketAddr::from_str(DEFAULT_BIND_ADDR).expect("default bind address parses"),
        };

        let database_path = PathBuf::from(
            optional_env("DATABASE_PATH").unwrap_or_else(|| DEFAULT_DATABASE_PATH.to_owned()),
        );
        if database_path.as_os_str().is_empty() {
            return Err(ConfigError::new("DATABASE_PATH must not be empty"));
        }

        let public_url = validate_url("PUBLIC_URL", required_env("PUBLIC_URL")?, true)?;
        // The public URL is the single source of truth for the mount point, so
        // links and routes cannot disagree about the prefix.
        let base_path = base_path_from_url(&public_url)?;
        let site_origin = validate_url("SITE_ORIGIN", required_env("SITE_ORIGIN")?, false)?;
        let site_css_url = validate_url("SITE_CSS_URL", required_env("SITE_CSS_URL")?, true)?;

        let admin_user =
            optional_env("ADMIN_USER").unwrap_or_else(|| DEFAULT_ADMIN_USER.to_owned());
        if admin_user.is_empty() {
            return Err(ConfigError::new("ADMIN_USER must not be empty"));
        }
        if admin_user.contains(':') || admin_user.chars().any(char::is_control) {
            return Err(ConfigError::new(
                "ADMIN_USER must not contain ':' or control characters",
            ));
        }

        let admin_password_hash = required_env("ADMIN_PASSWORD_HASH")?;
        validate_password_hash(&admin_password_hash)?;

        let secret_key = parse_secret_key(&required_env("SECRET_KEY")?)?;

        let trust_proxy = parse_bool("TRUST_PROXY", optional_env("TRUST_PROXY"), true)?;
        // Link moderation is opt-in. Plenty of real comments contain a link,
        // so holding them by default surprises both readers and the author.
        let moderate_links = parse_bool("MODERATE_LINKS", optional_env("MODERATE_LINKS"), false)?;

        let mut pending_keywords = Vec::new();
        if let Some(raw) = optional_env("PENDING_KEYWORDS") {
            for keyword in raw.split(',') {
                let keyword = keyword.trim().to_lowercase();
                if keyword.is_empty() {
                    continue;
                }
                if keyword.chars().count() > 64 {
                    return Err(ConfigError::new(
                        "PENDING_KEYWORDS entries must be at most 64 characters",
                    ));
                }
                pending_keywords.push(keyword);
            }
        }
        if pending_keywords.len() > 50 {
            return Err(ConfigError::new(
                "PENDING_KEYWORDS accepts at most 50 entries",
            ));
        }

        Ok(Self {
            bind_addr,
            database_path,
            public_url,
            base_path,
            site_origin,
            site_css_url,
            admin_user,
            admin_password_hash,
            secret_key,
            trust_proxy,
            moderate_links,
            pending_keywords,
        })
    }

    /// Canonical URL of the standalone thread page for a validated page path.
    pub fn thread_url(&self, page: &str) -> String {
        format!("{}/thread?page={page}", self.public_url)
    }

    /// URL of the original blog post for a validated page path.
    pub fn post_url(&self, page: &str) -> String {
        format!("{}{page}", self.site_origin)
    }

    /// Absolute path on this service, including the mount prefix. `path` must
    /// start with `/`.
    pub fn path(&self, path: &str) -> String {
        format!("{}{path}", self.base_path)
    }
}

/// Extract the mount path from the public URL. `https://example.com` gives an
/// empty prefix, `https://example.com/comments` gives `/comments`.
fn base_path_from_url(public_url: &str) -> Result<String, ConfigError> {
    let rest = public_url
        .strip_prefix("https://")
        .or_else(|| public_url.strip_prefix("http://"))
        .expect("public_url was validated as absolute");
    let Some(index) = rest.find('/') else {
        return Ok(String::new());
    };
    let path = &rest[index..];
    validate_base_path(path)?;
    Ok(path.to_owned())
}

fn validate_base_path(path: &str) -> Result<(), ConfigError> {
    if path.is_empty() {
        return Ok(());
    }
    if !path.starts_with('/') || path.ends_with('/') {
        return Err(ConfigError::new(
            "PUBLIC_URL path must not end with a slash",
        ));
    }
    for segment in path.split('/').skip(1) {
        let safe = segment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~'));
        if segment.is_empty() || segment == "." || segment == ".." || !safe {
            return Err(ConfigError::new(
                "PUBLIC_URL path may only contain letters, digits, '.', '_', '~' and '-'",
            ));
        }
    }
    Ok(())
}

fn optional_env(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.trim().is_empty())
}

fn required_env(name: &str) -> Result<String, ConfigError> {
    optional_env(name).ok_or_else(|| ConfigError::new(format!("{name} is required")))
}

fn parse_bool(name: &str, value: Option<String>, default: bool) -> Result<bool, ConfigError> {
    let Some(value) = value else {
        return Ok(default);
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        other => Err(ConfigError::new(format!(
            "{name} must be true or false, got {other:?}"
        ))),
    }
}

fn validate_url(name: &str, raw: String, allow_path: bool) -> Result<String, ConfigError> {
    let trimmed = raw.trim();
    // Accept one trailing slash from copy-pasted URLs, then require the rest to
    // be clean.
    let value = trimmed.strip_suffix('/').unwrap_or(trimmed);
    let scheme_end = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
        .ok_or_else(|| ConfigError::new(format!("{name} must be an absolute http(s) URL")))?;
    if scheme_end.is_empty() {
        return Err(ConfigError::new(format!("{name} must include a host")));
    }
    if scheme_end
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || c == '?' || c == '#' || c == '@')
    {
        return Err(ConfigError::new(format!(
            "{name} must not contain whitespace, credentials, a query or a fragment"
        )));
    }
    if !allow_path && scheme_end.contains('/') {
        return Err(ConfigError::new(format!(
            "{name} must be an origin without a path"
        )));
    }
    Ok(value.to_owned())
}

fn validate_password_hash(raw: &str) -> Result<(), ConfigError> {
    let hash = PasswordHash::new(raw)
        .map_err(|_| ConfigError::new("ADMIN_PASSWORD_HASH must be an argon2 PHC string"))?;
    if hash.algorithm.as_str() != "argon2id" {
        return Err(ConfigError::new(
            "ADMIN_PASSWORD_HASH must use argon2id (generate it with `hash-password`)",
        ));
    }
    if hash.salt.is_none() || hash.hash.is_none() {
        return Err(ConfigError::new(
            "ADMIN_PASSWORD_HASH is missing its salt or hash",
        ));
    }
    Ok(())
}

fn parse_secret_key(raw: &str) -> Result<[u8; 32], ConfigError> {
    let raw = raw.trim();
    if raw.len() != 64 {
        return Err(ConfigError::new(
            "SECRET_KEY must be 64 hex characters (32 random bytes)",
        ));
    }
    let bytes = hex_decode(raw)
        .ok_or_else(|| ConfigError::new("SECRET_KEY must contain only hex characters"))?;
    <[u8; 32]>::try_from(bytes).map_err(|_| ConfigError::new("SECRET_KEY must be 32 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_origins_with_a_path() {
        let err = validate_url("SITE_ORIGIN", "https://example.com/blog".into(), false)
            .expect_err("path must be rejected");
        assert!(err.to_string().contains("origin"));
    }

    #[test]
    fn strips_a_single_trailing_slash() {
        assert_eq!(
            validate_url("PUBLIC_URL", "https://example.com/".into(), true).unwrap(),
            "https://example.com"
        );
    }

    #[test]
    fn rejects_credentials_and_queries() {
        assert!(validate_url("PUBLIC_URL", "https://u:p@example.com".into(), true).is_err());
        assert!(validate_url("PUBLIC_URL", "https://example.com?a=b".into(), true).is_err());
    }

    #[test]
    fn validates_secret_key_length() {
        assert!(parse_secret_key(&"ab".repeat(32)).is_ok());
        assert!(parse_secret_key(&"ab".repeat(31)).is_err());
        assert!(parse_secret_key(&"zz".repeat(32)).is_err());
    }

    #[test]
    fn derives_base_path_from_public_url() {
        assert_eq!(base_path_from_url("https://example.com").unwrap(), "");
        assert_eq!(
            base_path_from_url("https://example.com/comments").unwrap(),
            "/comments"
        );
        assert_eq!(
            base_path_from_url("http://127.0.0.1:8080/a/b").unwrap(),
            "/a/b"
        );
    }

    #[test]
    fn rejects_unsafe_base_paths() {
        assert!(base_path_from_url("https://example.com/a/../b").is_err());
        assert!(base_path_from_url("https://example.com/a b").is_err());
        assert!(base_path_from_url("https://example.com/a%2fb").is_err());
    }
}
