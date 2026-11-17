#![allow(dead_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::OnceLock;

use axum::body::{to_bytes, Body};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderName, Request, StatusCode};
use axum::Router;
use base64::Engine;
use blog_comments::config::Config;
use blog_comments::routes::{build_router, AppState};
use blog_comments::security::hash_admin_password;
use rusqlite::{params, Connection};
use tempfile::TempDir;
use tower::ServiceExt;

pub const PAGE: &str = "/blog/post/";
pub const OTHER_PAGE: &str = "/blog/other/";
pub const ADMIN_PASSWORD: &str = "test-password";

pub struct TestApp {
    _dir: TempDir,
    pub state: AppState,
    pub router: Router,
    pub db_path: PathBuf,
}

pub struct TestResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: String,
}

impl TestResponse {
    pub fn header(&self, name: &str) -> &str {
        self.headers
            .get(HeaderName::from_bytes(name.as_bytes()).expect("valid header name"))
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
    }

    pub fn location(&self) -> &str {
        self.header("location")
    }
}

/// One argon2 hash per test binary; hashing is deliberately slow.
pub fn admin_password_hash() -> &'static str {
    static HASH: OnceLock<String> = OnceLock::new();
    HASH.get_or_init(|| hash_admin_password(ADMIN_PASSWORD).expect("hash test password"))
}

impl TestApp {
    pub fn new() -> Self {
        let dir = TempDir::new().expect("temp dir");
        let db_path = dir.path().join("comments.db");
        let config = Config {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            database_path: db_path.clone(),
            public_url: "https://comments.test".to_owned(),
            site_origin: "https://blog.test".to_owned(),
            site_css_url: "https://blog.test/style.css".to_owned(),
            admin_user: "admin".to_owned(),
            admin_password_hash: admin_password_hash().to_owned(),
            secret_key: [9u8; 32],
            trust_proxy: true,
            moderate_links: true,
            pending_keywords: vec!["casino".to_owned()],
        };
        let state = AppState::new(config).expect("create app state");
        let router = build_router(state.clone());
        Self {
            _dir: dir,
            state,
            router,
            db_path,
        }
    }

    pub async fn send(&self, request: Request<Body>) -> TestResponse {
        let response = self
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("router response");
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), 8 * 1024 * 1024)
            .await
            .expect("read response body");
        TestResponse {
            status,
            headers,
            body: String::from_utf8_lossy(&bytes).into_owned(),
        }
    }

    pub async fn get(&self, uri: &str) -> TestResponse {
        self.get_as("203.0.113.9", uri).await
    }

    pub async fn get_as(&self, ip: &str, uri: &str) -> TestResponse {
        let request = Request::builder()
            .method("GET")
            .uri(uri)
            .header("x-forwarded-for", ip)
            .header("origin", "https://blog.test")
            .body(Body::empty())
            .expect("build request");
        self.send(request).await
    }

    pub async fn post_form(
        &self,
        uri: &str,
        fields: &[(String, String)],
        fragment: bool,
    ) -> TestResponse {
        self.post_form_as("203.0.113.9", uri, fields, fragment)
            .await
    }

    pub async fn post_form_as(
        &self,
        ip: &str,
        uri: &str,
        fields: &[(String, String)],
        fragment: bool,
    ) -> TestResponse {
        let encoded = encode_form(fields);
        let mut builder = Request::builder()
            .method("POST")
            .uri(uri)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("x-forwarded-for", ip)
            .header("origin", "https://blog.test");
        if fragment {
            builder = builder.header("x-fragment", "1");
        }
        let request = builder
            .body(Body::from(encoded))
            .expect("build form request");
        self.send(request).await
    }

    pub async fn post_multipart(&self, fields: &[(String, String)]) -> TestResponse {
        let boundary = "----blogcommentstestboundary";
        let mut body = Vec::new();
        for (name, value) in fields {
            body.extend_from_slice(
                format!(
                    "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
                )
                .as_bytes(),
            );
        }
        body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        let request = Request::builder()
            .method("POST")
            .uri("/comment")
            .header(
                CONTENT_TYPE,
                format!("multipart/form-data; boundary={boundary}"),
            )
            .header("x-forwarded-for", "203.0.113.9")
            .header("origin", "https://blog.test")
            .body(Body::from(body))
            .expect("build multipart request");
        self.send(request).await
    }

    /// Fields with an already-old-enough signed token, bypassing the two
    /// second minimum without sleeping in every test.
    pub fn fields(&self, page: &str, author: &str, body: &str) -> Vec<(String, String)> {
        self.fields_with_parent(page, author, body, None)
    }

    pub fn fields_with_parent(
        &self,
        page: &str,
        author: &str,
        body: &str,
        parent_id: Option<i64>,
    ) -> Vec<(String, String)> {
        let token = self
            .state
            .signer
            .issue_comment_token(page, self.state.now() - 10);
        let mut fields = vec![
            ("page".to_owned(), page.to_owned()),
            ("author".to_owned(), author.to_owned()),
            ("body".to_owned(), body.to_owned()),
            ("ts".to_owned(), token.ts),
            ("token".to_owned(), token.token),
        ];
        if let Some(id) = parent_id {
            fields.push(("parent_id".to_owned(), id.to_string()));
        }
        fields
    }

    pub fn token_with_timestamp(&self, page: &str, ts: i64) -> (String, String) {
        let token = self.state.signer.issue_comment_token(page, ts);
        (token.ts, token.token)
    }

    pub async fn admin_get(&self, uri: &str) -> TestResponse {
        self.admin_get_with_auth(uri, true).await
    }

    pub async fn admin_get_with_auth(&self, uri: &str, authenticate: bool) -> TestResponse {
        let mut builder = Request::builder().method("GET").uri(uri);
        if authenticate {
            builder = builder.header(AUTHORIZATION, basic_auth(ADMIN_PASSWORD));
        }
        let request = builder.body(Body::empty()).expect("build admin request");
        self.send(request).await
    }

    pub async fn admin_post(
        &self,
        uri: &str,
        fields: &[(String, String)],
        sec_fetch_site: Option<&str>,
    ) -> TestResponse {
        self.admin_post_with_auth(uri, fields, sec_fetch_site, true)
            .await
    }

    pub async fn admin_post_with_auth(
        &self,
        uri: &str,
        fields: &[(String, String)],
        sec_fetch_site: Option<&str>,
        authenticate: bool,
    ) -> TestResponse {
        let mut builder = Request::builder()
            .method("POST")
            .uri(uri)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded");
        if authenticate {
            builder = builder.header(AUTHORIZATION, basic_auth(ADMIN_PASSWORD));
        }
        if let Some(value) = sec_fetch_site {
            builder = builder.header("sec-fetch-site", value);
        }
        let request = builder
            .body(Body::from(encode_form(fields)))
            .expect("build admin post");
        self.send(request).await
    }

    /// Insert a comment directly, for read-path and moderation tests that do
    /// not care how it was created.
    #[allow(clippy::too_many_arguments)]
    pub fn seed(
        &self,
        page: &str,
        parent_id: Option<i64>,
        author: &str,
        body: &str,
        status: &str,
        created_at: i64,
    ) -> i64 {
        let connection = Connection::open(&self.db_path).expect("open test database");
        connection
            .execute(
                "INSERT INTO comments (page, parent_id, author, body, status, created_at, ip_hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'test')",
                params![page, parent_id, author, body, status, created_at],
            )
            .expect("insert test comment");
        connection.last_insert_rowid()
    }

    pub fn comment_count(&self) -> i64 {
        let connection = Connection::open(&self.db_path).expect("open test database");
        connection
            .query_row("SELECT COUNT(*) FROM comments", [], |row| row.get(0))
            .expect("count comments")
    }

    /// Extract the hidden `ts` and `token` from the first comment form in a
    /// fragment or page.
    pub fn form_token(&self, html: &str) -> (String, String) {
        (
            hidden_value(html, "ts").expect("ts field"),
            hidden_value(html, "token").expect("token field"),
        )
    }

    /// Extract the signed fields from an admin action form, scoped to its
    /// `<form>` so multiple comments on the page cannot be confused.
    pub fn action_token(&self, html: &str, id: i64, action: &str) -> (String, String) {
        let needle = format!("action=\"/admin/{id}/{action}\"");
        let start = html.find(&needle).expect("action form");
        let end = html[start..]
            .find("</form>")
            .map(|offset| start + offset)
            .expect("closing form tag");
        let form = &html[start..end];
        (
            hidden_value(form, "ts").expect("admin ts field"),
            hidden_value(form, "token").expect("admin token field"),
        )
    }
}

pub fn encode_form(fields: &[(String, String)]) -> String {
    let map: HashMap<&str, &str> = fields
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();
    serde_urlencoded::to_string(map).expect("encode form")
}

pub fn basic_auth(password: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("admin:{password}"))
    )
}

pub fn hidden_value(html: &str, name: &str) -> Option<String> {
    let needle = format!("name=\"{name}\" value=\"");
    let start = html.find(&needle)? + needle.len();
    let rest = &html[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_owned())
}
