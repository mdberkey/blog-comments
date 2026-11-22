//! Application state, router assembly and shared response helpers.

mod admin;
mod embed;
mod health;
mod post;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use askama::Template;
use axum::body::Body;
use axum::extract::DefaultBodyLimit;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::from_fn_with_state;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use rusqlite::Connection;
use tokio::sync::Mutex;
use tower_http::trace::{DefaultOnResponse, TraceLayer};
use tower_http::LatencyUnit;
use tracing::Level;

use crate::config::Config;
use crate::db;
use crate::models::{AdminComment, Comment, CommentStatus, RenderedComment};
use crate::render::{self, Html};
use crate::security::{
    admin_auth_middleware, build_security_headers, client_ip_middleware, cors_layer,
    security_headers_middleware, X_COMMENT_ID, X_COMMENT_STATUS,
};
use crate::spam::{self, FormToken, Signer};

#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<Config>,
    pub db: Arc<Mutex<Connection>>,
    pub signer: Arc<Signer>,
    pub security_headers: Arc<HeaderMap>,
}

impl AppState {
    pub fn new(config: Config) -> rusqlite::Result<Self> {
        let connection = db::open(&config.database_path)?;
        let signer = Signer::new(config.secret_key);
        let security_headers = build_security_headers(&config);
        Ok(Self {
            cfg: Arc::new(config),
            db: Arc::new(Mutex::new(connection)),
            signer: Arc::new(signer),
            security_headers: Arc::new(security_headers),
        })
    }

    /// Seconds since the Unix epoch. A clock before 1970 is treated as zero,
    /// which makes every token invalid rather than valid forever.
    pub fn now(&self) -> i64 {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => duration.as_secs() as i64,
            Err(_) => 0,
        }
    }
}

pub fn build_router(state: AppState) -> Router {
    let public = Router::new()
        .route("/embed", get(embed::embed))
        .route("/comment", post(post::create_comment))
        .layer(cors_layer(&state.cfg));

    let admin = Router::new()
        .route("/admin", get(admin::index))
        .route("/admin/{id}/approve", post(admin::approve))
        .route("/admin/{id}/delete", post(admin::delete))
        .route_layer(from_fn_with_state(state.clone(), admin_auth_middleware));

    let service = Router::new()
        .route("/thread", get(embed::thread_page))
        .route("/static/comments.css", get(comments_css))
        .route("/static/admin.css", get(admin_css))
        .merge(public)
        .merge(admin)
        .fallback(not_found);

    // `PUBLIC_URL` decides whether the service owns the host root or lives
    // under a prefix such as /comments. `nest` keeps the inner routes unaware
    // of the prefix; generated links use `Config::path`.
    let service = if state.cfg.base_path.is_empty() {
        service
    } else {
        Router::new().nest(&state.cfg.base_path, service)
    };

    Router::new()
        // The container healthcheck asks for /healthz on localhost, so it stays
        // at the root even when the public routes are nested.
        .route("/healthz", get(health::healthz))
        .merge(service)
        // The body limit applies to every body-consuming route, including the
        // multipart branch of the comment form.
        .layer(DefaultBodyLimit::max(spam::MAX_BODY_BYTES))
        .layer(from_fn_with_state(state.clone(), client_ip_middleware))
        .layer(from_fn_with_state(
            state.clone(),
            security_headers_middleware,
        ))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &axum::http::Request<Body>| {
                    // Only the path: queries can contain the page being read,
                    // and headers can contain credentials.
                    tracing::info_span!(
                        "request",
                        method = %request.method(),
                        path = %request.uri().path()
                    )
                })
                .on_response(
                    DefaultOnResponse::new()
                        .level(Level::INFO)
                        .latency_unit(LatencyUnit::Millis),
                ),
        )
        .with_state(state)
}

async fn comments_css() -> impl IntoResponse {
    (
        StatusCode::OK,
        [
            (CONTENT_TYPE, "text/css; charset=utf-8"),
            (CACHE_CONTROL, "public, max-age=3600"),
        ],
        include_str!("../../static/comments.css"),
    )
}

async fn admin_css() -> impl IntoResponse {
    (
        StatusCode::OK,
        [
            (CONTENT_TYPE, "text/css; charset=utf-8"),
            (CACHE_CONTROL, "public, max-age=3600"),
        ],
        include_str!("../../static/admin.css"),
    )
}

async fn not_found() -> AppError {
    AppError::NotFound
}

#[derive(Debug)]
pub enum AppError {
    BadRequest(&'static str),
    NotFound,
    PayloadTooLarge,
    UnsupportedMediaType,
    Internal,
}

impl AppError {
    pub fn internal(context: &'static str, error: impl std::fmt::Display) -> Self {
        tracing::error!(context, error = %error, "request failed");
        Self::Internal
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, title, message) = match self {
            Self::BadRequest(message) => (StatusCode::BAD_REQUEST, "bad request", message),
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                "not found",
                "that page does not exist",
            ),
            Self::PayloadTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "request too large",
                "that comment is too large",
            ),
            Self::UnsupportedMediaType => (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "unsupported content type",
                "send the comment as a form",
            ),
            Self::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error",
                "something went wrong on our side",
            ),
        };
        let template = ErrorTemplate {
            title: title.to_owned(),
            message: message.to_owned(),
            css: include_str!("../../static/comments.css"),
        };
        match template.render() {
            Ok(html) => {
                (status, [(CONTENT_TYPE, "text/html; charset=utf-8")], html).into_response()
            }
            Err(error) => {
                tracing::error!(%error, "failed to render error page");
                (
                    status,
                    [(CONTENT_TYPE, "text/plain; charset=utf-8")],
                    message,
                )
                    .into_response()
            }
        }
    }
}

/// Every field a comment form needs. Values submitted by the user are kept on
/// errors so nothing has to be retyped.
#[derive(Debug, Clone)]
pub struct FormState {
    pub page: String,
    pub author: String,
    pub body: String,
    pub parent_id_value: String,
    pub ts: String,
    pub token: String,
    pub reply_author: String,
    pub error_author: String,
    pub error_body: String,
    pub error_general: String,
    pub action: String,
    pub cancel_url: String,
    pub is_reply: bool,
}

impl FormState {
    /// Blank form with a freshly signed token for `page`. `base` is the
    /// unprefixed route the form belongs to (`/embed` or `/thread`).
    pub fn new(state: &AppState, page: &str, base: &str) -> Self {
        let FormToken { ts, token } = state.signer.issue_comment_token(page, state.now());
        Self {
            page: page.to_owned(),
            author: String::new(),
            body: String::new(),
            parent_id_value: String::new(),
            ts,
            token,
            reply_author: String::new(),
            error_author: String::new(),
            error_body: String::new(),
            error_general: String::new(),
            action: state.cfg.path("/comment"),
            cancel_url: format!("{}?page={page}", state.cfg.path(base)),
            is_reply: false,
        }
    }

    pub fn set_reply(&mut self, id: i64, author: &str) {
        self.parent_id_value = id.to_string();
        self.reply_author = author.to_owned();
        self.is_reply = true;
    }

    pub fn parent_id(&self) -> Option<i64> {
        spam::parse_parent_id(&self.parent_id_value).ok().flatten()
    }
}

pub struct ThreadView {
    pub page: String,
    pub comments: Vec<RenderedComment>,
    pub visible_count: usize,
    pub form: FormState,
    pub notice: String,
}

pub fn view_from_comments(form: FormState, comments: &[Comment], notice: String) -> ThreadView {
    let rendered = render::flatten(comments, form.parent_id());
    let visible_count = comments
        .iter()
        .filter(|comment| comment.status == CommentStatus::Visible)
        .count();
    ThreadView {
        page: form.page.clone(),
        comments: rendered,
        visible_count,
        form,
        notice,
    }
}

pub async fn load_comments(state: &AppState, page: &str) -> Result<Vec<Comment>, AppError> {
    let connection = state.db.lock().await;
    db::load_comments(&connection, page)
        .map_err(|error| AppError::internal("loading comments", error))
}

pub fn render_fragment(
    state: &AppState,
    view: &ThreadView,
    base: &'static str,
    show_heading: bool,
) -> Result<Html, AppError> {
    let template = CommentsTemplate {
        page: view.page.clone(),
        comments: view.comments.clone(),
        visible_count: view.visible_count,
        form: view.form.clone(),
        notice: view.notice.clone(),
        reply_base: state.cfg.path(base),
        thread_url_base: format!("{}/thread", state.cfg.public_url),
        show_heading,
    };
    template
        .render()
        .map(Html::new)
        .map_err(|error| AppError::internal("rendering fragment", error))
}

/// HTML fragment response for `/embed` and fragment-mode `POST /comment`.
pub fn fragment_response(
    state: &AppState,
    view: &ThreadView,
    base: &'static str,
    status: StatusCode,
    comment: Option<(i64, CommentStatus)>,
) -> Response {
    let html = match render_fragment(state, view, base, true) {
        Ok(html) => html,
        Err(error) => return error.into_response(),
    };
    let mut response = (
        status,
        [
            (CONTENT_TYPE, "text/html; charset=utf-8"),
            (
                axum::http::header::HeaderName::from_static("cross-origin-resource-policy"),
                "cross-origin",
            ),
        ],
        html.as_str().to_owned(),
    )
        .into_response();
    if let Some((id, status)) = comment {
        let id =
            HeaderValue::try_from(id.to_string()).unwrap_or_else(|_| HeaderValue::from_static("0"));
        response.headers_mut().insert(X_COMMENT_ID, id);
        response.headers_mut().insert(
            X_COMMENT_STATUS,
            HeaderValue::from_static(match status {
                CommentStatus::Visible => "visible",
                CommentStatus::Pending => "pending",
                CommentStatus::Deleted => "deleted",
            }),
        );
    }
    response
}

/// Full standalone page used by `/thread` and by non-fragment POST errors.
pub fn thread_response(state: &AppState, view: &ThreadView, status: StatusCode) -> Response {
    let comments_html = match render_fragment(state, view, "/thread", false) {
        Ok(html) => html,
        Err(error) => return error.into_response(),
    };
    let template = ThreadPageTemplate {
        page: view.page.clone(),
        comments_html,
        site_css_url: state.cfg.site_css_url.clone(),
        static_css_url: state.cfg.path("/static/comments.css"),
        post_url: state.cfg.post_url(&view.page),
        canonical_url: state.cfg.thread_url(&view.page),
    };
    match template.render() {
        Ok(html) => (status, [(CONTENT_TYPE, "text/html; charset=utf-8")], html).into_response(),
        Err(error) => AppError::internal("rendering thread page", error).into_response(),
    }
}

pub fn admin_comment(state: &AppState, comment: &Comment, now: i64) -> AdminComment {
    let (created_human, _) = render::format_timestamp(comment.created_at);
    let approve = state.signer.issue_action_token(comment.id, "approve", now);
    let delete = state.signer.issue_action_token(comment.id, "delete", now);
    AdminComment {
        id: comment.id,
        page: comment.page.clone(),
        author: comment.author.clone(),
        body: comment.body.clone(),
        created_human,
        ts: approve.ts,
        approve_token: approve.token,
        delete_token: delete.token,
    }
}

#[derive(Template)]
#[template(path = "comments.html")]
struct CommentsTemplate {
    page: String,
    comments: Vec<RenderedComment>,
    visible_count: usize,
    form: FormState,
    notice: String,
    reply_base: String,
    thread_url_base: String,
    show_heading: bool,
}

#[derive(Template)]
#[template(path = "thread_page.html")]
struct ThreadPageTemplate {
    page: String,
    comments_html: Html,
    site_css_url: String,
    static_css_url: String,
    post_url: String,
    canonical_url: String,
}

#[derive(Template)]
#[template(path = "error.html")]
struct ErrorTemplate {
    title: String,
    message: String,
    /// Inlined so the error page needs no route prefix or extra request.
    css: &'static str,
}

#[derive(Template)]
#[template(path = "admin.html")]
struct AdminTemplate {
    admin_user: String,
    pending: Vec<AdminComment>,
    recent: Vec<AdminComment>,
    pending_count: usize,
    recent_count: usize,
    static_css_url: String,
    admin_url: String,
    thread_url_base: String,
}
