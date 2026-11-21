//! Read paths: the embeddable fragment and the standalone thread page.

use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use super::{
    fragment_response, load_comments, thread_response, view_from_comments, AppError, AppState,
    FormState,
};
use crate::models::CommentStatus;
use crate::spam;

#[derive(Debug, Default, Deserialize)]
pub struct ThreadQuery {
    #[serde(default)]
    pub page: String,
    #[serde(default)]
    pub reply: String,
    /// Only `1` is recognised; shows the "awaiting moderation" notice after a
    /// redirect from a held comment.
    #[serde(default)]
    pub pending: String,
}

/// `GET /embed?page=…` — HTML fragment fetched by the blog.
pub async fn embed(
    State(state): State<AppState>,
    query: Result<Query<ThreadQuery>, QueryRejection>,
) -> Response {
    let Ok(Query(query)) = query else {
        return text_error(StatusCode::BAD_REQUEST, "invalid query string");
    };
    if !spam::is_valid_page(&query.page) {
        return text_error(StatusCode::BAD_REQUEST, "invalid page");
    }

    let comments = match load_comments(&state, &query.page).await {
        Ok(comments) => comments,
        Err(error) => return error.into_response(),
    };
    let mut form = FormState::new(&state, &query.page, "/embed");
    apply_reply(&mut form, &comments, &query.reply);

    let view = view_from_comments(form, &comments, String::new());
    fragment_response(&state, &view, "/embed", StatusCode::OK, None)
}

/// `GET /thread?page=…` — full page, works without JavaScript.
pub async fn thread_page(
    State(state): State<AppState>,
    query: Result<Query<ThreadQuery>, QueryRejection>,
) -> Result<Response, AppError> {
    let Query(query) = query.map_err(|_| AppError::BadRequest("invalid query string"))?;
    if !spam::is_valid_page(&query.page) {
        return Err(AppError::BadRequest("invalid page"));
    }

    let comments = load_comments(&state, &query.page).await?;
    let mut form = FormState::new(&state, &query.page, "/thread");
    apply_reply(&mut form, &comments, &query.reply);

    let notice = if query.pending == "1" {
        "Your comment is awaiting moderation and will appear after review.".to_owned()
    } else {
        String::new()
    };

    let view = view_from_comments(form, &comments, notice);
    Ok(thread_response(&state, &view, StatusCode::OK))
}

/// Point the form at a reply target only when it exists, is visible and lives
/// on the same page. A stale or foreign id silently falls back to a top-level
/// form instead of replacing the thread with an error.
fn apply_reply(form: &mut FormState, comments: &[crate::models::Comment], reply: &str) {
    let Ok(Some(id)) = spam::parse_parent_id(reply) else {
        return;
    };
    if let Some(target) = comments
        .iter()
        .find(|comment| comment.id == id && comment.status == CommentStatus::Visible)
    {
        if target.page == form.page {
            form.set_reply(id, &target.author);
        }
    }
}

fn text_error(status: StatusCode, message: &'static str) -> Response {
    (
        status,
        [(CONTENT_TYPE, "text/plain; charset=utf-8")],
        message,
    )
        .into_response()
}
