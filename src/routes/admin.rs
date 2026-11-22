//! Moderation: list held comments and approve or soft delete them.

use askama::Template;
use axum::extract::{Path, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use super::{admin_comment, AdminTemplate, AppError, AppState};
use crate::db;
use crate::security::admin_post_allowed;

#[derive(Debug, Deserialize)]
pub struct ActionForm {
    #[serde(default)]
    pub ts: String,
    #[serde(default)]
    pub token: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    Approve,
    Delete,
}

impl Action {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Delete => "delete",
        }
    }
}

pub async fn index(State(state): State<AppState>) -> Result<Response, AppError> {
    let now = state.now();
    let (pending, recent) = {
        let connection = state.db.lock().await;
        let pending = db::pending_comments(&connection)
            .map_err(|error| AppError::internal("loading pending comments", error))?;
        let recent = db::recent_visible_comments(&connection, 100)
            .map_err(|error| AppError::internal("loading recent comments", error))?;
        (pending, recent)
    };

    let pending: Vec<_> = pending
        .iter()
        .map(|comment| admin_comment(&state, comment, now))
        .collect();
    let recent: Vec<_> = recent
        .iter()
        .map(|comment| admin_comment(&state, comment, now))
        .collect();
    let pending_count = pending.len();
    let recent_count = recent.len();

    let template = AdminTemplate {
        admin_user: state.cfg.admin_user.clone(),
        pending,
        recent,
        pending_count,
        recent_count,
        static_css_url: state.cfg.path("/static/admin.css"),
        admin_url: state.cfg.path("/admin"),
        thread_url_base: format!("{}/thread", state.cfg.public_url),
    };
    match template.render() {
        Ok(html) => Ok((
            StatusCode::OK,
            [(CONTENT_TYPE, "text/html; charset=utf-8")],
            html,
        )
            .into_response()),
        Err(error) => Err(AppError::internal("rendering admin page", error)),
    }
}

pub async fn approve(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    form: axum::Form<ActionForm>,
) -> Result<Response, AppError> {
    act(&state, &headers, id, Action::Approve, &form).await
}

pub async fn delete(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    form: axum::Form<ActionForm>,
) -> Result<Response, AppError> {
    act(&state, &headers, id, Action::Delete, &form).await
}

async fn act(
    state: &AppState,
    headers: &HeaderMap,
    id: i64,
    action: Action,
    form: &ActionForm,
) -> Result<Response, AppError> {
    if !admin_post_allowed(headers) {
        return Err(AppError::BadRequest("cross-site request rejected"));
    }
    let now = state.now();
    if !state
        .signer
        .verify_action_token(id, action.as_str(), &form.ts, &form.token, now)
    {
        return Err(AppError::BadRequest(
            "this moderation form expired; reload the page",
        ));
    }

    let changed = {
        let connection = state.db.lock().await;
        match action {
            Action::Approve => db::approve_comment(&connection, id),
            Action::Delete => db::delete_comment(&connection, id),
        }
        .map_err(|error| AppError::internal("updating comment", error))?
    };
    if !changed {
        return Err(AppError::NotFound);
    }
    Ok(Redirect::to(&state.cfg.path("/admin")).into_response())
}
