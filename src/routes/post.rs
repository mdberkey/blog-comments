//! `POST /comment`: validation, anti-spam, storage and both response shapes.

use std::collections::HashMap;

use axum::body::to_bytes;
use axum::extract::{Extension, FromRequest, Multipart, Request, State};
use axum::http::header::{CONTENT_TYPE, LOCATION};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

use super::{
    fragment_response, load_comments, thread_response, view_from_comments, AppError, AppState,
    FormState,
};
use crate::db::{self, CreateOutcome};
use crate::models::{CommentStatus, NewComment};
use crate::security::{ClientIp, X_FRAGMENT};
use crate::spam;

const GENERAL_REJECTION: &str = "Your comment could not be posted. Reload the page and try again.";
const TOKEN_REJECTION: &str = "This form expired. Reload the page and try again.";
const RATE_REJECTION: &str = "You are posting too quickly. Try again later.";
const PARENT_REJECTION: &str = "The comment you are replying to is no longer available.";

/// Parsed comment form. Accepts both the urlencoded posts produced by HTML
/// forms and the multipart bodies produced by `fetch(..., {body: formData})`.
pub struct CommentForm {
    fields: HashMap<String, String>,
}

impl CommentForm {
    fn get(&self, name: &str) -> &str {
        self.fields.get(name).map(String::as_str).unwrap_or("")
    }
}

impl<S: Send + Sync> FromRequest<S> for CommentForm {
    type Rejection = AppError;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        let content_type = request
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();

        if content_type.starts_with("application/x-www-form-urlencoded") {
            let bytes = to_bytes(request.into_body(), spam::MAX_BODY_BYTES)
                .await
                .map_err(|_| AppError::PayloadTooLarge)?;
            let fields: HashMap<String, String> = serde_urlencoded::from_bytes(&bytes)
                .map_err(|_| AppError::BadRequest("invalid form body"))?;
            return Ok(Self { fields });
        }

        if content_type.starts_with("multipart/form-data") {
            let mut multipart = Multipart::from_request(request, state)
                .await
                .map_err(|error| {
                    if error.status() == StatusCode::PAYLOAD_TOO_LARGE {
                        AppError::PayloadTooLarge
                    } else {
                        AppError::BadRequest("invalid form body")
                    }
                })?;
            let mut fields = HashMap::new();
            let mut field_count = 0usize;
            while let Some(field) = multipart.next_field().await.map_err(multipart_error)? {
                field_count += 1;
                if field_count > spam::MAX_FORM_FIELDS {
                    return Err(AppError::BadRequest("too many form fields"));
                }
                let name = field.name().unwrap_or_default().to_owned();
                if field.file_name().is_some() {
                    // Files are not part of the form. Drain and ignore them;
                    // the total body limit still applies.
                    field.bytes().await.map_err(multipart_error)?;
                    continue;
                }
                if name.is_empty() {
                    continue;
                }
                let text = field.text().await.map_err(multipart_error)?;
                fields.insert(name, text);
            }
            return Ok(Self { fields });
        }

        Err(AppError::UnsupportedMediaType)
    }
}

fn multipart_error(error: axum::extract::multipart::MultipartError) -> AppError {
    if error.status() == StatusCode::PAYLOAD_TOO_LARGE {
        AppError::PayloadTooLarge
    } else {
        AppError::BadRequest("invalid form body")
    }
}

pub async fn create_comment(
    State(state): State<AppState>,
    Extension(client): Extension<ClientIp>,
    headers: HeaderMap,
    form: CommentForm,
) -> Result<Response, AppError> {
    let fragment = wants_fragment(&headers);
    let page = form.get("page").trim().to_owned();
    if !spam::is_valid_page(&page) {
        return Err(AppError::BadRequest("invalid page"));
    }
    let now = state.now();

    if state
        .signer
        .verify_comment_token(&page, form.get("ts"), form.get("token"), now)
        .is_err()
    {
        return validation_response(
            &state,
            fragment,
            &page,
            form.get("author"),
            form.get("body"),
            form.get("parent_id"),
            ("", "", TOKEN_REJECTION),
            StatusCode::UNPROCESSABLE_ENTITY,
        )
        .await;
    }

    // Honeypot: hidden from humans, tempting to bots. The message is generic
    // so it does not teach the sender which field was wrong.
    if spam::honeypot_tripped(form.get("website")) {
        return validation_response(
            &state,
            fragment,
            &page,
            form.get("author"),
            form.get("body"),
            form.get("parent_id"),
            ("", "", GENERAL_REJECTION),
            StatusCode::UNPROCESSABLE_ENTITY,
        )
        .await;
    }

    let author = match spam::clean_author(form.get("author")) {
        Ok(author) => author,
        Err(message) => {
            return validation_response(
                &state,
                fragment,
                &page,
                form.get("author"),
                form.get("body"),
                form.get("parent_id"),
                (message, "", ""),
                StatusCode::UNPROCESSABLE_ENTITY,
            )
            .await;
        }
    };

    let body = match spam::clean_body(form.get("body")) {
        Ok(body) => body,
        Err(message) => {
            return validation_response(
                &state,
                fragment,
                &page,
                form.get("author"),
                form.get("body"),
                form.get("parent_id"),
                ("", message, ""),
                StatusCode::UNPROCESSABLE_ENTITY,
            )
            .await;
        }
    };

    let parent_id = match spam::parse_parent_id(form.get("parent_id")) {
        Ok(parent_id) => parent_id,
        Err(message) => {
            return validation_response(
                &state,
                fragment,
                &page,
                form.get("author"),
                form.get("body"),
                form.get("parent_id"),
                ("", "", message),
                StatusCode::UNPROCESSABLE_ENTITY,
            )
            .await;
        }
    };

    if let Some(id) = parent_id {
        let target = {
            let connection = state.db.lock().await;
            db::parent_target(&connection, id)
        }
        .map_err(|error| AppError::internal("loading reply target", error))?;
        let valid = matches!(
            target,
            Some((ref target_page, CommentStatus::Visible)) if target_page == &page
        );
        if !valid {
            return validation_response(
                &state,
                fragment,
                &page,
                form.get("author"),
                form.get("body"),
                form.get("parent_id"),
                ("", "", PARENT_REJECTION),
                StatusCode::UNPROCESSABLE_ENTITY,
            )
            .await;
        }
    }

    let moderated = (state.cfg.moderate_links && spam::has_link(&body))
        || spam::matches_keyword(&state.cfg.pending_keywords, &body);
    let status = if moderated {
        CommentStatus::Pending
    } else {
        CommentStatus::Visible
    };

    // Unknown peers all share one bucket. Behind the proxy the address is
    // always available, so this only affects direct local requests.
    let address = client
        .0
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "unknown".to_owned());
    let ip_hash = state.signer.hash_ip(&address);

    let new_comment = NewComment {
        page: page.clone(),
        parent_id,
        author,
        body,
        status,
        created_at: now,
        ip_hash,
    };

    let outcome = {
        let mut connection = state.db.lock().await;
        db::create_comment(&mut connection, &new_comment, &spam::RATE_LIMITS)
    }
    .map_err(|error| AppError::internal("storing comment", error))?;

    let id = match outcome {
        CreateOutcome::Created(id) => id,
        CreateOutcome::RateLimited => {
            return validation_response(
                &state,
                fragment,
                &page,
                form.get("author"),
                form.get("body"),
                form.get("parent_id"),
                ("", "", RATE_REJECTION),
                StatusCode::TOO_MANY_REQUESTS,
            )
            .await;
        }
    };

    let notice = if status == CommentStatus::Pending {
        "Your comment is awaiting moderation and will appear after review.".to_owned()
    } else {
        String::new()
    };

    if fragment {
        let base = "/embed";
        let form = FormState::new(&state, &page, base);
        let comments = load_comments(&state, &page).await?;
        let view = view_from_comments(form, &comments, notice);
        Ok(fragment_response(
            &state,
            &view,
            base,
            StatusCode::OK,
            Some((id, status)),
        ))
    } else {
        let location = if status == CommentStatus::Pending {
            state
                .cfg
                .path(&format!("/thread?page={page}&pending=1#comments"))
        } else {
            state.cfg.path(&format!("/thread?page={page}#c{id}"))
        };
        let location = HeaderValue::try_from(location)
            .unwrap_or_else(|_| HeaderValue::try_from(state.cfg.path("/thread")).expect("path"));
        Ok((StatusCode::SEE_OTHER, [(LOCATION, location)]).into_response())
    }
}

fn wants_fragment(headers: &HeaderMap) -> bool {
    headers
        .get(X_FRAGMENT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.trim() == "1")
}

/// Re-render the thread with a preserved form and an error message. Fragment
/// requests always get a 200 so the client can swap in one step; the
/// standalone page gets a meaningful status code instead.
#[allow(clippy::too_many_arguments)]
async fn validation_response(
    state: &AppState,
    fragment: bool,
    page: &str,
    author: &str,
    body: &str,
    parent_id: &str,
    errors: (&str, &str, &str),
    status: StatusCode,
) -> Result<Response, AppError> {
    let base = if fragment { "/embed" } else { "/thread" };
    let mut form = FormState::new(state, page, base);
    form.author = author.trim().to_owned();
    form.body = body.to_owned();
    form.error_author = errors.0.to_owned();
    form.error_body = errors.1.to_owned();
    form.error_general = errors.2.to_owned();

    let comments = load_comments(state, page).await?;
    if let Ok(Some(id)) = spam::parse_parent_id(parent_id) {
        if let Some(target) = comments
            .iter()
            .find(|comment| comment.id == id && comment.status == CommentStatus::Visible)
        {
            form.set_reply(id, &target.author);
        }
    }

    let view = view_from_comments(form, &comments, String::new());
    if fragment {
        Ok(fragment_response(
            state,
            &view,
            "/embed",
            StatusCode::OK,
            None,
        ))
    } else {
        Ok(thread_response(state, &view, status))
    }
}
