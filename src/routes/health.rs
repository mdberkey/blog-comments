//! Liveness endpoint. It intentionally does not touch the database: the
//! healthcheck is about the process being able to answer HTTP, not about the
//! state of the data volume.

use axum::http::header::CONTENT_TYPE;
use axum::response::{IntoResponse, Response};

pub async fn healthz() -> Response {
    ([(CONTENT_TYPE, "text/plain; charset=utf-8")], "ok").into_response()
}
