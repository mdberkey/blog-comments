mod common;

use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{Request, StatusCode};
use common::{TestApp, OTHER_PAGE, PAGE};

#[tokio::test]
async fn redirects_303_without_the_fragment_header() {
    let app = TestApp::new();
    let fields = app.fields(PAGE, "ada", "hello redirect");
    let response = app.post_form("/comment", &fields, false).await;
    assert_eq!(response.status, StatusCode::SEE_OTHER);
    assert_eq!(response.location(), "/thread?page=/blog/post/#c1");
    assert_eq!(app.comment_count(), 1);
}

#[tokio::test]
async fn fragment_mode_returns_the_updated_thread() {
    let app = TestApp::new();
    let fields = app.fields(PAGE, "ada", "hello fragment");
    let response = app.post_form("/comment", &fields, true).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.header("content-type"), "text/html; charset=utf-8");
    assert_eq!(response.header("x-comment-id"), "1");
    assert_eq!(response.header("x-comment-status"), "visible");
    assert_eq!(
        response.header("access-control-allow-origin"),
        "https://blog.test"
    );
    assert!(response.body.contains("hello fragment"));
    assert!(response.body.contains("ada"));
    assert!(response.body.contains("name=\"token\" value=\""));
}

#[tokio::test]
async fn accepts_multipart_form_data() {
    let app = TestApp::new();
    let fields = app.fields(PAGE, "ada", "multipart body");
    let response = app.post_multipart(&fields).await;
    assert_eq!(response.status, StatusCode::SEE_OTHER);
    assert_eq!(app.comment_count(), 1);
}

#[tokio::test]
async fn body_length_is_enforced_at_the_boundary() {
    let app = TestApp::new();

    let accepted = app.fields(PAGE, "ada", &"a".repeat(2000));
    let response = app.post_form("/comment", &accepted, false).await;
    assert_eq!(response.status, StatusCode::SEE_OTHER);

    let rejected = app.fields(PAGE, "ada", &"a".repeat(2001));
    let response = app.post_form("/comment", &rejected, false).await;
    assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(response.body.contains("too long"));
    assert_eq!(app.comment_count(), 1);
}

#[tokio::test]
async fn multibyte_bodies_are_measured_in_characters() {
    let app = TestApp::new();
    // 2000 four-byte characters are 8000 bytes; the body limit must accept it.
    let body = "🦀".repeat(2000);
    let fields = app.fields(PAGE, "ada", &body);
    let response = app.post_form("/comment", &fields, false).await;
    assert_eq!(response.status, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn fields_are_escaped_when_echoed_back() {
    let app = TestApp::new();
    let fields = app.fields(PAGE, "<script>alert(1)</script>", &"a".repeat(2001));
    let response = app.post_form("/comment", &fields, false).await;
    assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(!response.body.contains("<script>alert(1)</script>"));
    assert!(response.body.contains("alert(1)"));
    assert!(response.body.contains("&#60;script&#62;"));
}

#[tokio::test]
async fn invalid_parent_is_rejected() {
    let app = TestApp::new();
    let fields = app.fields_with_parent(PAGE, "ada", "reply", Some(999));
    let response = app.post_form("/comment", &fields, false).await;
    assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(response.body.contains("no longer available"));
    assert_eq!(app.comment_count(), 0);
}

#[tokio::test]
async fn parent_must_belong_to_the_same_page() {
    let app = TestApp::new();
    let other = app.seed(OTHER_PAGE, None, "ada", "elsewhere", "visible", 1_000);
    let fields = app.fields_with_parent(PAGE, "ada", "reply", Some(other));
    let response = app.post_form("/comment", &fields, false).await;
    assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(app.comment_count(), 1);
}

#[tokio::test]
async fn pending_parent_is_not_a_valid_target() {
    let app = TestApp::new();
    let pending = app.seed(PAGE, None, "ada", "held", "pending", 1_000);
    let fields = app.fields_with_parent(PAGE, "ada", "reply", Some(pending));
    let response = app.post_form("/comment", &fields, false).await;
    assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn rejects_technical_junk() {
    let app = TestApp::new();

    let request = Request::builder()
        .method("POST")
        .uri("/comment")
        .header(CONTENT_TYPE, "text/plain")
        .body(Body::from("hello"))
        .expect("request");
    assert_eq!(
        app.send(request).await.status,
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );

    let fields = app.fields(PAGE, "ada", "hello");
    let response = app.post_form("/comment", &fields, false).await;
    assert_eq!(response.status, StatusCode::SEE_OTHER);

    let huge = format!("page=/blog/post/&author=ada&body={}", "a".repeat(70 * 1024));
    let request = Request::builder()
        .method("POST")
        .uri("/comment")
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(huge))
        .expect("request");
    assert_eq!(
        app.send(request).await.status,
        StatusCode::PAYLOAD_TOO_LARGE
    );
}

#[tokio::test]
async fn empty_or_control_character_fields_are_rejected() {
    let app = TestApp::new();

    let response = app
        .post_form("/comment", &app.fields(PAGE, "", "hello"), false)
        .await;
    assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);

    let response = app
        .post_form("/comment", &app.fields(PAGE, "  ", "hello"), false)
        .await;
    assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);

    let response = app
        .post_form("/comment", &app.fields(PAGE, "ada", "   "), false)
        .await;
    assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);

    let response = app
        .post_form("/comment", &app.fields(PAGE, "a\u{0007}b", "hello"), false)
        .await;
    assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);

    let response = app
        .post_form("/comment", &app.fields(PAGE, "ada", "a\u{0007}b"), false)
        .await;
    assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);

    assert_eq!(app.comment_count(), 0);
}

#[tokio::test]
async fn invalid_page_is_rejected_before_storage() {
    let app = TestApp::new();
    let mut fields = app.fields(PAGE, "ada", "hello");
    for (key, value) in &mut fields {
        if key == "page" {
            *value = "/blog/../secret".to_owned();
        }
    }
    let response = app.post_form("/comment", &fields, false).await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert_eq!(app.comment_count(), 0);
}

#[tokio::test]
async fn fragment_errors_keep_the_form_and_return_200() {
    let app = TestApp::new();
    let fields = app.fields(PAGE, "ada", "");
    let response = app.post_form("/comment", &fields, true).await;
    assert_eq!(response.status, StatusCode::OK);
    assert!(response.body.contains("write a comment"));
    assert!(response.body.contains("value=\"ada\""));
    assert!(response.body.contains("name=\"token\" value=\""));
}
