mod common;

use axum::body::Body;
use axum::http::header::AUTHORIZATION;
use axum::http::{Request, StatusCode};
use common::{basic_auth, TestApp, PAGE};

fn action_fields(ts: String, token: String) -> Vec<(String, String)> {
    vec![("ts".to_owned(), ts), ("token".to_owned(), token)]
}

#[tokio::test]
async fn admin_requires_basic_auth() {
    let app = TestApp::new();
    let response = app.admin_get_with_auth("/admin", false).await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert!(response
        .header("www-authenticate")
        .contains("Basic realm=\"comments\""));
    assert!(response.body.contains("authentication required"));
    assert_eq!(response.header("cache-control"), "no-store");
}

#[tokio::test]
async fn wrong_password_is_rejected() {
    let app = TestApp::new();
    let request = Request::builder()
        .method("GET")
        .uri("/admin")
        .header(AUTHORIZATION, basic_auth("wrong-password"))
        .body(Body::empty())
        .expect("request");
    assert_eq!(app.send(request).await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn admin_lists_pending_and_recent_comments() {
    let app = TestApp::new();
    app.seed(PAGE, None, "held", "held body", "pending", 1_000);
    app.seed(PAGE, None, "visible", "visible body", "visible", 1_001);

    let response = app.admin_get("/admin").await;
    assert_eq!(response.status, StatusCode::OK);
    assert!(response.body.contains("held body"));
    assert!(response.body.contains("visible body"));
    assert!(response
        .body
        .contains("pending <span class=\"admin-count\">1</span>"));
    assert!(response
        .body
        .contains("recent <span class=\"admin-count\">1</span>"));
    assert_eq!(response.header("cache-control"), "no-store");
    assert!(response
        .header("content-security-policy")
        .contains("default-src 'none'"));
}

#[tokio::test]
async fn admin_escapes_comment_content() {
    let app = TestApp::new();
    // A held comment is the dangerous case: the admin is the first person to
    // see it, and the text came straight from an anonymous visitor.
    app.seed(
        PAGE,
        None,
        "<script>alert('author')</script>",
        "<img src=x onerror=\"alert('body')\">",
        "pending",
        1_000,
    );

    let admin = app.admin_get("/admin").await;
    assert_eq!(admin.status, StatusCode::OK);
    assert!(!admin.body.contains("<script>alert"));
    assert!(!admin.body.contains("<img src=x"));
    assert!(admin
        .body
        .contains("&#60;script&#62;alert(&#39;author&#39;)&#60;/script&#62;"));
    assert!(admin
        .body
        .contains("&#60;img src=x onerror=&#34;alert(&#39;body&#39;)&#34;&#62;"));
}

#[tokio::test]
async fn approve_publishes_a_held_comment() {
    let app = TestApp::new();
    let id = app.seed(PAGE, None, "ada", "held body", "pending", 1_000);

    let admin = app.admin_get("/admin").await;
    let (ts, token) = app.action_token(&admin.body, id, "approve");
    let response = app
        .admin_post(
            &format!("/admin/{id}/approve"),
            &action_fields(ts, token),
            None,
        )
        .await;
    assert_eq!(response.status, StatusCode::SEE_OTHER);
    assert_eq!(response.location(), "/admin");

    let thread = app.get("/thread?page=/blog/post/").await;
    assert!(thread.body.contains("held body"));
}

#[tokio::test]
async fn delete_removes_a_comment_from_the_thread() {
    let app = TestApp::new();
    let id = app.seed(PAGE, None, "ada", "delete me", "visible", 1_000);

    let admin = app.admin_get("/admin").await;
    let (ts, token) = app.action_token(&admin.body, id, "delete");
    let response = app
        .admin_post(
            &format!("/admin/{id}/delete"),
            &action_fields(ts, token),
            None,
        )
        .await;
    assert_eq!(response.status, StatusCode::SEE_OTHER);

    let thread = app.get("/thread?page=/blog/post/").await;
    assert!(!thread.body.contains("delete me"));
}

#[tokio::test]
async fn missing_or_forged_action_tokens_are_rejected() {
    let app = TestApp::new();
    let id = app.seed(PAGE, None, "ada", "held", "pending", 1_000);

    let response = app
        .admin_post(
            &format!("/admin/{id}/approve"),
            &action_fields(String::new(), String::new()),
            None,
        )
        .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);

    let (ts, token) = app.action_token(&app.admin_get("/admin").await.body, id, "approve");
    let mut forged = token;
    let last = forged.pop().expect("token");
    forged.push(if last == 'a' { 'b' } else { 'a' });
    let response = app
        .admin_post(
            &format!("/admin/{id}/approve"),
            &action_fields(ts, forged),
            None,
        )
        .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);

    let thread = app.get("/thread?page=/blog/post/").await;
    assert!(!thread.body.contains("held"));
}

#[tokio::test]
async fn cross_site_admin_posts_are_rejected() {
    let app = TestApp::new();
    let id = app.seed(PAGE, None, "ada", "held", "pending", 1_000);
    let (ts, token) = app.action_token(&app.admin_get("/admin").await.body, id, "approve");
    let response = app
        .admin_post(
            &format!("/admin/{id}/approve"),
            &action_fields(ts, token),
            Some("cross-site"),
        )
        .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn expired_action_tokens_are_rejected() {
    let app = TestApp::new();
    let id = app.seed(PAGE, None, "ada", "held", "pending", 1_000);
    let token = app
        .state
        .signer
        .issue_action_token(id, "approve", app.state.now() - 3 * 60 * 60);
    let response = app
        .admin_post(
            &format!("/admin/{id}/approve"),
            &action_fields(token.ts, token.token),
            None,
        )
        .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn admin_posts_still_require_authentication() {
    let app = TestApp::new();
    let id = app.seed(PAGE, None, "ada", "held", "pending", 1_000);
    let (ts, token) = app.action_token(&app.admin_get("/admin").await.body, id, "approve");
    let response = app
        .admin_post_with_auth(
            &format!("/admin/{id}/approve"),
            &action_fields(ts, token),
            None,
            false,
        )
        .await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn unknown_comment_ids_are_not_found() {
    let app = TestApp::new();
    let token = app
        .state
        .signer
        .issue_action_token(999, "approve", app.state.now());
    let response = app
        .admin_post(
            "/admin/999/approve",
            &action_fields(token.ts, token.token),
            None,
        )
        .await;
    assert_eq!(response.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn cross_origin_embeds_are_not_allowed_from_other_sites() {
    let app = TestApp::new();
    let request = Request::builder()
        .method("GET")
        .uri("/embed?page=/blog/post/")
        .header("origin", "https://evil.example")
        .body(Body::empty())
        .expect("request");
    let response = app.send(request).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.header("access-control-allow-origin"), "");
}

#[tokio::test]
async fn preflight_allows_only_the_configured_origin_and_headers() {
    let app = TestApp::new();
    let request = Request::builder()
        .method("OPTIONS")
        .uri("/comment")
        .header("origin", "https://blog.test")
        .header("access-control-request-method", "POST")
        .header("access-control-request-headers", "content-type, x-fragment")
        .body(Body::empty())
        .expect("request");
    let response = app.send(request).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(
        response.header("access-control-allow-origin"),
        "https://blog.test"
    );
    let allowed = response.header("access-control-allow-headers");
    assert!(allowed.contains("content-type"));
    assert!(allowed.contains("x-fragment"));
}
