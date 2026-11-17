mod common;

use axum::http::StatusCode;
use common::{TestApp, PAGE};

fn fields_with_token(app: &TestApp, ts: i64) -> Vec<(String, String)> {
    let (ts, token) = app.token_with_timestamp(PAGE, ts);
    vec![
        ("page".to_owned(), PAGE.to_owned()),
        ("author".to_owned(), "ada".to_owned()),
        ("body".to_owned(), "hello".to_owned()),
        ("ts".to_owned(), ts),
        ("token".to_owned(), token),
    ]
}

#[tokio::test]
async fn missing_token_is_rejected() {
    let app = TestApp::new();
    let fields = vec![
        ("page".to_owned(), PAGE.to_owned()),
        ("author".to_owned(), "ada".to_owned()),
        ("body".to_owned(), "hello".to_owned()),
    ];
    let response = app.post_form("/comment", &fields, false).await;
    assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(app.comment_count(), 0);
}

#[tokio::test]
async fn stale_and_future_tokens_are_rejected() {
    let app = TestApp::new();
    let now = app.state.now();

    let stale = fields_with_token(&app, now - 3 * 60 * 60);
    assert_eq!(
        app.post_form("/comment", &stale, false).await.status,
        StatusCode::UNPROCESSABLE_ENTITY
    );

    let future = fields_with_token(&app, now + 60);
    assert_eq!(
        app.post_form("/comment", &future, false).await.status,
        StatusCode::UNPROCESSABLE_ENTITY
    );

    assert_eq!(app.comment_count(), 0);
}

#[tokio::test]
async fn tokens_younger_than_two_seconds_are_rejected() {
    let app = TestApp::new();
    let fields = fields_with_token(&app, app.state.now());
    let response = app.post_form("/comment", &fields, false).await;
    assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(response.body.contains("expired"));
    assert_eq!(app.comment_count(), 0);
}

#[tokio::test]
async fn tampered_tokens_are_rejected() {
    let app = TestApp::new();
    let mut fields = app.fields(PAGE, "ada", "hello");
    for (key, value) in &mut fields {
        if key == "token" {
            let last = value.pop().expect("token");
            value.push(if last == 'a' { 'b' } else { 'a' });
        }
    }
    let response = app.post_form("/comment", &fields, false).await;
    assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(app.comment_count(), 0);
}

#[tokio::test]
async fn honeypot_submissions_are_dropped() {
    let app = TestApp::new();
    let mut fields = app.fields(PAGE, "ada", "hello");
    fields.push(("website".to_owned(), "https://spam.example".to_owned()));

    let response = app.post_form("/comment", &fields, false).await;
    assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(app.comment_count(), 0);

    let response = app.post_form("/comment", &fields, true).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(app.comment_count(), 0);
}

#[tokio::test]
async fn sixth_comment_in_ten_minutes_is_rate_limited() {
    let app = TestApp::new();
    for index in 0..5 {
        let fields = app.fields(PAGE, "ada", &format!("comment {index}"));
        let response = app.post_form("/comment", &fields, false).await;
        assert_eq!(response.status, StatusCode::SEE_OTHER, "post {index}");
    }

    let blocked = app.fields(PAGE, "ada", "one too many");
    let response = app.post_form("/comment", &blocked, false).await;
    assert_eq!(response.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(response.body.contains("too quickly"));
    assert_eq!(app.comment_count(), 5);

    // A different address has its own bucket.
    let other = app.fields(PAGE, "bob", "from elsewhere");
    let response = app
        .post_form_as("198.51.100.7", "/comment", &other, false)
        .await;
    assert_eq!(response.status, StatusCode::SEE_OTHER);
    assert_eq!(app.comment_count(), 6);
}

#[tokio::test]
async fn link_comments_are_pending_until_approved() {
    let app = TestApp::new();
    let fields = app.fields(PAGE, "ada", "see https://spam.example for deals");
    let response = app.post_form("/comment", &fields, false).await;
    assert_eq!(response.status, StatusCode::SEE_OTHER);
    assert!(response.location().contains("pending=1"));
    assert_eq!(app.comment_count(), 1);

    let embed = app.get("/embed?page=/blog/post/").await;
    assert!(!embed.body.contains("spam.example"));

    let thread = app.get("/thread?page=/blog/post/&pending=1").await;
    assert!(thread.body.contains("awaiting moderation"));
    assert!(!thread.body.contains("spam.example"));

    let admin = app.admin_get("/admin").await;
    assert_eq!(admin.status, StatusCode::OK);
    assert!(admin.body.contains("spam.example"));
    let (ts, token) = app.action_token(&admin.body, 1, "approve");
    let response = app
        .admin_post(
            "/admin/1/approve",
            &[("ts".to_owned(), ts), ("token".to_owned(), token)],
            None,
        )
        .await;
    assert_eq!(response.status, StatusCode::SEE_OTHER);

    let embed = app.get("/embed?page=/blog/post/").await;
    assert!(embed.body.contains("spam.example"));
    assert!(embed.body.contains("<a href=\"https://spam.example\""));
}

#[tokio::test]
async fn keyword_comments_are_pending() {
    let app = TestApp::new();
    let fields = app.fields(PAGE, "ada", "best CASINO deals");
    let response = app.post_form("/comment", &fields, false).await;
    assert_eq!(response.status, StatusCode::SEE_OTHER);
    assert!(response.location().contains("pending=1"));

    let embed = app.get("/embed?page=/blog/post/").await;
    assert!(!embed.body.contains("CASINO"));
}

#[tokio::test]
async fn fragment_rate_limit_still_returns_a_fragment() {
    let app = TestApp::new();
    for index in 0..5 {
        let fields = app.fields(PAGE, "ada", &format!("comment {index}"));
        assert_eq!(
            app.post_form("/comment", &fields, false).await.status,
            StatusCode::SEE_OTHER
        );
    }
    let fields = app.fields(PAGE, "ada", "one too many");
    let response = app.post_form("/comment", &fields, true).await;
    assert_eq!(response.status, StatusCode::OK);
    assert!(response.body.contains("too quickly"));
    assert!(response.body.contains("value=\"ada\""));
}
