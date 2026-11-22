mod common;

use axum::http::StatusCode;
use common::{TestApp, PAGE};

#[tokio::test]
async fn healthz_is_plain_ok() {
    let app = TestApp::new();
    let response = app.get("/healthz").await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body, "ok");
}

#[tokio::test]
async fn thread_renders_and_escapes_user_content() {
    let app = TestApp::new();
    app.seed(
        PAGE,
        None,
        "<script>alert('author')</script>",
        "<img src=x onerror=boom> https://example.com/a?b=1&c=2",
        "visible",
        1_700_000_000,
    );

    let response = app.get("/thread?page=/blog/post/").await;
    assert_eq!(response.status, StatusCode::OK);
    assert!(response.body.contains("<div id=\"comments\""));
    assert!(
        response
            .body
            .contains("&#60;script&#62;alert(&#39;author&#39;)&#60;/script&#62;"),
        "author must be escaped: {}",
        response.body
    );
    assert!(!response.body.contains("<script>alert"));
    assert!(response.body.contains("&lt;img src=x onerror=boom&gt;"));
    assert!(!response.body.contains("<img src=x"));
    assert!(response
        .body
        .contains("<a href=\"https://example.com/a?b=1&amp;c=2\" rel=\"nofollow ugc noopener\">"));
    assert!(response.body.contains("href=\"/static/comments.css\""));
    assert!(response.body.contains("https://blog.test/style.css"));

    let csp = response.header("content-security-policy");
    assert!(csp.contains("default-src 'none'"));
    assert!(csp.contains("style-src 'self' https://blog.test"));
    assert_eq!(response.header("x-content-type-options"), "nosniff");
    assert_eq!(response.header("referrer-policy"), "no-referrer");
    assert_eq!(response.header("cache-control"), "no-store");
}

#[tokio::test]
async fn nesting_produces_preorder_and_depth_classes() {
    let app = TestApp::new();
    let root = app.seed(PAGE, None, "root", "one", "visible", 1_000);
    let child = app.seed(PAGE, Some(root), "child", "two", "visible", 1_001);
    let grandchild = app.seed(PAGE, Some(child), "grandchild", "three", "visible", 1_002);
    let second = app.seed(PAGE, None, "second", "four", "visible", 1_003);

    let response = app.get("/thread?page=/blog/post/").await;
    assert_eq!(response.status, StatusCode::OK);
    let body = &response.body;
    let root_pos = body.find(&format!("id=\"c{root}\"")).expect("root");
    let child_pos = body.find(&format!("id=\"c{child}\"")).expect("child");
    let grandchild_pos = body
        .find(&format!("id=\"c{grandchild}\""))
        .expect("grandchild");
    let second_pos = body.find(&format!("id=\"c{second}\"")).expect("second");
    assert!(root_pos < child_pos);
    assert!(child_pos < grandchild_pos);
    assert!(grandchild_pos < second_pos);
    assert!(body.contains("class=\"comment depth-0\""));
    assert!(body.contains("class=\"comment depth-1\""));
    assert!(body.contains("class=\"comment depth-2\""));
}

#[tokio::test]
async fn deleted_comments_are_skipped_or_shown_as_tombstones() {
    let app = TestApp::new();
    let root = app.seed(PAGE, None, "root", "one", "visible", 1_000);
    let childless = app.seed(PAGE, Some(root), "gone", "gone body", "deleted", 1_001);
    let parent = app.seed(PAGE, Some(root), "gone too", "gone body", "deleted", 1_002);
    let reply = app.seed(PAGE, Some(parent), "reply", "still here", "visible", 1_003);

    let response = app.get("/thread?page=/blog/post/").await;
    let body = &response.body;
    assert!(!body.contains("gone body"));
    assert!(
        body.contains(&format!("id=\"c{parent}\"")),
        "tombstone kept"
    );
    assert!(body.contains(&format!("id=\"c{reply}\"")));
    assert!(body.contains("[deleted]"));
    assert!(!body.contains(&format!("id=\"c{childless}\"")));
}

#[tokio::test]
async fn thread_page_hides_the_fragment_heading() {
    let app = TestApp::new();
    let response = app.get("/thread?page=/blog/post/").await;
    assert_eq!(response.status, StatusCode::OK);
    assert!(!response.body.contains("comments-heading"));
    assert!(response
        .body
        .contains("<h1 class=\"comments-title\">comments</h1>"));
}

#[tokio::test]
async fn embed_returns_a_cors_fragment() {
    let app = TestApp::new();
    app.seed(PAGE, None, "ada", "hello", "visible", 1_000);
    let response = app.get("/embed?page=/blog/post/").await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.header("content-type"), "text/html; charset=utf-8");
    assert_eq!(
        response.header("access-control-allow-origin"),
        "https://blog.test"
    );
    assert!(response.body.contains("<div id=\"comments\""));
    assert!(response.body.contains("comments-heading"));
    assert!(response.body.contains("hello"));
    assert!(response.body.contains("name=\"token\" value=\""));
    assert_eq!(response.header("cache-control"), "no-store");
}

#[tokio::test]
async fn reply_query_puts_the_form_under_the_parent() {
    let app = TestApp::new();
    let root = app.seed(PAGE, None, "ada", "hello", "visible", 1_000);
    let response = app.get("/thread?page=/blog/post/&reply=1").await;
    assert_eq!(response.status, StatusCode::OK);
    let body = &response.body;
    assert!(body.contains(&format!("name=\"parent_id\" value=\"{root}\"")));
    assert!(body.contains("replying to <strong>ada</strong>"));

    let list_item = body.find(&format!("id=\"c{root}\"")).expect("comment");
    let list_item_end = body[list_item..]
        .find("</li>")
        .map(|offset| list_item + offset)
        .expect("closing list item");
    let form = body.find("class=\"comment-form\"").expect("form");
    assert!(
        form > list_item && form < list_item_end,
        "form nested under parent"
    );
    assert_eq!(body.matches("class=\"comment-form\"").count(), 1);
}

#[tokio::test]
async fn invalid_reply_target_falls_back_to_the_bottom_form() {
    let app = TestApp::new();
    app.seed(PAGE, None, "ada", "hello", "visible", 1_000);
    let response = app.get("/thread?page=/blog/post/&reply=999").await;
    assert_eq!(response.status, StatusCode::OK);
    assert!(!response.body.contains("name=\"parent_id\""));
    assert!(response.body.contains("class=\"comment-form\""));
}

#[tokio::test]
async fn traversal_and_missing_pages_are_rejected() {
    let app = TestApp::new();
    for uri in [
        "/thread?page=%2F..%2Fetc%2Fpasswd",
        "/thread?page=/blog/../secret/",
        "/thread?page=blog/post/",
        "/thread",
        "/embed?page=%2F..%2Fetc%2Fpasswd",
    ] {
        let response = app.get(uri).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "uri: {uri}");
    }
}

#[tokio::test]
async fn pending_comments_never_render() {
    let app = TestApp::new();
    app.seed(PAGE, None, "spammer", "buy things", "pending", 1_000);
    let response = app.get("/thread?page=/blog/post/").await;
    assert_eq!(response.status, StatusCode::OK);
    assert!(!response.body.contains("buy things"));
    assert!(!response.body.contains("no comments yet"));
    assert!(response.body.contains("comment-form"));
}

#[tokio::test]
async fn pending_notice_is_shown_after_redirect() {
    let app = TestApp::new();
    let response = app.get("/thread?page=/blog/post/&pending=1").await;
    assert_eq!(response.status, StatusCode::OK);
    assert!(response.body.contains("awaiting moderation"));
}

#[tokio::test]
async fn css_assets_are_served_with_their_own_cache_policy() {
    let app = TestApp::new();
    for (path, needle) in [
        ("/static/comments.css", ".comment-body"),
        ("/static/admin.css", ".admin-approve"),
    ] {
        let response = app.get(path).await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.header("content-type"), "text/css; charset=utf-8");
        assert_eq!(response.header("cache-control"), "public, max-age=3600");
        assert!(response.body.contains(needle));
    }
}
