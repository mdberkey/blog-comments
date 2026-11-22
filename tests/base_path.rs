mod common;

use axum::http::StatusCode;
use common::{TestApp, PAGE};

const BASE: &str = "/comments";

#[tokio::test]
async fn routes_live_under_the_public_url_path() {
    let app = TestApp::new_with_base_path(BASE);
    app.seed(PAGE, None, "ada", "hello", "visible", 1_000);

    let fragment = app.get(&format!("{BASE}/embed?page={PAGE}")).await;
    assert_eq!(fragment.status, StatusCode::OK);
    assert!(fragment
        .body
        .contains(&format!("action=\"{BASE}/comment\"")));
    assert!(fragment
        .body
        .contains(&format!("href=\"{BASE}/embed?page={PAGE}&reply=1\"")));

    let thread = app.get(&format!("{BASE}/thread?page={PAGE}")).await;
    assert_eq!(thread.status, StatusCode::OK);
    assert!(thread
        .body
        .contains(&format!("href=\"{BASE}/static/comments.css\"")));
    assert!(thread
        .body
        .contains(&format!("https://comments.test{BASE}/thread?page={PAGE}")));
    assert!(thread.body.contains("https://blog.test/blog/post/"));
}

#[tokio::test]
async fn the_unprefixed_routes_are_not_served() {
    let app = TestApp::new_with_base_path(BASE);
    assert_eq!(
        app.get("/embed?page=/blog/post/").await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        app.get("/thread?page=/blog/post/").await.status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn healthz_stays_at_the_root_for_the_container_check() {
    let app = TestApp::new_with_base_path(BASE);
    let response = app.get("/healthz").await;
    assert_eq!(response.status, StatusCode::OK);
}

#[tokio::test]
async fn posts_and_redirects_include_the_prefix() {
    let app = TestApp::new_with_base_path(BASE);
    let fields = app.fields(PAGE, "ada", "hello prefix");

    let response = app
        .post_form(&format!("{BASE}/comment"), &fields, false)
        .await;
    assert_eq!(response.status, StatusCode::SEE_OTHER);
    assert_eq!(response.location(), format!("{BASE}/thread?page={PAGE}#c1"));

    let fields = app.fields(PAGE, "ada", "hello fragment");
    let response = app
        .post_form(&format!("{BASE}/comment"), &fields, true)
        .await;
    assert_eq!(response.status, StatusCode::OK);
    assert!(response
        .body
        .contains(&format!("action=\"{BASE}/comment\"")));
}

#[tokio::test]
async fn admin_links_and_redirects_include_the_prefix() {
    let app = TestApp::new_with_base_path(BASE);
    app.seed(PAGE, None, "held", "held body", "pending", 1_000);

    let page = app.admin_get(&format!("{BASE}/admin")).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page
        .body
        .contains(&format!("href=\"{BASE}/static/admin.css\"")));
    assert!(page
        .body
        .contains(&format!("action=\"{BASE}/admin/1/approve\"")));
    assert!(page
        .body
        .contains(&format!("href=\"https://comments.test{BASE}/thread?page=")));

    let (ts, token) = app.action_token_at(BASE, &page.body, 1, "approve");
    let fields = vec![("ts".to_owned(), ts), ("token".to_owned(), token)];
    let response = app
        .admin_post(
            &format!("{BASE}/admin/1/approve"),
            &fields,
            Some("same-origin"),
        )
        .await;
    assert_eq!(response.status, StatusCode::SEE_OTHER);
    assert_eq!(response.location(), format!("{BASE}/admin"));
}

#[tokio::test]
async fn error_pages_are_self_contained() {
    let app = TestApp::new_with_base_path(BASE);
    let response = app.get(&format!("{BASE}/missing")).await;
    assert_eq!(response.status, StatusCode::NOT_FOUND);
    assert!(response.body.contains("<style>"));
    assert!(!response.body.contains("<link rel=\"stylesheet\""));
}
