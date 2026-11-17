//! Thread assembly and the only place that turns user text into HTML.

use std::collections::HashMap;
use std::fmt;

use linkify::{LinkFinder, LinkKind};
use time::format_description::well_known::Rfc3339;
use time::macros::format_description;
use time::OffsetDateTime;

use crate::models::{Comment, CommentStatus, RenderedComment};
use crate::spam::is_http_url;

/// Pre-escaped HTML. Templates insert it without escaping, so the only
/// constructor is the code below, which escapes every user supplied fragment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Html(String);

impl Html {
    /// Wrap already-trusted HTML, such as rendered template output. User text
    /// must go through [`body_html`], which escapes it first.
    pub(crate) fn new(html: impl Into<String>) -> Self {
        Self(html.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Html {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl askama::filters::HtmlSafe for Html {}

const HUMAN_FORMAT: &[time::format_description::FormatItem<'static>] =
    format_description!("[year]-[month]-[day] [hour]:[minute] UTC");

/// Render a comment body as escaped text with preserved line breaks and
/// http(s) links. Everything else, including quotes, is escaped.
pub fn body_html(body: &str) -> Html {
    let mut finder = LinkFinder::new();
    finder.url_must_have_scheme(true).kinds(&[LinkKind::Url]);

    let mut out = String::with_capacity(body.len() + 32);
    for (line_index, line) in body.split('\n').enumerate() {
        if line_index > 0 {
            out.push_str("<br>");
        }
        for span in finder.spans(line) {
            if span.kind() == Some(&LinkKind::Url) && is_http_url(span.as_str()) {
                out.push_str("<a href=\"");
                escape_into(&mut out, span.as_str());
                out.push_str("\" rel=\"nofollow ugc noopener\">");
                escape_into(&mut out, span.as_str());
                out.push_str("</a>");
            } else {
                escape_into(&mut out, span.as_str());
            }
        }
    }
    Html(out)
}

/// Escape text for use in HTML text nodes and quoted attribute values.
pub fn escape_into(out: &mut String, text: &str) {
    for character in text.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(character),
        }
    }
}

/// Turn the flat comment list into a pre-order rendering.
///
/// - deleted comments with visible descendants become tombstones
/// - deleted comments without descendants are skipped entirely
/// - pending comments never reach this function
/// - `reply_to` marks the comment that should carry the reply form
pub fn flatten(comments: &[Comment], reply_to: Option<i64>) -> Vec<RenderedComment> {
    let index: HashMap<i64, usize> = comments
        .iter()
        .enumerate()
        .map(|(position, comment)| (comment.id, position))
        .collect();

    let mut roots = Vec::new();
    let mut children: HashMap<usize, Vec<usize>> = HashMap::new();
    for (position, comment) in comments.iter().enumerate() {
        if comment.status == CommentStatus::Pending {
            continue;
        }
        match comment.parent_id.and_then(|id| index.get(&id).copied()) {
            Some(parent) if comments[parent].status != CommentStatus::Pending => {
                children.entry(parent).or_default().push(position);
            }
            // No parent, or a parent that is not rendered: show the comment as
            // a root rather than losing it.
            _ => roots.push(position),
        }
    }

    // Iterative post-order so a pathological deep chain cannot overflow the
    // stack. `kept[i]` means comment i is visible or is a tombstone with at
    // least one kept descendant.
    let mut kept = vec![false; comments.len()];
    let mut stack: Vec<(usize, bool)> = roots.iter().map(|&position| (position, false)).collect();
    while let Some((position, expanded)) = stack.pop() {
        if expanded {
            let has_kept_child = children
                .get(&position)
                .is_some_and(|list| list.iter().any(|&child| kept[child]));
            kept[position] = match comments[position].status {
                CommentStatus::Visible => true,
                CommentStatus::Deleted => has_kept_child,
                CommentStatus::Pending => false,
            };
        } else {
            stack.push((position, true));
            if let Some(list) = children.get(&position) {
                for &child in list.iter().rev() {
                    stack.push((child, false));
                }
            }
        }
    }

    let mut rendered = Vec::new();
    let mut stack: Vec<(usize, u32)> = roots.iter().rev().map(|&position| (position, 0)).collect();
    while let Some((position, depth)) = stack.pop() {
        if !kept[position] {
            continue;
        }
        let comment = &comments[position];
        rendered.push(render_one(comment, depth, reply_to));
        if let Some(list) = children.get(&position) {
            for &child in list.iter().rev() {
                stack.push((child, depth.saturating_add(1)));
            }
        }
    }
    rendered
}

fn render_one(comment: &Comment, depth: u32, reply_to: Option<i64>) -> RenderedComment {
    let (created_human, created_iso) = format_timestamp(comment.created_at);
    if comment.status == CommentStatus::Deleted {
        return RenderedComment {
            id: comment.id,
            depth,
            depth_class: depth.min(8),
            author: "[deleted]".to_owned(),
            body_html: Html(String::new()),
            created_human,
            created_iso,
            deleted: true,
            show_form: false,
        };
    }
    RenderedComment {
        id: comment.id,
        depth,
        depth_class: depth.min(8),
        author: comment.author.clone(),
        body_html: body_html(&comment.body),
        created_human,
        created_iso,
        deleted: false,
        show_form: reply_to == Some(comment.id),
    }
}

/// Human readable UTC time and an RFC 3339 timestamp for `<time datetime>`.
pub fn format_timestamp(timestamp: i64) -> (String, String) {
    let Ok(time) = OffsetDateTime::from_unix_timestamp(timestamp) else {
        return (String::new(), String::new());
    };
    let human = time.format(HUMAN_FORMAT).unwrap_or_default();
    let iso = time.format(&Rfc3339).unwrap_or_default();
    (human, iso)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_and_linkifies() {
        let html = body_html("<script>alert(\"x\")</script> https://example.com/a?b=1&c=2");
        let html = html.as_str();
        assert!(html.contains("&lt;script&gt;"));
        assert!(!html.contains("<script>"));
        assert!(html.contains("<a href=\"https://example.com/a?b=1&amp;c=2\""));
        assert!(html.contains("rel=\"nofollow ugc noopener\""));
        assert!(!html.contains("javascript:"));
    }

    #[test]
    fn preserves_lines() {
        assert_eq!(body_html("one\ntwo").as_str(), "one<br>two");
        assert_eq!(body_html("one\n\ntwo").as_str(), "one<br><br>two");
    }

    #[test]
    fn leaves_non_http_schemes_as_text() {
        let html = body_html("ftp://example.com ftp&#58;//example.com");
        assert!(!html.as_str().contains("<a "));
    }

    fn comment(id: i64, parent_id: Option<i64>, status: CommentStatus) -> Comment {
        Comment {
            id,
            page: "/p/".into(),
            parent_id,
            author: format!("author{id}"),
            body: format!("body{id}"),
            status,
            created_at: 1_000 + id,
        }
    }

    #[test]
    fn nests_and_orders() {
        let comments = vec![
            comment(1, None, CommentStatus::Visible),
            comment(2, Some(1), CommentStatus::Visible),
            comment(3, Some(2), CommentStatus::Visible),
            comment(4, None, CommentStatus::Visible),
        ];
        let flat = flatten(&comments, None);
        let shape: Vec<(i64, u32)> = flat.iter().map(|item| (item.id, item.depth)).collect();
        assert_eq!(shape, vec![(1, 0), (2, 1), (3, 2), (4, 0)]);
    }

    #[test]
    fn skips_childless_deleted_comments_and_keeps_tombstones() {
        let comments = vec![
            comment(1, None, CommentStatus::Visible),
            comment(2, Some(1), CommentStatus::Deleted),
            comment(3, Some(1), CommentStatus::Deleted),
            comment(4, Some(3), CommentStatus::Visible),
        ];
        let flat = flatten(&comments, None);
        let ids: Vec<i64> = flat.iter().map(|item| item.id).collect();
        assert_eq!(ids, vec![1, 3, 4]);
        let tombstone = flat.iter().find(|item| item.id == 3).unwrap();
        assert!(tombstone.deleted);
        assert_eq!(tombstone.author, "[deleted]");
        assert_eq!(tombstone.body_html.as_str(), "");
    }

    #[test]
    fn marks_the_reply_target() {
        let comments = vec![
            comment(1, None, CommentStatus::Visible),
            comment(2, None, CommentStatus::Visible),
        ];
        let flat = flatten(&comments, Some(2));
        assert!(!flat[0].show_form);
        assert!(flat[1].show_form);
    }
}
