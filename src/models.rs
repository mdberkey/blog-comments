//! Database models shared by the read, write and admin paths.

use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommentStatus {
    Visible,
    Pending,
    Deleted,
}

impl CommentStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Visible => "visible",
            Self::Pending => "pending",
            Self::Deleted => "deleted",
        }
    }
}

impl fmt::Display for CommentStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for CommentStatus {
    type Err = UnknownStatus;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "visible" => Ok(Self::Visible),
            "pending" => Ok(Self::Pending),
            "deleted" => Ok(Self::Deleted),
            _ => Err(UnknownStatus),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct UnknownStatus;

impl fmt::Display for UnknownStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unknown comment status in database")
    }
}

impl std::error::Error for UnknownStatus {}

#[derive(Debug, Clone)]
pub struct Comment {
    pub id: i64,
    pub page: String,
    pub parent_id: Option<i64>,
    pub author: String,
    pub body: String,
    pub status: CommentStatus,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct NewComment {
    pub page: String,
    pub parent_id: Option<i64>,
    pub author: String,
    pub body: String,
    pub status: CommentStatus,
    pub created_at: i64,
    pub ip_hash: String,
}

/// Comment prepared for rendering. `body_html` is pre-escaped HTML built by
/// [`crate::render::body_html`]; every other field is plain text.
#[derive(Debug, Clone)]
pub struct RenderedComment {
    pub id: i64,
    pub depth: u32,
    pub depth_class: u32,
    pub author: String,
    pub body_html: crate::render::Html,
    pub created_human: String,
    pub created_iso: String,
    pub deleted: bool,
    pub show_form: bool,
}

/// Comment shown in the moderation list.
#[derive(Debug, Clone)]
pub struct AdminComment {
    pub id: i64,
    pub page: String,
    pub author: String,
    pub body: String,
    pub created_human: String,
    pub ts: String,
    pub approve_token: String,
    pub delete_token: String,
}
