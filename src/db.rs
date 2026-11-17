//! SQLite connection, migrations and every SQL statement in the service.
//!
//! All statements are static and use bound parameters. There is no string
//! interpolation of user input anywhere in this module.

use std::path::Path;
use std::str::FromStr;

use rusqlite::{params, Connection, Row};

use crate::models::{Comment, CommentStatus, NewComment};
use crate::spam::{RateLimit, RATE_EVENT_RETENTION_SECS};

const MIGRATIONS: &[(i64, &str)] = &[(1, include_str!("../migrations/0001_init.sql"))];

/// Open the database, apply pragmas and run pending migrations.
pub fn open(path: &Path) -> rusqlite::Result<Connection> {
    let mut connection = Connection::open(path)?;
    connection.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA foreign_keys = ON;
         PRAGMA busy_timeout = 5000;
         PRAGMA synchronous = NORMAL;
         -- The container root filesystem is read-only; keep SQLite's
         -- temporary b-trees in memory instead of /tmp.
         PRAGMA temp_store = MEMORY;",
    )?;
    migrate(&mut connection)?;
    Ok(connection)
}

/// Apply migrations newer than `PRAGMA user_version`, each in its own
/// transaction. The version is stored in the database file, so restarts and
/// concurrent containers never re-run a migration.
pub fn migrate(connection: &mut Connection) -> rusqlite::Result<()> {
    let current: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    for (version, sql) in MIGRATIONS {
        if *version <= current {
            continue;
        }
        let transaction = connection.transaction()?;
        transaction.execute_batch(sql)?;
        // `version` comes from the compiled-in table above, never from input.
        transaction.pragma_update(None, "user_version", version)?;
        transaction.commit()?;
    }
    Ok(())
}

/// Load every non-pending comment for a page in stable chronological order.
/// Deleted comments are included so their replies can keep their position.
pub fn load_comments(connection: &Connection, page: &str) -> rusqlite::Result<Vec<Comment>> {
    let mut statement = connection.prepare(
        "SELECT id, page, parent_id, author, body, status, created_at
         FROM comments
         WHERE page = ?1 AND status <> 'pending'
         ORDER BY created_at ASC, id ASC",
    )?;
    let rows = statement.query_map([page], map_comment)?;
    rows.collect()
}

/// Comments waiting for approval, oldest first.
pub fn pending_comments(connection: &Connection) -> rusqlite::Result<Vec<Comment>> {
    let mut statement = connection.prepare(
        "SELECT id, page, parent_id, author, body, status, created_at
         FROM comments
         WHERE status = 'pending'
         ORDER BY created_at ASC, id ASC",
    )?;
    let rows = statement.query_map([], map_comment)?;
    rows.collect()
}

/// Most recent visible comments, newest first.
pub fn recent_visible_comments(
    connection: &Connection,
    limit: i64,
) -> rusqlite::Result<Vec<Comment>> {
    let mut statement = connection.prepare(
        "SELECT id, page, parent_id, author, body, status, created_at
         FROM comments
         WHERE status = 'visible'
         ORDER BY created_at DESC, id DESC
         LIMIT ?1",
    )?;
    let rows = statement.query_map([limit], map_comment)?;
    rows.collect()
}

/// Page and status of a potential reply target.
pub fn parent_target(
    connection: &Connection,
    id: i64,
) -> rusqlite::Result<Option<(String, CommentStatus)>> {
    let mut statement = connection.prepare("SELECT page, status FROM comments WHERE id = ?1")?;
    let mut rows = statement.query([id])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    let page: String = row.get(0)?;
    let status_raw: String = row.get(1)?;
    let status = CommentStatus::from_str(&status_raw).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, Box::new(error))
    })?;
    Ok(Some((page, status)))
}

pub fn approve_comment(connection: &Connection, id: i64) -> rusqlite::Result<bool> {
    let changed = connection.execute(
        "UPDATE comments SET status = 'visible' WHERE id = ?1 AND status = 'pending'",
        [id],
    )?;
    Ok(changed > 0)
}

pub fn delete_comment(connection: &Connection, id: i64) -> rusqlite::Result<bool> {
    let changed = connection.execute(
        "UPDATE comments SET status = 'deleted' WHERE id = ?1 AND status <> 'deleted'",
        [id],
    )?;
    Ok(changed > 0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateOutcome {
    Created(i64),
    RateLimited,
}

/// Check the rate limits, record the attempt and insert the comment in one
/// transaction. A rejected attempt writes nothing.
pub fn create_comment(
    connection: &mut Connection,
    comment: &NewComment,
    limits: &[RateLimit],
) -> rusqlite::Result<CreateOutcome> {
    let now = comment.created_at;
    let transaction = connection.transaction()?;

    for limit in limits {
        let since = now - limit.window_secs;
        let count: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM rate_events WHERE ip_hash = ?1 AND created_at >= ?2",
            params![comment.ip_hash, since],
            |row| row.get(0),
        )?;
        if count >= i64::from(limit.max) {
            // Dropping the transaction rolls it back; no event is recorded for
            // a rejected comment, so a blocked client cannot extend its ban.
            return Ok(CreateOutcome::RateLimited);
        }
    }

    transaction.execute(
        "INSERT INTO rate_events (ip_hash, created_at) VALUES (?1, ?2)",
        params![comment.ip_hash, now],
    )?;
    transaction.execute(
        "DELETE FROM rate_events WHERE created_at < ?1",
        [now - RATE_EVENT_RETENTION_SECS],
    )?;

    let id = transaction.query_row(
        "INSERT INTO comments (page, parent_id, author, body, status, created_at, ip_hash)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         RETURNING id",
        params![
            comment.page,
            comment.parent_id,
            comment.author,
            comment.body,
            comment.status.as_str(),
            comment.created_at,
            comment.ip_hash,
        ],
        |row| row.get(0),
    )?;

    transaction.commit()?;
    Ok(CreateOutcome::Created(id))
}

fn map_comment(row: &Row<'_>) -> rusqlite::Result<Comment> {
    let status_raw: String = row.get(5)?;
    let status = CommentStatus::from_str(&status_raw).map_err(|error| {
        // The CHECK constraint should make this unreachable; surfacing it as a
        // conversion error keeps the failure visible instead of guessing.
        rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(error))
    })?;
    Ok(Comment {
        id: row.get(0)?,
        page: row.get(1)?,
        parent_id: row.get(2)?,
        author: row.get(3)?,
        body: row.get(4)?,
        status,
        created_at: row.get(6)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_connection() -> Connection {
        let mut connection = Connection::open_in_memory().expect("open in-memory database");
        migrate(&mut connection).expect("run migrations");
        connection
    }

    #[test]
    fn migrations_are_idempotent() {
        let mut connection = test_connection();
        migrate(&mut connection).expect("second migration run is a no-op");
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, 1);
    }

    #[test]
    fn created_comments_are_returned_in_order() {
        let mut connection = test_connection();
        for (index, body) in ["first", "second"].iter().enumerate() {
            let comment = NewComment {
                page: "/p/".into(),
                parent_id: None,
                author: "a".into(),
                body: (*body).into(),
                status: CommentStatus::Visible,
                created_at: 1_000 + index as i64,
                ip_hash: "ip".into(),
            };
            assert!(matches!(
                create_comment(&mut connection, &comment, &[]).unwrap(),
                CreateOutcome::Created(_)
            ));
        }
        let comments = load_comments(&connection, "/p/").unwrap();
        assert_eq!(comments.len(), 2);
        assert_eq!(comments[0].body, "first");
        assert_eq!(comments[1].body, "second");
    }

    #[test]
    fn rate_limits_are_enforced_and_pruned() {
        let mut connection = test_connection();
        let limits = [RateLimit {
            window_secs: 600,
            max: 2,
        }];
        let comment = NewComment {
            page: "/p/".into(),
            parent_id: None,
            author: "a".into(),
            body: "b".into(),
            status: CommentStatus::Visible,
            created_at: 1_000,
            ip_hash: "ip".into(),
        };
        assert!(matches!(
            create_comment(&mut connection, &comment, &limits).unwrap(),
            CreateOutcome::Created(_)
        ));
        assert!(matches!(
            create_comment(&mut connection, &comment, &limits).unwrap(),
            CreateOutcome::Created(_)
        ));
        assert_eq!(
            create_comment(&mut connection, &comment, &limits).unwrap(),
            CreateOutcome::RateLimited
        );
        // Once the window has passed, the same client can comment again.
        let mut later = comment.clone();
        later.created_at = 2_000;
        assert!(matches!(
            create_comment(&mut connection, &later, &limits).unwrap(),
            CreateOutcome::Created(_)
        ));
    }
}
