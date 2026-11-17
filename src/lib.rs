//! Library entry point. `main.rs` is a thin wrapper so integration tests can
//! build the real router against a temporary database.

pub mod config;
pub mod db;
pub mod models;
pub mod render;
pub mod routes;
pub mod security;
pub mod spam;
