//! blog-comments: a small self-hosted comment service.
//!
//! Subcommands:
//! - (none)         run the HTTP server
//! - `healthcheck`  GET /healthz on localhost, for container healthchecks
//! - `hash-password` read one password from stdin and print an argon2id hash

use std::env;
use std::error::Error;
use std::io::{self, IsTerminal, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::ExitCode;
use std::str::FromStr;
use std::time::Duration;

use blog_comments::config::{Config, DEFAULT_BIND_ADDR};
use blog_comments::routes::{build_router, AppState};
use blog_comments::security::hash_admin_password;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("blog-comments: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn Error>> {
    match env::args().nth(1).as_deref() {
        Some("healthcheck") => return healthcheck(),
        Some("hash-password") => return hash_password(),
        Some("-h" | "--help" | "help") => {
            print_help();
            return Ok(());
        }
        Some(other) => {
            return Err(format!("unknown command {other:?}; try --help").into());
        }
        None => {}
    }

    init_tracing();
    let config = Config::from_env()?;
    if let Some(parent) = config.database_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    let bind_addr = config.bind_addr;
    let database_path = config.database_path.clone();
    info!(
        %bind_addr,
        database = %database_path.display(),
        site = %config.site_origin,
        moderate_links = config.moderate_links,
        trust_proxy = config.trust_proxy,
        "starting blog-comments"
    );

    let state = AppState::new(config)?;
    let router = build_router(state);
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    info!(%bind_addr, "listening");

    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    info!("server stopped");
    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                tracing::error!(%error, "failed to install SIGTERM handler");
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
    info!("shutdown signal received");
}

/// Minimal HTTP client so the runtime image needs neither curl nor a shell.
fn healthcheck() -> Result<(), Box<dyn Error>> {
    let bind = env::var("BIND_ADDR").unwrap_or_else(|_| DEFAULT_BIND_ADDR.to_owned());
    let port = SocketAddr::from_str(&bind)
        .map(|address| address.port())
        .unwrap_or(8080);
    let address = SocketAddr::from(([127, 0, 0, 1], port));

    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let (head, body) = match response.split_once("\r\n\r\n") {
        Some(parts) => parts,
        None => return Err("healthcheck: malformed HTTP response".into()),
    };
    if head.starts_with("HTTP/1.1 200") && body.trim() == "ok" {
        Ok(())
    } else {
        Err(format!(
            "healthcheck: unexpected response: {}",
            head.lines().next().unwrap_or("<empty>")
        )
        .into())
    }
}

fn hash_password() -> Result<(), Box<dyn Error>> {
    if io::stdin().is_terminal() {
        eprintln!("reading one line from stdin (use `read -s` to keep it out of shell history)");
        eprintln!("password: ");
    }
    let mut password = String::new();
    io::stdin().read_line(&mut password)?;
    let password = password.trim_end_matches(['\r', '\n']);
    if password.is_empty() {
        return Err("password must not be empty".into());
    }
    let hash = hash_admin_password(password)?;
    println!("{hash}");
    Ok(())
}

fn print_help() {
    println!(
        "blog-comments {version}

usage:
  blog-comments              run the HTTP server (configuration comes from the environment)
  blog-comments healthcheck  GET /healthz on 127.0.0.1:$BIND_ADDR
  blog-comments hash-password  read one password from stdin, print an argon2id PHC string

see README.md for the environment variables",
        version = env!("CARGO_PKG_VERSION")
    );
}
