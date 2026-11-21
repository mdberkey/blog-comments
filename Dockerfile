# syntax=docker/dockerfile:1

# Dependency builds are cached independently of source changes.
FROM rust:1.100-slim-bookworm AS chef
RUN cargo install cargo-chef --locked
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --locked --recipe-path recipe.json
COPY . .
RUN cargo build --release --locked --bin blog-comments

# The runtime image has no shell, package manager or curl. The binary's
# `healthcheck` subcommand performs the HTTP check itself.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /app/target/release/blog-comments /usr/local/bin/blog-comments
ENV BIND_ADDR=0.0.0.0:8080
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/blog-comments"]
