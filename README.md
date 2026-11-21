# blog-comments

Self-hosted comment service for [mdberkey.github.io](https://mdberkey.github.io).

Rust, SQLite, server-rendered HTML, and roughly 100 lines of vanilla JavaScript
on the blog. Readers post without an account. The blog stays on GitHub Pages;
only this service runs on the home server, behind Nginx Proxy Manager at
`comments.mikecraft.ooguy.com`.

The service is deliberately small: one SQLite file, no queue, no cache, no
background workers, no third-party requests. [PLAN.md](PLAN.md) is the original
design; the "Deviations from PLAN.md" section below records where the
implementation had to differ.

## HTTP surface

| Method | Path                     | Purpose |
| ------ | ------------------------ | ------- |
| `GET`  | `/healthz`               | Liveness, returns `ok`. Does not touch the database. |
| `GET`  | `/embed?page=/blog/post/` | HTML fragment: thread plus form. CORS enabled for `SITE_ORIGIN`. |
| `GET`  | `/thread?page=/blog/post/` | Standalone page, works without JavaScript. |
| `POST` | `/comment`               | Create a comment. Redirects (303) or returns a fragment with `X-Fragment: 1`. |
| `GET`  | `/admin`                 | Moderation list. HTTP Basic auth. |
| `POST` | `/admin/{id}/approve`    | Publish a held comment. Basic auth plus a signed action token. |
| `POST` | `/admin/{id}/delete`     | Soft delete a comment. Same protection. |
| `GET`  | `/static/comments.css`   | Public comment styles. |
| `GET`  | `/static/admin.css`      | Moderation styles. |

`page` must be a root-relative path made of `/`, letters, digits, `_`, `-`, `.`.
It cannot contain `..`. The same path is used as the storage key, so
`/blog/post/` and `/blog/post` are different threads.

### `POST /comment` fields

| Field       | Required | Rules |
| ----------- | -------- | ----- |
| `page`      | yes      | See above, 1–200 characters. |
| `author`    | yes      | Trimmed, 1–40 characters, no control characters. |
| `body`      | yes      | Trimmed, 1–2000 characters, control characters other than `\n` and `\t` rejected. |
| `parent_id` | no       | Existing, visible comment on the same page. |
| `ts`, `token` | yes    | Signed form token from `/embed` or `/thread`. |
| `website`   | no       | Honeypot. Any non-empty value rejects the submission. |

Both `application/x-www-form-urlencoded` and `multipart/form-data` bodies are
accepted, because the blog script submits `FormData`.

Without `X-Fragment: 1` a successful post redirects to
`/thread?page=...#c{id}` (or `&pending=1` when held). With `X-Fragment: 1`, the
response is the refreshed fragment, always `200`, with `X-Comment-Id` and
`X-Comment-Status` headers describing the new comment; `X-Comment-Status` is
`visible` or `pending`.

## Configuration

All configuration comes from the environment and is validated at startup. A bad
value stops the process instead of failing a later request.

| Variable              | Default            | Notes |
| --------------------- | ------------------ | ----- |
| `BIND_ADDR`           | `0.0.0.0:8080`     | Socket address to listen on. |
| `DATABASE_PATH`       | `/data/comments.db`| SQLite file; its parent directory is created. |
| `PUBLIC_URL`          | required           | Public base URL of this service, no trailing slash. |
| `SITE_ORIGIN`         | required           | Blog origin, no path. Used for CORS, links and CSP. |
| `SITE_CSS_URL`        | required           | The blog's stylesheet, linked from `/thread`. |
| `ADMIN_USER`          | `admin`            | Basic auth user. |
| `ADMIN_PASSWORD_HASH` | required           | argon2id PHC string, generated with `hash-password`. |
| `SECRET_KEY`          | required           | 64 hex characters (32 random bytes). Signs tokens and hashes IPs. |
| `TRUST_PROXY`         | `true`             | Trust the rightmost `X-Forwarded-For` entry. |
| `MODERATE_LINKS`      | `false`            | Opt in to holding comments that contain an `http(s)` URL. |
| `PENDING_KEYWORDS`    | empty              | Comma-separated case-insensitive substrings that force moderation. |
| `RUST_LOG`            | `info`             | Standard `tracing` filter. |

Generate the secrets:

```sh
openssl rand -hex 32                          # SECRET_KEY
read -rs -p 'admin password: ' PW; echo
printf '%s\n' "$PW" | cargo run -- hash-password
```

`hash-password` reads exactly one line from stdin and prints the PHC string.
Change `SECRET_KEY` only if you accept invalidating every outstanding form and
moderation token; rate-limit buckets also change because the IP hash changes.

`TRUST_PROXY=true` only makes sense behind a proxy that appends the real client
address as the **rightmost** `X-Forwarded-For` entry; Nginx's
`$proxy_add_x_forwarded_for` does this. The service reads the rightmost entry,
which a client cannot forge. If the service is reachable directly, set
`TRUST_PROXY=false`, otherwise a client can supply its own header and choose its
rate-limit bucket.

## Local development

```sh
export PUBLIC_URL=http://127.0.0.1:8080
export SITE_ORIGIN=http://127.0.0.1:8000
export SITE_CSS_URL=http://127.0.0.1:8000/style.css
export ADMIN_PASSWORD_HASH="$(printf 'hunter2\n' | cargo run --quiet -- hash-password)"
export SECRET_KEY=$(openssl rand -hex 32)
export BIND_ADDR=127.0.0.1:8080
export DATABASE_PATH=/tmp/comments.db
cargo run
```

Then open <http://127.0.0.1:8080/thread?page=/blog/hello/>. The admin page is
<http://127.0.0.1:8080/admin> with user `admin` and the password you hashed.

Checks used during development:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

The test suite builds the real router against a temporary SQLite file. It
covers escaping, nesting, token age and tampering, the honeypot, rate limits,
multipart and urlencoded posts, fragment and redirect responses, moderation,
admin authentication, signed admin actions and CORS.

## Deployment

The image is built from `Dockerfile`: a cargo-chef builder plus
`gcr.io/distroless/cc-debian12:nonroot`. It has no shell, so the compose
healthcheck calls the binary's own `healthcheck` subcommand, which performs a
minimal `GET /healthz` against `127.0.0.1` on the port from `BIND_ADDR`.

```sh
docker build -t blog-comments .
```

Copy `compose.example.yml` into the compose project and set the image name to
wherever you push it. The service expects:

```sh
mkdir -p ./app_data/comments
sudo chown -R 65532:65532 ./app_data/comments
```

The container runs as uid/gid `65532` (distroless `nonroot`) and the root
filesystem is read-only. `/data` is the only writable path. Keep the directory
owned by `65532`; otherwise SQLite fails with "unable to open database file".

Create `comments.env` next to the compose file:

```sh
PUBLIC_URL=https://comments.mikecraft.ooguy.com
SITE_ORIGIN=https://mdberkey.github.io
SITE_CSS_URL=https://mdberkey.github.io/style.css
ADMIN_USER=admin
ADMIN_PASSWORD_HASH=$argon2id$v=19$m=19456,t=2,p=1$...
SECRET_KEY=...
TRUST_PROXY=true
# Both moderation rules are off unless set.
# MODERATE_LINKS=true
# PENDING_KEYWORDS=casino,payday loan
```

The argon2 hash contains `$`, and Compose interpolates `$` inside a plain
`env_file`. The example therefore uses the long `env_file` form with
`format: raw`. Without it, `ADMIN_PASSWORD_HASH` reaches the container as an
empty or truncated string. If you use a different orchestrator, verify that the
hash arrives intact (for example with `docker compose config`).

In Nginx Proxy Manager create a proxy host for
`comments.mikecraft.ooguy.com` pointing at `comments:8080`, attach a Let's
Encrypt certificate, and set the maximum body size to **64k** (the service's own
limit). Add this to the advanced configuration so the service sees the client
address and the correct scheme:

```nginx
proxy_set_header Host $host;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
client_max_body_size 64k;
```

NPM and this service must share a Docker network; `expose` intentionally does
not publish a host port.

Backups: stop the container or use `sqlite3 /data/comments.db '.backup ...'`
before copying. The database uses WAL mode, so a plain copy of only
`comments.db` while the service is running can miss recent writes. If `app_data`
is already covered by restic, include the `-wal` and `-shm` files or back up
through SQLite.

## Moderation

New comments are `visible` immediately unless they contain an `http(s)` URL
(when `MODERATE_LINKS=true`) or match `PENDING_KEYWORDS`. Held comments are
`pending`, never appear in `/embed` or `/thread`, and are listed at `/admin`
with **approve** and **delete** buttons. Delete is a soft delete: a deleted
comment with visible replies becomes a `[deleted]` tombstone so the replies keep
their place; a deleted leaf disappears.

`/admin` shows every pending comment and the 100 most recent visible ones.
Approving or deleting requires both the Basic auth credentials and a signed
action token embedded in the form, valid for two hours. Cross-site POSTs are
rejected via `Sec-Fetch-Site` (older clients that omit the header are allowed),
so a malicious page cannot submit a cached Basic-auth form on the admin's
behalf.

## Blog integration contract

The blog owns the small script and the `<section id="comments" data-src="...">`.
This service provides:

- `GET /embed?page=…` returning the fragment `#comments`.
- `POST /comment` accepting the form fields above and returning a fragment when
  the request carries `X-Fragment: 1`.
- CORS only for `SITE_ORIGIN`, with `X-Comment-Id` and `X-Comment-Status`
  exposed to the page.
- Reply links in the fragment point back at `/embed?page=…&reply={id}`, so the
  script can fetch them without a navigation; on `/thread` the same links stay
  on the full page.

Every control is a real link or a real form, so the thread keeps working if
JavaScript fails.

## Deviations from PLAN.md

Each change below fixes a flaw or closes a gap in the plan; none change the
architecture.

| Plan | Implementation | Reason |
| ---- | -------------- | ------ |
| Layout only mentions `src/main.rs` | Added `src/lib.rs`; `main.rs` is a thin wrapper | Integration tests need to build the real router in-process. |
| `AllowOrigin::exact` | `AllowOrigin::list([origin])` | `exact` emits `Access-Control-Allow-Origin` even for foreign origins, which is not an allowlist. `list` filters and adds `Vary: Origin`. |
| CSP `style-src 'self'; img-src 'self'` | Also allows `SITE_ORIGIN` for style, img and font | `/thread` links the blog's own stylesheet; the plan's policy would block it. Scripts remain disabled. |
| Indent with an inline `--depth` style | Classes `depth-0` … `depth-8` | The CSP blocks inline styles. |
| Proxy body limit `16k` | 64 KiB in the service; README tells the proxy to use 64k | 2,000 four-byte characters are ~24 KiB after percent-encoding, so 16k rejects valid comments. |
| Token "valid 30 minutes … over 2 hours" | Accepted from 2 seconds to 2 hours old | The plan states two different lifetimes. The rejection rule was kept as the upper bound. |
| Optional keyword list, no hash tool | `PENDING_KEYWORDS` env var and `hash-password` subcommand | Without them the keyword list and admin password cannot be configured. |
| "No cookies, no sessions, so no CSRF surface" | Signed admin action tokens plus `Sec-Fetch-Site` rejection | Browsers resend Basic auth automatically, so admin forms do have a CSRF surface. |
| Form posts are urlencoded | Accept multipart too | The planned blog script submits `FormData`, which is multipart. |
| No response headers for the new comment | `X-Comment-Id` and `X-Comment-Status` on fragment responses | The blog script needs to focus the new comment and show the moderation state. |
| No notice after a held comment | `pending=1` on the redirect shows "awaiting moderation" | Otherwise a held comment looks lost. |
| Invalid `reply` query is undefined | Silently falls back to the bottom form | A stale link should not replace the thread with an error. |
| Admin only approves/deletes | Admin bodies render as escaped `<pre>` text, not linkified | Clickable spam in the moderation UI is an unnecessary risk. |
| Serve static files with `ServeDir` | CSS is embedded with `include_str!` | Two small files, no directory traversal surface, one less dependency. |
| Unspecified error codes | 422 for validation, 429 for rate limit, 200 for fragment errors | Full pages keep a meaningful status; fragment clients always get a fragment to swap in. |
| Honeypot rejection message unspecified | Generic rejection message | Do not teach bots which field failed. |
| `/healthz` implied | Does not query SQLite | It is a process liveness check, not a data-volume check. |
| Compose example | Added `user: "65532:65532"`, `start_period`, and `env_file` `format: raw` | Makes the volume ownership requirement explicit, avoids a slow-start false failure, and stops Compose from interpolating the `$` in the argon2 hash. |

## Operational limits

- 5 comments per 10 minutes and 20 per day per hashed client address.
- Comments are plain text: no Markdown, images, voting, email notifications or
  live updates. Reload to see other readers' comments.
- Recent comments on `/admin` are capped at 100; older ones remain in the
  database.
- Only one site origin is supported. Multi-site tenancy is out of scope.
- The service does not send email, so a held comment is only visible in
  `/admin`.

## License

GNU General Public License v3.0. See [LICENSE](LICENSE).
