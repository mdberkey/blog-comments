# blog-comments

Comment service for [mdberkey.github.io](https://mdberkey.github.io). Rust,
SQLite, server-rendered HTML, and a small script on the blog. The blog stays on
GitHub Pages; this runs on my home server behind Nginx Proxy Manager.

## Endpoints

Paths are relative to the service root. When `PUBLIC_URL` has a path, such as
`https://example.com/comments`, every route except `/healthz` lives under that
prefix.

| Method | Path | Purpose |
| ------ | ---- | ------- |
| `GET`  | `/healthz` | Liveness. Does not touch the database. |
| `GET`  | `/embed?page=/blog/post/` | HTML fragment: thread plus form. CORS for `SITE_ORIGIN`. |
| `GET`  | `/thread?page=/blog/post/` | Standalone page, works without JavaScript. |
| `POST` | `/comment` | Create a comment. Redirects (303) or returns a fragment with `X-Fragment: 1`. |
| `GET`  | `/admin` | Moderation list. HTTP Basic auth. |
| `POST` | `/admin/{id}/approve` | Publish a held comment. Basic auth plus a signed action token. |
| `POST` | `/admin/{id}/delete` | Soft delete. Same protection. |
| `GET`  | `/static/comments.css` | Public comment styles. |
| `GET`  | `/static/admin.css` | Moderation styles. |

`page` is a root-relative path of `/`, letters, digits, `_`, `-`, and `.`, up to
200 characters, no `..`. It is the storage key, so `/blog/post/` and
`/blog/post` are different threads.

`POST /comment` takes `page`, `author` (1–40 characters), `body` (1–2000
characters), an optional `parent_id`, and the signed `ts`/`token` from the form.
`website` is a honeypot: any value rejects the post. urlencoded and multipart
bodies are both accepted. Without `X-Fragment: 1` a successful post redirects to
`/thread?page=…#c{id}` (`&pending=1` when held); with it, the response is the
refreshed fragment carrying `X-Comment-Id` and `X-Comment-Status`.

## Configuration

Configuration is environment-only and validated at startup; a bad value stops
the process.

| Variable | Default | Notes |
| -------- | ------- | ----- |
| `BIND_ADDR` | `0.0.0.0:8080` | Listen address. |
| `DATABASE_PATH` | `/data/comments.db` | SQLite file; the parent directory is created. |
| `PUBLIC_URL` | required | Public base URL, no trailing slash. A path prefix here mounts the service there. |
| `SITE_ORIGIN` | required | Blog origin, no path. Used for CORS, links, and CSP. |
| `SITE_CSS_URL` | required | Blog stylesheet, linked from `/thread`. |
| `ADMIN_USER` | `admin` | Basic auth user. |
| `ADMIN_PASSWORD_HASH` | required | argon2id PHC string from `hash-password`. |
| `SECRET_KEY` | required | 64 hex characters. Signs tokens and hashes IPs. |
| `TRUST_PROXY` | `true` | Trust the rightmost `X-Forwarded-For` entry. |
| `MODERATE_LINKS` | `false` | Hold comments containing an `http(s)` URL. |
| `PENDING_KEYWORDS` | empty | Comma-separated case-insensitive substrings that force moderation. |
| `RUST_LOG` | `info` | `tracing` filter. |

```sh
openssl rand -hex 32                          # SECRET_KEY
read -rs -p 'admin password: ' PW; echo
printf '%s\n' "$PW" | cargo run -- hash-password
```

`TRUST_PROXY=true` reads the rightmost `X-Forwarded-For` entry, which Nginx's
`$proxy_add_x_forwarded_for` appends and a client cannot forge. Set it to false
if the service is reachable directly. Changing `SECRET_KEY` invalidates every
outstanding form and admin token.

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

Open <http://127.0.0.1:8080/thread?page=/blog/hello/> or `/admin` with user
`admin` and the password you hashed.

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

## Deployment

The `Dockerfile` builds a cargo-chef image on distroless, which has no shell, so
the healthcheck calls the binary's own `healthcheck` subcommand.

```sh
docker build -t blog-comments .
```

Copy `compose.example.yml`, set the image, and give the data directory to the
container's user:

```sh
mkdir -p ./app_data/comments
sudo chown -R 65532:65532 ./app_data/comments
```

The root filesystem is read-only and `/data` is the only writable path.

`comments.env`:

```sh
# Use a path here to share a host: https://example.com/comments
PUBLIC_URL=https://comments.example.com
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

The argon2 hash contains `$`, so the example uses the long `env_file` form with
`format: raw`; otherwise Compose truncates the hash.

In Nginx Proxy Manager, proxy the service. For a dedicated host, point the host
at `comments:8080`, attach a Let's Encrypt certificate, and set the body limit
to 64k. To share a host with other apps, add a custom location for the prefix
and keep the path intact (no trailing slash after the port):

```nginx
location /comments/ {
    proxy_pass http://comments:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    client_max_body_size 64k;
}
```

With that setup `PUBLIC_URL=https://example.com/comments`. The service reads the
prefix from `PUBLIC_URL` and nests its routes under it, so links, redirects, and
static assets stay under `/comments`. `/healthz` stays at the root for the
container healthcheck and is not exposed by the location above.

Back up through SQLite (`sqlite3 /data/comments.db '.backup ...'`) or stop the
container first. The database runs in WAL mode, so copying only `comments.db`
while the service is up can miss recent writes.

## Moderation

Comments are visible immediately. `MODERATE_LINKS=true` holds any comment with
an `http(s)` URL, and `PENDING_KEYWORDS` holds any comment containing a listed
substring. Held comments appear only on `/admin`, which also lists the 100 most
recent visible ones. Delete is a soft delete: a comment with visible replies
becomes a `[deleted]` tombstone so the replies keep their place.

## Blog integration

The blog owns the script and the `<section id="comments" data-src="...">`. This
service supplies `GET /embed?page=…`, fragment responses from `POST /comment`
when `X-Fragment: 1` is set, CORS for `SITE_ORIGIN` only, and reply links that
point at `/embed?page=…&reply={id}` so the script can fetch them in place. Every
control is a real link or form, so the thread still works without JavaScript.
The script derives the service root from the `data-src` URL (everything before
`/embed`), so it works with or without a path prefix.

## Limits

- 5 comments per 10 minutes and 20 per day per hashed client address.
- Plain text only: no Markdown, images, votes, email, or live updates.
- One site origin; multi-tenancy is out of scope.

## License

GPL-3.0. See [LICENSE](LICENSE).
