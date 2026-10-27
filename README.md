# auth-store

A credential vault for a single host: API keys and OAuth tokens kept in one
place, refreshed on the server, and handed to the services that need them.

- **Credentials**: stored per provider and account; every `/api/*` route takes
  a bearer token (`AUTHSTORE_TOKEN`).
- **OAuth providers** as plugins, with interactive login and server-side
  refresh of stored tokens.
- **Audit log** of who resolved which credential.

It binds to loopback (`127.0.0.1:8303` by default) and is meant to sit behind
the services that call it, never on the open internet.

Go, SQLite. `go build ./cmd/...` and `go test ./...`. `AGENTS.md` describes
the routes and how it is run.

## License

MIT, see `LICENSE`.
