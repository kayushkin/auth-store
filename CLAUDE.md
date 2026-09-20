# About auth-store

## What it owns

`:8303`. The credential vault: OAuth provider plugins, interactive login, server-side refresh of stored tokens, audit log. dash resolves its Google Calendar token from here. Replaces `apiauth`. The two variables it reads, `AUTHSTORE_TOKEN` (the bearer every `/api/*` route demands) and `AUTHSTORE_CALLBACK_URL`, are declared once in `settings.go` with llm-bridge `servicesettings` (hence `replace ../llm-bridge` in `go.mod`, which makes `deploy-gate` check that tree too) and served read-only at `GET /settings` behind the same bearer; the token is served as set or unset, never its value. A new variable is declared there or `TestEveryEnvironmentVariableTheServiceReadsIsDeclared` fails, and a set `AUTHSTORE_` variable that nobody declared stops the service at boot; `deploy.sh` checks the running service's environment for one before it stops it. Keep a secret a `string` setting, so no parse error can quote it. The listen port and database path are flags (`--port`, `--db`), not settings.

## Where this prompt lives

These sections are stored in agent-store as a project prompt collection and rendered, with identical text, to `AGENTS.md` and `CLAUDE.md` at the root of this repo, so that whichever file a harness reads it gets the same thing. Edit them on dash `/files`, or edit either rendered file: the 15-minute scan carries the edit back into the sections and out to the other file. The host prompt keeps one row for this repo with only what an agent elsewhere needs.
