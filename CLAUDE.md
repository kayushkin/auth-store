# About auth-store

## What it owns

`:8303`. The credential vault: OAuth provider plugins, interactive login, server-side refresh of stored tokens, audit log. dash resolves its Google Calendar token from here. Replaces `apiauth`.

## Where this prompt lives

These sections are stored in agent-store as a project prompt collection and rendered, with identical text, to `AGENTS.md` and `CLAUDE.md` at the root of this repo, so that whichever file a harness reads it gets the same thing. Edit them on dash `/files`, or edit either rendered file: the 15-minute scan carries the edit back into the sections and out to the other file. The host prompt keeps one row for this repo with only what an agent elsewhere needs.
