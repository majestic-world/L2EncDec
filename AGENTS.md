# AGENTS.md

## Conventions

- Code, comments, and identifiers in English; replies to the user in Brazilian Portuguese (pt-br).
- Count before pluralizing and write the matching form: "1 classe", "2 classes", never the "(s)" shorthand.
- Commit only when the user asks. Use Conventional Commits with the description and body in pt-br (e.g. `fix(decoder): corrige leitura do cabeçalho`). The user is the sole author: omit `Co-authored-by` trailers.
- Unit tests live in `src/tests/`, mirroring the module path (`src/foo/bar.rs` → `src/tests/foo/bar.rs`). Wire each file from the module under test with `#[cfg(test)] #[path = "../tests/foo/bar.rs"] mod tests;` so `use super::*;` reaches private items.

## Agent skills

### Issue tracker

Issues are tracked as local markdown files under `.scratch/<feature>/`. See `docs/agents/issue-tracker.md`.

### Triage labels

Default canonical labels: `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: root `GLOSSARY.md` + `docs/adr/`. See `docs/agents/domain.md`.
