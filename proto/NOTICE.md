# Vendored schema — WhatsApp's `HistorySync` wire format

The 16 files in this directory prefixed `WAWeb*`, plus `WACommon.proto`, are **not**
original to this project. They are the subset (of 57) needed to parse `HistorySync` /
`WebMessageInfo` / `MessageKey` — the protobuf schema an incremental backup's
`messages.bin` uses (see `waincrement.py`, issue #129).

- **Source:** [`tulir/whatsmeow`](https://github.com/tulir/whatsmeow), directory `proto/`.
- **Commit:** `0fadda796019293764d0c2f6f08cb9453ef3eaaa` (2026-08-29).
- **License:** MPL-2.0 (Mozilla Public License 2.0) — compatible with distribution as
  part of this GPL-3.0 project (MPL-2.0 §3.3 permits combining with a GPL-licensed work
  without the "Incompatible With Secondary Licenses" notice, which whatsmeow does not
  carry).
- **Modification:** only the `import "dir/File.proto";` lines were rewritten to
  `import "File.proto";`, to match this project's flat, single-directory `proto/`
  convention (whatsmeow's own tree nests each file under a per-package directory). No
  message, field, or enum definition was changed. Regenerate with `protoc` exactly as
  for every other file here — see the root `CLAUDE.md` / README "Protobuf automatic fix".
- **Not all of whatsmeow's `proto/` directory** — only what `WAWebProtobufsHistorySync`,
  `WAWebProtobufsWeb` and `WAWebProtobufsE2E` transitively import, determined by tracing
  actual Python imports, not guessed.

This schema is reverse-engineered by the whatsmeow/Baileys community, not published by
WhatsApp/Meta. `lib/increment.py` treats it as best-effort: an unparseable frame or
message is skipped, not raised.
