# Changelog

## 1.0.0 (2026-02-26)

### Features

- **Encrypted vault** — AES-256-GCM encryption with Argon2id key derivation (64 MB memory cost)
- **CLI** — 16 commands: init, unlock, lock, add, get, list, remove, search, status, export, import, run, proxy-init, audit, doctor
- **MCP server** — Model Context Protocol integration for AI coding tools (Claude Code, Cursor, Windsurf) with 6 tools: store_secret, get_secret, list_secrets, delete_secret, export_env, list_projects
- **Proxy key system** — `lockbox://` URI references in .env files; resolved at runtime by `lockbox run`. Generate safe-to-commit `.env.proxy` files with `lockbox proxy-init`
- **Import/export** — Import from .env and JSON files; export in env, JSON, or shell format
- **Project organization** — Group secrets by project for multi-app workflows

### Security

- **HMAC-SHA256 integrity** — Vault integrity verified before every decryption attempt
- **Session management** — 15-minute auto-lock with encrypted session file
- **Rate limiting** — 5 failed unlock attempts per 60s triggers 60-second lockout
- **Audit logging** — Every operation logged with timestamp, source (CLI/MCP), and key identifier (values never logged)
- **Clipboard security** — Auto-clears clipboard 30 seconds after `--copy`
- **Health checks** — `lockbox doctor` verifies vault file, HMAC integrity, decryption, and session status
