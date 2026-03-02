# Lockbox

**Encrypted API key vault with MCP integration for AI coding tools.**

Lockbox stores your API keys in an AES-256-GCM encrypted vault on your machine. Access them from the CLI, pipe them into scripts, or let AI coding agents (Claude Code, Cursor, Windsurf) retrieve secrets through the Model Context Protocol — without ever putting real keys in your codebase.

## Quick Start

```bash
npm install -g lockbox-vault

lockbox init                        # create your encrypted vault
lockbox add openai API_KEY sk-...   # store a secret
lockbox get openai API_KEY          # retrieve it
```

## Installation

```bash
npm install -g lockbox-vault
```

Requires Node.js 18+.

## CLI Commands

### Vault Lifecycle

```bash
lockbox init                # create a new encrypted vault
lockbox unlock              # unlock with your master password (15-min session)
lockbox lock                # lock the vault immediately
lockbox status              # show vault info, lock state, key count
lockbox doctor              # run health checks on the vault
```

### Secret Management

```bash
lockbox add openai API_KEY sk-abc123              # store a secret
lockbox add stripe SECRET --project myapp         # organize by project
lockbox add aws ACCESS_KEY                        # prompts for value (hidden)
lockbox get openai API_KEY                        # print to stdout
lockbox get openai API_KEY --copy                 # copy to clipboard (clears in 30s)
lockbox remove openai API_KEY                     # delete (with confirmation)
lockbox list                                      # show all keys (never values)
lockbox list --project myapp                      # filter by project
lockbox search stripe                             # search by name, service, or notes
```

### Import & Export

```bash
lockbox import .env                               # import from .env file
lockbox import creds.json --project myapp         # import from JSON
lockbox export > .env                             # export as .env format
lockbox export --format json                      # export as JSON
lockbox export --format shell >> ~/.bashrc        # export as shell exports
```

### Proxy Key System

The proxy key system lets you commit `.env` files to git without exposing real secrets. Instead of actual values, your env file contains `lockbox://` references that are resolved at runtime.

```bash
# generate a .env.proxy file (safe to commit)
lockbox proxy-init --project myapp

# the generated file looks like:
# OPENAI_API_KEY=lockbox://openai/API_KEY
# STRIPE_SECRET_KEY=lockbox://stripe/SECRET_KEY

# run your app with real values injected
lockbox run --env-file .env.proxy "npm start"
lockbox run --env-file .env.proxy "python app.py"
```

Non-proxy values (like `DATABASE_URL=postgresql://localhost/mydb`) are passed through unchanged.

### Audit & Security

```bash
lockbox audit                                     # show last 50 audit entries
lockbox audit --since 2025-01-01                  # filter by date
lockbox audit -n 10                               # limit entries
```

## MCP Setup

Lockbox exposes your vault to AI coding agents via the Model Context Protocol. The MCP server provides 6 tools: `store_secret`, `get_secret`, `list_secrets`, `delete_secret`, `export_env`, and `list_projects`.

**Prerequisites:** Unlock your vault before using MCP tools:

```bash
lockbox unlock
```

### Claude Code

Add to your project's `.mcp.json`:

```json
{
  "mcpServers": {
    "lockbox": {
      "command": "npx",
      "args": ["lockbox-mcp"]
    }
  }
}
```

### Cursor

Add to `.cursor/mcp.json` in your project root (or `~/.cursor/mcp.json` for global):

```json
{
  "mcpServers": {
    "lockbox": {
      "command": "npx",
      "args": ["lockbox-mcp"]
    }
  }
}
```

### Windsurf

Add to `~/.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "lockbox": {
      "command": "npx",
      "args": ["lockbox-mcp"]
    }
  }
}
```

## Security Model

| Layer | Implementation |
|-------|---------------|
| **Encryption** | AES-256-GCM with 12-byte random IV (fresh on every save) |
| **Key Derivation** | Argon2id (64 MB memory, 3 iterations, 4 threads) |
| **Integrity** | HMAC-SHA256 verified before decryption attempt |
| **Session** | Derived key encrypted to temp file, auto-expires after 15 minutes |
| **Rate Limiting** | 5 failed unlock attempts per 60s triggers 60s lockout |
| **Audit Trail** | Append-only log of all operations (values never logged) |
| **Clipboard** | Auto-clears after 30 seconds when using `--copy` |
| **Memory** | Derived key zeroed on lock; secrets only in memory while unlocked |

### Vault File Format

The vault is a single encrypted JSON file at `~/.config/lockbox/vault.enc`:

```
{ salt, iv, tag, ciphertext, hmac }  (all base64-encoded)
```

The decrypted payload contains versioned key entries with per-key metadata (project, notes, timestamps, expiry).

## Contributing

Contributions are welcome! Please open an issue or submit a pull request on [GitHub](https://github.com/lockboxdev/lockbox).

```bash
git clone https://github.com/lockboxdev/lockbox.git
cd lockbox
npm install
npm run build
npm test
```

## License

MIT
