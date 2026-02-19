# agent-vault

Keep your secrets hidden from AI agents.

When AI coding agents (Claude Code, Codex, OpenCode) help you set up services, secrets like API keys and tokens flow through LLM provider servers. **agent-vault** prevents this by acting as a secret-aware file I/O layer — agents see placeholders like `<agent-vault:api-key>`, never real values.

```
┌──────────────────────────────────────────────┐
│  Agent sees:                                 │
│    api_key: <agent-vault:openai-key>         │
│    bot_token: <agent-vault:tg-bot-token>     │
│    port: 3000                                │
├──────────────────────────────────────────────┤
│  agent-vault                                 │
│    read:  real value → <agent-vault:key>     │
│    write: <agent-vault:key> → real value     │
├──────────────────────────────────────────────┤
│  Actual file on disk:                        │
│    api_key: sk-proj-abc123...                │
│    bot_token: 7821345:AAF...                 │
│    port: 3000                                │
└──────────────────────────────────────────────┘
```

## Install

```bash
npm install -g @botiverse/agent-vault
```

## Quick start

```bash
# 1. Store a secret (interactive, masked input)
agent-vault set my-api-key

# 2. Write a config file using placeholders
agent-vault write config.yaml --content 'api_key: <agent-vault:my-api-key>
port: 8080'

# 3. Read it back — secrets are redacted
agent-vault read config.yaml
#      1  api_key: <agent-vault:my-api-key>
#      2  port: 8080

# 4. The actual file has real values
cat config.yaml
# api_key: sk-proj-abc123...
# port: 8080
```

## How it works

Secrets are stored in an encrypted local vault (`~/.agent-vault/`). When reading files, known secret values are replaced with `<agent-vault:key>` placeholders. When writing, placeholders are restored to real values. The agent never sees or transmits your secrets.

High-entropy strings not in the vault (like API keys added manually) are automatically detected and redacted as `<agent-vault:UNVAULTED:sha256:XXXXXXXX>`.

## Command reference

### Safe commands

These commands never expose secret values. Both agents and humans can use them.

#### `agent-vault read <file>`

Read a file with all secrets replaced by `<agent-vault:key>` placeholders. Output format matches `cat -n` (line numbers, plain text).

```bash
agent-vault read .env
#      1  TELEGRAM_BOT_TOKEN=<agent-vault:telegram-bot-token>
#      2  OPENAI_API_KEY=<agent-vault:openai-key>
#      3  PORT=3000
```

#### `agent-vault write <file>`

Write a file, replacing `<agent-vault:key>` placeholders with real secret values.

```bash
# Via --content flag
agent-vault write config.yaml --content 'token: <agent-vault:my-token>
port: 3000'

# Via stdin / heredoc
agent-vault write config.yaml <<'EOF'
token: <agent-vault:my-token>
port: 3000
EOF
```

Fails with a clear error if any referenced key is missing:

```
✗ Error: Secret "my-token" not found in vault
  To add it, the user should run: agent-vault set my-token
```

#### `agent-vault has <key> [keys...]`

Check if one or more keys exist in the vault.

```bash
agent-vault has my-key           # prints true/false, exit code 0/1

agent-vault has a b c --json     # {"a": true, "b": false, "c": true}
```

#### `agent-vault list`

List all stored key names (never values).

```bash
agent-vault list                 # one key per line
agent-vault list --json          # {"keys": [{"key": "...", "desc": "..."}]}
```

### Sensitive commands

These commands involve secret values or destructive operations. They **require an interactive terminal (TTY)** and refuse to run without one. Agents should never execute these — they should tell the user to run them.

#### `agent-vault set <key>`

Store a secret value. Prompts for masked input. Warns before overwriting an existing key.

```bash
agent-vault set telegram-bot-token
# Enter value for "telegram-bot-token": ••••••••
# ✓ Saved "telegram-bot-token"

agent-vault set telegram-bot-token    # already exists
# ⚠ "telegram-bot-token" already exists (46 chars, set 2025-01-15T14:30:00.000Z)
# Overwrite? [y/N]

agent-vault set api-key --desc "OpenAI API key"
agent-vault set api-key --from-env OPENAI_API_KEY
echo "value" | agent-vault set api-key --stdin
```

#### `agent-vault get <key>`

View secret metadata, or the actual value with `--reveal`.

```bash
agent-vault get my-key
# Key:      my-key
# Desc:     My API key
# Set at:   2025-01-15T14:30:00.000Z
# Length:   46 chars

agent-vault get my-key --reveal
# sk-proj-abc123...
```

`--reveal` additionally checks that stdout is a TTY — you cannot pipe secret values.

#### `agent-vault rm <key>`

Remove a secret from the vault. Asks for confirmation.

```bash
agent-vault rm old-key
# Remove "old-key"? [y/N]
```

#### `agent-vault import <file>`

Bulk import secrets from a `.env` file. Shows a preview and asks for confirmation. Short/common values (like `localhost`, `3000`) are automatically skipped.

```bash
agent-vault import .env
# Found 5 entries:
#   TELEGRAM_BOT_TOKEN → telegram-bot-token
#   OPENAI_API_KEY     → openai-key
#   PORT               → (skip: too short)
# Import 2 secrets? [Y/n]
```

#### `agent-vault init`

Initialize the vault at `~/.agent-vault/`. Automatically called on first `set` if no vault exists.

```bash
agent-vault init
```

#### `agent-vault scan <file>`

Audit a file for vaulted and potentially unvaulted secrets.

```bash
agent-vault scan config.yaml
# Vaulted (2):
#   line 1: matches "telegram-bot-token"
#   line 2: matches "openai-key"
# Unvaulted suspects (0):
#   (none)
```

## Agent integration

### Skill installation

```bash
npx skills add botiverse/agent-vault
```

The skill teaches agents:

- Use `agent-vault read` instead of the Read tool for secret-bearing files
- Use `agent-vault write` instead of the Write tool
- Never execute `set`, `get`, `rm`, `import` — tell the user to run them
- Use `<agent-vault:key-name>` placeholders in all config content

### How agents work with agent-vault

```
User:  "Help me set up a Telegram bot"

Agent: Let me check if you have the bot token stored.
       → executes: agent-vault has telegram-bot-token
       → false

Agent: I need your Telegram bot token. Please run this in your terminal:

           agent-vault set telegram-bot-token

       You can get the token from @BotFather on Telegram.

User:  (runs the command, enters token)
User:  "Done"

Agent: → executes: agent-vault write config.yaml --content '...<agent-vault:telegram-bot-token>...'
       → ✓ Written config.yaml (1 secret restored)

Agent: Config created. Your bot token is securely stored and I never saw it.
```

## Vault storage

All secrets are stored in a single global vault at `~/.agent-vault/`:

```
~/.agent-vault/
├── vault.json      # AES-256-GCM encrypted secrets (per-value encryption)
└── vault.key       # 256-bit master encryption key (0600 permissions)
```

Living in the home directory means secrets are shared across all projects and are never at risk of being committed to version control.

## Security

- **Secret values never appear in safe command output** — enforced by code, not convention
- **TTY requirement on sensitive commands** — prevents agents from calling `set` / `get --reveal` even through prompt injection
- **High-entropy detection** — unvaulted secrets in files are automatically redacted on read
- **Vault outside project tree** — lives in `~/.agent-vault/`, never at risk of git commit
- **Encrypted at rest** — AES-256-GCM with per-value encryption
- **0600 permissions** — vault files are owner-readable only

## License

Apache-2.0
