# agent-vault — Design Document

## Problem

When AI coding agents (Claude Code, Codex, OpenCode, etc.) help users configure environments — setting up bot tokens, API keys, database credentials — the secrets flow through the LLM provider's servers. With proxies or relay services in the middle, the risk of leakage multiplies. Users currently have no good way to let agents manage config files without exposing secrets.

## Solution

`agent-vault` is a CLI tool that acts as a **secret-aware file I/O layer** for AI agents. It provides `read` and `write` commands that automatically redact/restore secrets, so the agent only ever sees placeholders like `<agent-vault:telegram-bot-token>`.

```
┌─────────────────────────────────────────────────────┐
│  Agent (Claude Code / Codex / OpenCode)             │
│                                                     │
│  Sees: api_key: <agent-vault:openai-key>            │
│        bot_token: <agent-vault:tg-bot-token>        │
│        port: 3000                                   │
│                                                     │
│  Executes: read / write / has / list   (safe)       │
│  Suggests: "Please run: agent-vault set ..." (sens.)│
├─────────────────────────────────────────────────────┤
│  agent-vault CLI                                    │
│                                                     │
│  read:  real value → <agent-vault:key>              │
│  write: <agent-vault:key> → real value              │
├─────────────────────────────────────────────────────┤
│  Actual file on disk                                │
│                                                     │
│  api_key: sk-proj-abc123...                         │
│  bot_token: 7821345:AAF...                          │
│  port: 3000                                         │
└─────────────────────────────────────────────────────┘
```

## Design Principles

1. **Secrets never reach the agent.** Read always redacts, write always restores.
2. **Safety classification, not role separation.** Every command is classified by whether it can expose secret values. Safe commands can be used by both agents and humans. Sensitive commands enforce a TTY requirement — structurally impossible for agents to execute.
3. **The agent guides, the user acts.** When a secret is missing, the agent tells the user what command to run. The user runs it in their own terminal.
4. **CLI-first.** Standalone command, composable with any agent framework.
5. **Minimal surface area.** Few commands, each does one thing well.

---

## Command Safety Classification

The fundamental question for each command is: **can its output or its interaction ever expose a secret value?** This determines who can use it.

```
┌─────────────────────────────────────────────────────────────┐
│  SAFE COMMANDS                                              │
│  Output never contains secret values. Non-interactive.      │
│  Can be used by both agents and humans.                     │
│                                                             │
│  read <file>            cat -n with secrets redacted        │
│  write <file>           placeholders → real values on disk  │
│  has <key> [keys...]    true/false, exit code 0/1           │
│  list                   key names only, never values        │
│                                                             │
│  Agents execute these directly via Bash/shell tools.        │
│  Humans use them too — e.g. read to preview what an agent   │
│  sees, list to check their vault, write to populate a       │
│  config from a template.                                    │
├─────────────────────────────────────────────────────────────┤
│  SENSITIVE COMMANDS                                         │
│  Involve secret values (input or output) or destructive ops.│
│  Human only. Require interactive TTY — refuse without.      │
│                                                             │
│  set <key>              Secret value enters via masked input│
│  get <key> --reveal     Secret value exits to stdout        │
│  rm <key>               Destructive, needs confirmation     │
│  import <file>          Reads secret values, needs confirm  │
│  init                   Vault setup                         │
│  scan <file>            Audit tool, human-oriented output   │
│                                                             │
│  Agents NEVER execute these. They tell the user to run them.│
│  TTY check enforces this — no TTY, command refuses to start.│
└─────────────────────────────────────────────────────────────┘
```

### Why this split?

The boundary is drawn by a single invariant: **no secret value ever appears in the output of a safe command.** This is structural, not policy.

- `read` — outputs file content, but ALL secret values (known + high-entropy suspects) are replaced with placeholders before output. Structurally safe.
- `write` — takes placeholders IN, writes real values to DISK, outputs only a status message. Structurally safe.
- `has` — outputs true/false. No values involved.
- `list` — outputs key names. No values involved.

Conversely, sensitive commands inherently touch secret values:

- `set` — the user types a secret value into the terminal.
- `get --reveal` — a secret value appears on stdout.
- `import` — reads a file full of secret values into the vault.

**The TTY requirement is the hard enforcement.** Even if an agent (through prompt injection or misconfigured skill) tries to run `agent-vault set foo`, the command detects no interactive TTY and exits immediately with an error. This makes the boundary not just a convention but a technical guarantee.

### Why can't agents call `set`?

1. **No TTY in agent context.** Agent tool environments (Bash in Claude Code, shell in Codex) are not interactive terminals. Even if some handle stdin, the behavior is unreliable and varies across platforms.
2. **Wrong trust model.** The agent is orchestrating a flow where a secret passes through its execution context — even if masked, the process is under agent control.
3. **Unnecessary risk.** The agent can simply tell the user: "please run `agent-vault set stripe-key`". The user runs it in their own terminal. Zero exposure, zero ambiguity.

---

## Safe Commands (agent + human)

Non-interactive. Deterministic. Stdout never contains secret values. Agents call these directly. Humans use them too.

### `agent-vault read <file>`

Reads a file, replacing any known secret values with `<agent-vault:key>` placeholders. Output format mirrors `cat -n` — line numbers, plain text, no decoration.

```bash
$ agent-vault read config.yaml
     1	bot_token: <agent-vault:telegram-bot-token>
     2	api_key: <agent-vault:openai-key>
     3	port: 3000
     4	log_level: info
```

This matches the format agents are accustomed to from Read tools, making it a drop-in replacement. Line numbers help agents reference specific lines in conversation.

**Detection**: Loads all secret values from vault, scans file content for exact matches (Aho-Corasick), replaces with placeholders. Longer matches win.

**Unvaulted secrets**: If a high-entropy string is found that doesn't match any vault key, it is replaced with a warning placeholder:

```bash
$ agent-vault read .env
     1	DATABASE_URL=<agent-vault:database-url>
     2	REDIS_URL=redis://localhost:6379
     3	NEW_API_KEY=<agent-vault:UNVAULTED:sha256:a8f3c9d1>
```

The agent sees `UNVAULTED` and knows to tell the user to vault it (see Flow 3). The sha256 prefix is a fingerprint so the agent can refer to it without seeing the actual value.

### `agent-vault write <file>`

Writes content to a file, replacing `<agent-vault:key>` placeholders with real values.

```bash
# --content flag: agent passes file content as argument
$ agent-vault write config.yaml --content 'bot_token: <agent-vault:telegram-bot-token>
api_key: <agent-vault:openai-key>
port: 8080'
✓ Written config.yaml (2 secrets restored)

# stdin: for longer content or heredoc usage
$ agent-vault write config.yaml <<'EOF'
bot_token: <agent-vault:telegram-bot-token>
api_key: <agent-vault:openai-key>
port: 8080
EOF
✓ Written config.yaml (2 secrets restored)
```

**Missing key error** (agent-parseable):

```bash
$ agent-vault write config.yaml --content 'key: <agent-vault:nonexistent>'
✗ Error: Secret "nonexistent" not found in vault
  To add it, the user should run: agent-vault set nonexistent
```

Exit code 1. The error message is designed so the agent can extract the missing key name and relay instructions to the user.

### `agent-vault has <key> [keys...]`

Check if one or more keys exist in the vault. Non-interactive, pure query.

```bash
$ agent-vault has telegram-bot-token
true                            # exit code 0

$ agent-vault has nonexistent
false                           # exit code 1

$ agent-vault has stripe-key openai-key twilio-sid --json
{
  "stripe-key": false,
  "openai-key": true,
  "twilio-sid": false
}                               # exit code 1 (not all present)
```

### `agent-vault list`

List all stored key names. Never shows values.

```bash
$ agent-vault list
telegram-bot-token
openai-key
db-password

$ agent-vault list --json
{
  "keys": [
    {"key": "telegram-bot-token", "desc": "Telegram bot token from @BotFather"},
    {"key": "openai-key", "desc": "OpenAI API key"},
    {"key": "db-password", "desc": null}
  ]
}
```

---

## Sensitive Commands (human only)

These commands touch secret values (input or output) or are destructive. They require an interactive TTY — without one they refuse to run. The agent NEVER executes them. It tells the user to run them via text output.

### `agent-vault set <key>`

Interactively store a secret value. If the key already exists, prompts for confirmation before overwriting.

```bash
$ agent-vault set telegram-bot-token
Enter value for "telegram-bot-token": ••••••••••••••••
✓ Saved "telegram-bot-token"

# With description (for future reference)
$ agent-vault set telegram-bot-token --desc "Bot token from @BotFather"
⚠ "telegram-bot-token" already exists (46 chars, set 2025-01-15T14:30:00.000Z)
Overwrite? [y/N] y
Enter value for "telegram-bot-token": ••••••••••••••••
✓ Saved "telegram-bot-token"

# Non-interactive variants for power users
$ agent-vault set openai-key --from-env OPENAI_API_KEY
✓ Saved "openai-key" (from $OPENAI_API_KEY)

$ pbpaste | agent-vault set ssh-key --stdin
✓ Saved "ssh-key"
```

### `agent-vault rm <key>`

Remove a secret. Requires confirmation.

```bash
$ agent-vault rm telegram-bot-token
Remove "telegram-bot-token"? [y/N] y
✓ Removed "telegram-bot-token"
```

### `agent-vault import <file>`

Bulk import from a .env file. Interactive — shows preview, asks for confirmation.

```bash
$ agent-vault import .env
Found 5 entries:
  TELEGRAM_BOT_TOKEN → telegram-bot-token
  OPENAI_API_KEY     → openai-key
  DB_PASSWORD        → db-password
  DB_HOST            → (skip: "localhost" — too common)
  PORT               → (skip: "3000" — too short)
Import 3 secrets? [Y/n] y
✓ Imported 3 secrets
```

### `agent-vault init`

Initialize the vault at `~/.agent-vault/`.

```bash
$ agent-vault init
✓ Initialized vault at ~/.agent-vault/
```

Auto-triggered on first `set` if no vault exists.

### `agent-vault scan <file>`

Audit a file for secrets — both vaulted and potentially unvaulted.

```bash
$ agent-vault scan config.yaml
Vaulted (2):
  line 1: bot_token → telegram-bot-token
  line 2: api_key → openai-key
Unvaulted suspects (1):
  line 5: db_conn contains high-entropy string (40 chars)
  → Run: agent-vault set db-conn
```

### `agent-vault get <key> --reveal`

Show a secret's actual value. **The most sensitive command in agent-vault.**

Double safety gate:

1. `--reveal` flag must be explicit (no default "show" behavior)
2. TTY check — refuses to run if stdout is not an interactive terminal

```bash
$ agent-vault get telegram-bot-token --reveal
7821345:AAF_xxxxxxxxxxxxxxxxxxxxx

# Without --reveal: shows metadata only
$ agent-vault get telegram-bot-token
Key:     telegram-bot-token
Desc:    Bot token from @BotFather
Set at:  2025-01-15 14:30:00
Length:  46 chars

# Piped or non-TTY: refuses
$ agent-vault get telegram-bot-token --reveal | cat
✗ Error: --reveal requires an interactive terminal (TTY)
```

---

## How the Agent Guides the User

The agent knows about sensitive commands but never executes them. Instead, it communicates via natural language. The SKILL.md teaches this pattern:

### Pattern: Missing Secret

```
Agent detects: agent-vault has stripe-key → false

Agent outputs to user (as text, not as a command):
┌─────────────────────────────────────────────────────────┐
│ I need your Stripe secret key to create the config.     │
│ Please run this in your terminal:                       │
│                                                         │
│   agent-vault set stripe-key                            │
│                                                         │
│ You can find your key at:                               │
│ https://dashboard.stripe.com/apikeys                    │
│                                                         │
│ Let me know when you've added it and I'll continue.     │
└─────────────────────────────────────────────────────────┘
```

### Pattern: Bulk Setup

```
Agent outputs:
┌─────────────────────────────────────────────────────────┐
│ This project needs several API keys. If you already     │
│ have a .env file, the fastest way is:                   │
│                                                         │
│   agent-vault import .env                               │
│                                                         │
│ Otherwise, add them one by one:                         │
│                                                         │
│   agent-vault set telegram-bot-token                    │
│   agent-vault set openai-key                            │
│   agent-vault set db-password                           │
│                                                         │
│ Let me know when you're done.                           │
└─────────────────────────────────────────────────────────┘
```

### Pattern: Unvaulted Secret Detected on Read

```
Agent runs: agent-vault read config.yaml
Agent sees: NEW_KEY=<agent-vault:UNVAULTED:sha256-prefix:a8f3c9d1>

Agent outputs:
┌─────────────────────────────────────────────────────────┐
│ I found an unvaulted secret in config.yaml (line 3).    │
│ Please vault it so I can work with this file safely:    │
│                                                         │
│   agent-vault set new-key                               │
│                                                         │
│ (The import command can also pick it up automatically   │
│  if the file is in .env format.)                        │
└─────────────────────────────────────────────────────────┘
```

---

## UX Flows

### Flow 1: Agent Sets Up a New Service (Happy Path)

```
User:   "Help me set up a Telegram bot"

Agent:  Let me check if you have the bot token stored.

        [executes] agent-vault has telegram-bot-token
        → false

Agent:  I need your Telegram bot token to create the config. Please run
        this in your terminal:

            agent-vault set telegram-bot-token

        You can get the token from @BotFather on Telegram.
        Let me know when you've added it.

User:   (runs command in their terminal, enters token)
User:   "Done"

Agent:  [executes] agent-vault has telegram-bot-token
        → true

        [executes] agent-vault write config.yaml --content 'bot:
          token: <agent-vault:telegram-bot-token>
          webhook_port: 8443
          webhook_url: https://example.com/webhook'
        → ✓ Written config.yaml (1 secret restored)

Agent:  Config created. Your bot token is stored securely in the vault
        and I never saw its value.
```

### Flow 2: Agent Reads and Modifies Existing Config

```
User:   "Change the port in my config.yaml to 9090"

Agent:  [executes] agent-vault read config.yaml
        →      1	bot_token: <agent-vault:telegram-bot-token>
        →      2	api_key: <agent-vault:openai-key>
        →      3	port: 3000

Agent:  [executes] agent-vault write config.yaml --content 'bot_token: <agent-vault:telegram-bot-token>
        api_key: <agent-vault:openai-key>
        port: 9090'
        → ✓ Written config.yaml (2 secrets restored)

Agent:  Done — port changed to 9090. Secrets preserved.
```

### Flow 3: Agent Encounters Unvaulted Secret in File

```
User:   "Read my .env and help me set up the docker-compose"

Agent:  [executes] agent-vault read .env
        → DATABASE_URL=<agent-vault:database-url>
        → REDIS_URL=redis://localhost:6379
        → NEW_API_KEY=<agent-vault:UNVAULTED:sha256:a8f3c9d1>

Agent:  I can read most of your .env safely, but there's an unvaulted
        secret on line 3 (NEW_API_KEY). Please vault it first:

            agent-vault set new-api-key

        Or if you'd like to vault everything at once:

            agent-vault import .env

User:   (runs import)
User:   "Done"

Agent:  [executes] agent-vault read .env
        → DATABASE_URL=<agent-vault:database-url>
        → REDIS_URL=redis://localhost:6379
        → NEW_API_KEY=<agent-vault:new-api-key>

Agent:  Great, now I can see all placeholders. Let me create the
        docker-compose.yaml...
```

### Flow 4: Write Fails Due to Missing Key

```
Agent:  [executes] agent-vault write config.yaml --content '...<agent-vault:stripe-key>...'
        → ✗ Error: Secret "stripe-key" not found in vault

Agent:  I need your Stripe API key to complete this config. Please run:

            agent-vault set stripe-key

        You can find your key at https://dashboard.stripe.com/apikeys

User:   "Done"

Agent:  [executes] agent-vault write config.yaml --content '...<agent-vault:stripe-key>...'
        → ✓ Written config.yaml (1 secret restored)
```

---

## Agent Integration: Skill

### Installation

```bash
npx skills add agent-vault
```

### SKILL.md

```markdown
---
name: agent-vault
description: Secure secret management — read/write config files without exposing secrets to the agent.
---

# agent-vault

Manage secrets in config files without ever seeing the actual values.

## Safe commands (you execute these)

Command | Purpose
--- | ---
`agent-vault read <file>` | Read file, secrets replaced with `<agent-vault:key>`
`agent-vault write <file> --content '...'` | Write file, `<agent-vault:key>` restored to real values
`agent-vault has <key> [keys...]` | Check if keys exist (exit 0 = yes, 1 = no)
`agent-vault list` | List all stored key names

## Sensitive commands (NEVER execute — tell the user to run these)

Command | When to suggest
--- | ---
`agent-vault set <key>` | A needed secret is missing
`agent-vault import <file>` | User has an existing .env to onboard
`agent-vault rm <key>` | User wants to remove a secret
`agent-vault get <key> --reveal` | User wants to verify a stored value

These commands require a TTY and will fail if you try to execute them.

## Rules

1. **NEVER use Read/Write/Edit tools on files that contain secrets.** Use `agent-vault read` and `agent-vault write` instead.
2. **NEVER execute sensitive commands** (`set`, `get`, `rm`, `import`). They require a TTY. Tell the user to run them in their own terminal.
3. **Always check before asking.** Run `agent-vault has <key>` first to avoid asking users to set keys they've already stored.
4. **Use `<agent-vault:key-name>` placeholders** in all file content you write.
5. **Guide the user.** When a secret is missing, tell them the exact command to run and where to find the value.

## Workflow

1. `agent-vault has <key>` — check what's available
2. If missing → tell user: "Please run: `agent-vault set <key>`"
3. Wait for user confirmation
4. `agent-vault read <file>` — read existing config
5. `agent-vault write <file> --content '...'` — write updated config

## Placeholder Format

`<agent-vault:key-name>` where key-name is lowercase alphanumeric with hyphens.

Examples: `<agent-vault:telegram-bot-token>`, `<agent-vault:openai-key>`, `<agent-vault:db-password>`

## Example

```bash
# Check what exists
agent-vault has api-key db-password --json
# → {"api-key": true, "db-password": false}

# Tell user (as text output, DO NOT execute):
# "Please run: agent-vault set db-password"

# After user confirms, write the config
agent-vault write config.yaml --content 'api_key: <agent-vault:api-key>
db_password: <agent-vault:db-password>
host: 0.0.0.0
port: 8080'
```
```

---

## Placeholder Format

**Format**: `<agent-vault:key-name>`

- Key names: lowercase alphanumeric + hyphens, e.g. `telegram-bot-token`
- Regex: `<agent-vault:([a-z0-9](?:[a-z0-9-]*[a-z0-9])?)>`
- Unvaulted marker: `<agent-vault:UNVAULTED:sha256:XXXXXXXX>` (8-char prefix of sha256)

**Why `<agent-vault:...>`?**

- `${}` conflicts with shell variable expansion and template literals
- `{{}}` conflicts with Mustache/Handlebars/Jinja templates
- `<agent-vault:...>` is distinctive, never interpreted by templating systems, and follows the XML-like tag conventions that LLMs handle naturally

---

## Vault Storage

### Location

All secrets are stored in a single global vault: `~/.agent-vault/`

No per-project vaults. This is intentional:

- Secrets like API keys are typically shared across projects
- A single location is simpler to reason about and back up
- Avoids the risk of project-level vault directories being committed
- Agents working on any project can access the same keys

### Directory Structure

```
~/.agent-vault/
├── vault.json      # AES-256-GCM encrypted secrets
└── vault.key       # Master encryption key (0600 permissions)
```

### Encryption

- Master key: 256-bit random, stored in `vault.key` with 0600 permissions
- Vault directory: 0700 permissions
- Vault file: AES-256-GCM, each value encrypted individually with unique IV
- Per-value encryption: no single decryption reveals all secrets
- Future: master key in system keychain (macOS Keychain / Linux libsecret)

---

## Technology Choices

- **Language**: TypeScript (Node.js) — npm ecosystem, easy distribution
- **CLI framework**: `commander`
- **Encryption**: Node.js `crypto` (AES-256-GCM)
- **String matching**: Aho-Corasick for multi-pattern replacement on read
- **Distribution**: npm (`agent-vault` bin), Homebrew

---

## Security Model

Security is the entire point of agent-vault. The threat model is: **the agent's execution environment (including LLM provider servers, proxies, relay services) must never see secret values.** Every design decision flows from this.

### Defense in Depth

**Layer 1: Command safety classification**

- Safe commands (`read`, `write`, `has`, `list`) structurally cannot output secret values. This is not a policy — it's how the code works.
- Sensitive commands (`set`, `get --reveal`, `rm`, `import`) require an interactive TTY. No TTY → command exits immediately with error. This prevents agents from calling them even accidentally or through prompt injection.
- `get` without `--reveal` only shows metadata (key name, description, length, timestamp) — never the value. It is still classified sensitive to be safe.

**Layer 2: Redaction on read**

- `read` replaces ALL known vault values in file content before outputting.
- Additionally, high-entropy strings that don't match any vault key are also redacted with `<agent-vault:UNVAULTED:sha256:XXXXXXXX>`. This catches secrets that were added to files outside of agent-vault (manually edited, generated by other tools, etc.).
- Entropy detection uses Shannon entropy + pattern matching for known secret formats: `sk-`, `sk_live_`, `ghp_`, `gho_`, `xoxb-`, `xoxp-`, bearer tokens, JWT patterns, private key blocks (`-----BEGIN`), long hex/base64 strings, etc.

**Layer 3: No backdoors**

- There is no `agent-vault cat` or `agent-vault dump` or any command that outputs raw secret values without `--reveal` + TTY check.
- `write` only takes placeholders as input and outputs a success/failure message. Even if an agent tries to `write` and then `read` the file back, it gets placeholders again.
- Error messages never include secret values, only key names.

**Layer 4: Storage security**

- Vault lives in `~/.agent-vault/` — outside any project tree, never at risk of being committed to version control.
- Vault encrypted at rest (AES-256-GCM).
- File permissions: directory 0700, files 0600 (owner only).
- Each secret value encrypted individually — no single decryption reveals all.

**Layer 5: Operational safeguards**

- `set` warns on overwrite: interactive mode asks for confirmation, non-interactive modes (`--from-env`, `--stdin`) print a warning to stderr.
- `import` skips short/common values (configurable min length, default 8 chars) to prevent false-positive redaction on `read`.
- `read` runs entropy detection even for strings that aren't in the vault, erring on the side of over-redaction (safe) vs under-redaction (leak).
- Placeholder format `<agent-vault:...>` is designed to be visually obvious — if a secret somehow leaked into agent output, it would be immediately noticeable by its absence of the placeholder wrapper.

---

## Future Enhancements

- **MCP Server mode**: Expose `vault_read`, `vault_write`, `vault_has`, `vault_list` as MCP tools for tighter integration
- **Protected paths config**: List of file patterns that must go through agent-vault, with pre-commit hook enforcement
- **Secret rotation**: `agent-vault rotate <key>` — update value and rewrite all referencing files
- **Team vaults**: Shared encrypted vault via age/SOPS, synced through git
