# leakhook

> Stop secrets before they hit git history — one hook, zero deps.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Node >=18](https://img.shields.io/badge/node-%3E%3D18-brightgreen.svg)](https://nodejs.org)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-ff69b4.svg)](#contributing)

`leakhook` is a single, drop-in git **pre-commit hook** that blocks a commit when your staged changes contain secret-shaped strings or forbidden files. No husky. No `lint-staged`. No config file. No binary to install. Just Node built-ins.

---

## The problem

Everyone eventually pastes an API key into a file and runs `git commit -am "wip"` on autopilot. Once a secret lands in history, rotating it is the only real fix — and git history is forever.

The usual guards are heavier than the problem:

- **gitleaks** — a separate binary to install, version, and keep in your toolchain.
- **husky + lint-staged** — extra dependencies, a `prepare` script, and a config file per repo.

`leakhook` is the minimal version: one hook, zero runtime dependencies, sensible defaults, and an allowlist for the rare false positive.

---

## Install

Inside any git repo:

```bash
npx leakhook install
```

That writes (or safely extends) `.git/hooks/pre-commit`:

```sh
#!/bin/sh
# >>> leakhook >>>
# Managed by leakhook — https://devya.dev  (do not edit between these markers)
if [ "$LEAKHOOK_SKIP" != "1" ]; then
  npx --no-install leakhook scan --staged || exit 1
fi
# <<< leakhook <<<
```

- If **no hook exists**, it creates one and `chmod +x`s it.
- If a hook **already exists**, leakhook backs it up to `pre-commit.leakhook-backup` and appends its guarded, marker-delimited block.
- Re-running `install` is **idempotent** — it updates the block in place, never duplicates it.

Remove it anytime:

```bash
npx leakhook uninstall   # strips the block; restores your backup if there was one
```

---

## Usage

You don't run anything by hand — the hook fires on `git commit`. Under the hood it runs:

```bash
leakhook scan --staged   # default: forbidden filenames + secret patterns in added lines
leakhook scan --all      # scan every tracked file's contents
```

When a bad commit is caught, it looks like this:

```text
✖ leakhook: potential secrets detected

  src/config.js:14   aws-access-key-id        AKIA••••••••MPLE
  src/config.js:15   generic-secret-assignment  toke••••••••ken"
  .env:1             dotenv-file              .env

3 findings. Remove the secret, add an allowlist entry, or use a leakhook-allow comment.
To bypass this one commit: LEAKHOOK_SKIP=1 git commit ...
```

Matches are **redacted** — the middle is masked (`ghp_••••••••`, `AKIA…EXAMPLE`) so the hook output never re-leaks the secret into your terminal scrollback or CI logs.

---

## Rules

| Rule ID | Catches |
| --- | --- |
| `dotenv-file` | `.env` / `.env.*` (except `.env.example`, `.env.sample`, `.env.template`) |
| `pem-file` | `*.pem` files |
| `key-file` | `*.key` files |
| `ssh-private-key` | `id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519` |
| `service-account-json` | `*service-account*.json`, `*credentials*.json` |
| `aws-access-key-id` | AWS access key ids (`AKIA…`) |
| `aws-secret-access-key` | Contextual `aws_secret_access_key = …` |
| `github-token` | GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`) |
| `gitlab-token` | GitLab PATs (`glpat-…`) |
| `stripe-secret-key` | Stripe live secret keys (`sk_live_…`) |
| `slack-token` | Slack tokens (`xoxb-`, `xoxa-`, `xoxp-`, `xoxr-`, `xoxs-`) |
| `google-api-key` | Google API keys (`AIza…`) |
| `private-key-block` | PEM private key headers (`-----BEGIN … PRIVATE KEY-----`) |
| `jwt` | JSON Web Tokens (`eyJ….eyJ….…`) |
| `mongodb-uri-creds` | MongoDB URIs with embedded credentials |
| `generic-secret-assignment` | `password`/`secret`/`api_key`/`token`/`access_key = "…"` (12+ chars) |

Rules live in a plain array in [`src/index.js`](./src/index.js) — each is `{ id, description, regex }`, so adding your own is a two-line change.

---

## Allowlisting

Sometimes a match is a known-fake fixture, an example value, or a vendored file. Three escape hatches, smallest scope first:

**Inline — skip a single line.** Add a `leakhook-allow` comment on the line:

```js
const demoKey = "AKIA…EXAMPLE"; // leakhook-allow example key from docs
```

**Repo — `.leakhookignore`.** One entry per line, `#` for comments. Globs match paths; prefix with `regex:` for a pattern:

```gitignore
# ignore a whole folder of fixtures
test/fixtures/**

# ignore a path pattern
regex:^docs/.*\.md$
```

**One commit — `LEAKHOOK_SKIP=1`.** Bypass the scan for a single commit (prints a warning):

```bash
LEAKHOOK_SKIP=1 git commit -m "vendored sample with fake keys"
```

---

## Why not gitleaks / husky?

- **No binary to install.** gitleaks is a compiled tool you have to distribute and version. `leakhook` ships as one npm package that runs on the Node you already have.
- **No husky.** No `prepare` script, no `.husky/` directory, no extra dev dependencies wiring hooks together.
- **No config file required.** Sensible defaults out of the box; `.leakhookignore` only when you actually need it.
- **Single file, zero runtime deps.** The whole detector is a few hundred lines of plain ESM using only Node built-ins — easy to read, audit, and extend.

`leakhook` is intentionally small. If you need org-wide policy, historical scanning, and SARIF reports, reach for gitleaks. If you just want to stop the next accidental key from landing in history, this is it.

---

## Contributing

PRs welcome. To add a rule, append `{ id, description, regex }` to the `rules` array in `src/index.js` and add a matching test case in `test/leakhook.test.js`.

```bash
node --test        # run the suite
node bin/cli.js --help
```

**Never commit a real (or realistic) secret**, even in tests. Construct secret-shaped samples by string concatenation of obviously-fake values (`'AKIA' + 'IOSFODNN7' + 'EXAMPLE'`) so no scannable literal is ever written to disk.

---

## License

MIT © 2026 Ahmed Mahmoud (Devya) — see [LICENSE](./LICENSE).

---

Built by [Devya](https://devya.dev) — we take security seriously. · contact@devya.dev
