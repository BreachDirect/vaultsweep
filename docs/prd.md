# Product Requirements Document (PRD): VaultSweep

**Version:** 1.0  
**Last updated:** 2026-06-29  
**Wave program:** [Stellar Wave 7](https://www.drips.network/wave/stellar)

---

## 1. Overview

| Field | Value |
|---|---|
| **Project** | VaultSweep |
| **Tagline** | Stellar-aware secrets scanner for repos and CI |
| **Repository** | [BreachDirect/vaultsweep](https://github.com/BreachDirect/vaultsweep) |
| **Category** | Security tooling · Secret detection · Supply chain |
| **Sibling projects** | [ShieldScan](https://github.com/BreachDirect/shieldscan) (web DAST) · [RytScan](https://github.com/BreachDirect/RytScan) (Soroban static analysis) |

## 2. Problem Statement

Stellar Wave contributors routinely ship Rust, TypeScript, and config files that accidentally contain secret keys, mnemonics, and API tokens. Wave issue [#29 (secure key storage)](https://www.drips.network/wave/stellar/issues/58fe0db0-83e4-41eb-9456-a99e2d53355a) appears across the catalog — plaintext secrets in `config.toml`, leaked `S...` keys, RPC URLs with embedded credentials.

Generic tools (Gitleaks, TruffleHog) miss Stellar-specific patterns. Wave repos need a **fast, zero-config scanner** with CI exit codes that contributors can run before opening a PR.

## 3. Drips Wave Alignment

| Wave issue pattern | VaultSweep response |
|---|---|
| [#29 Secure key storage](https://www.drips.network/wave/stellar/issues/58fe0db0-83e4-41eb-9456-a99e2d53355a) | Detects plaintext Stellar keys, mnemonics, default creds |
| `make security-ci` pattern | `vaultsweep scan --fail-on high` in CI pipelines |
| Backend secret hygiene | API keys (GitHub, Anthropic, AWS), RPC embedded auth |
| Contributor onboarding | Fixture repos + `vaultsweep rules` catalog |

**Wave 7 goal:** Ship Phase 1 CLI so maintainers can gate PRs on secret leaks from day one.

## 4. Solution

VaultSweep provides:

1. **`vaultsweep scan <path>`** — walk repo files and run secret detection rules
2. **Rule catalog** — Stellar keys, mnemonics, API tokens, default creds, RPC URLs
3. **Fixture repos** — leaky + clean samples for regression tests
4. **CI-ready output** — text + JSON, `--fail-on high` exit code

## 5. Target Users

- Wave contributors before submitting PRs
- Repo maintainers adding `security-ci` gates
- Soroban/Horizon developers storing keys in env vars

## 6. Phased Delivery

### Phase 1: Core CLI & Rule Engine ✅

| Deliverable | Status |
|---|---|
| `vaultsweep scan` command | ✅ |
| `vaultsweep rules` catalog | ✅ |
| 8+ detection rules | ✅ |
| Leaky + clean fixture repos | ✅ |
| JSON + text report formats | ✅ |
| `--fail-on` CI exit codes | ✅ |
| PRD + architecture documentation | ✅ |
| `make ci` + GitHub Actions | ✅ |

**Success criteria:**

- [x] `make ci` passes
- [x] Scanning `fixtures/leaky-repo` produces ≥ 4 findings
- [x] Scanning `fixtures/clean-repo` produces 0 high/critical findings
- [x] `vaultsweep rules` lists all rule IDs
- [x] Documented Wave 7 alignment

### Phase 2: Pre-commit & GitHub Action

- `vaultsweep pre-commit` hook installer
- GitHub Action: `BreachDirect/vaultsweep-action`
- Baseline file (`.vaultsweep-baseline`) for incremental adoption
- Allowlist comments (`vaultsweep:ignore`)

### Phase 3: Entropy & Advanced Detection

- High-entropy string analysis for unknown secret formats
- Stellar federation address + muxed account patterns
- `.wasm` metadata string extraction
- Reduced false-positive tuning with ML-free heuristics

### Phase 4: Monorepo & History Scan

- `git log` / staged-diff scanning (`vaultsweep scan --staged`)
- Multi-language support: Solidity, Go, Java properties
- Unified report merging for Rust + TS monorepos

### Phase 5: Dashboard & Team Platform

- Web UI for scan history across org repos
- BreachDirect org-wide policy profiles
- Slack/Discord webhook alerts on CI failure

### Phase 6: Wave Integrator & Ecosystem

- Unified `breach scan secrets|web|contract` CLI
- Drips Wave issue matcher (flag repos with open #29-class issues)
- Integration with ShieldScan (no secret leaks before DAST scan)

## 7. Non-Goals (Phase 1)

- Git history rewriting
- Cloud secret manager integration
- Real-time GitHub org monitoring SaaS

## 8. Ethics

VaultSweep detects **patterns only** — fixture secrets are synthetic test vectors. Never commit real keys. Rotate any credential found in a live scan immediately.

---

**Author:** Michael Victory Osisienimo  
**Organisation:** [BreachDirect](https://github.com/BreachDirect)
