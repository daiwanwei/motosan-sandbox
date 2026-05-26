# Financial sandbox example — Design

**Status:** approved design, pre-implementation.
**Date:** 2026-05-26.

## Problem

`motosan-sandbox` now has every control needed to run untrusted financial
strategy code: network allowlist (`Proxied`), write confinement
(`WorkspaceWrite`), and secret read-hiding (`deny_read`). But there is no
end-to-end, runnable demonstration showing a consumer how to wire them together.
The original ask was "teach me how to use this to build a financial sandbox" —
this example is that teaching artifact.

## Goal

A single `cargo run --example financial_sandbox` that:
1. Demonstrates the **two-phase** pattern — a permissive *provision* policy, then
   a tight *run* policy — so the reader sees the policy change between installing
   tools and running untrusted code.
2. Exercises the full **enforcement matrix** (write-confine, deny-read,
   network-block, network-allow) with a real untrusted Python strategy.
3. Stays **reliably runnable offline / in CI** — deterministic controls are
   load-bearing; internet-dependent steps are best-effort and never fail the run.

## Non-goals

- No real trading, no API keys, no live order placement.
- No third-party Python packages required to run (stdlib-only strategy); the
  `pip install` path is shown best-effort, not required.
- No changes to the `motosan-sandbox` library itself — example + docs + one
  smoke test only.

## Decisions (from brainstorming)

- **(A) In-repo cargo example** — `crates/motosan-sandbox/examples/`. CI compiles
  examples, so it can't rot against API changes (e.g. the recent `ReadOnly`
  restructure). A reader copies it into their own external project; the README
  documents the external `Cargo.toml` git-dependency stanza.
- **(2) Mostly-offline / best-effort network** — the allowlist *block* path is
  deterministic (the proxy refuses the `CONNECT` before any real network); the
  *allow* path needs the internet, so it is best-effort (printed, non-fatal).
- **Python strategy** — matches the financial/numpy context; the example detects
  `python3` and skips gracefully (exit 0) if absent.

## Files

- `crates/motosan-sandbox/examples/financial_sandbox.rs` — Rust harness. Requires
  the `proxy` feature (`cargo run --example financial_sandbox --features proxy`).
- `crates/motosan-sandbox/examples/strategy.py` — the untrusted strategy
  (stdlib only). Pulled into the harness via `include_str!` and written into the
  sandbox workspace at runtime, so it ships as a real, readable file.
- `.github/workflows/ci.yml` — add a step that runs the example as a smoke test
  (idiomatic way to keep an example honest; no nested-cargo `tests/` file).
- `crates/motosan-sandbox/README.md` — "Financial sandbox example" section +
  external git-dependency stanza + the two-phase provisioning note + a one-line
  caveat that on **bwrap-less Linux the example self-skips**, because both
  features it showcases (`Proxied` and `deny_read`) are bwrap-only on Linux
  (`deny_read` is `Unsupported` on the Landlock path by design). Fully runnable
  on macOS and bwrap-equipped Linux (incl. CI-ubuntu).

## Architecture / flow

The harness (`financial_sandbox.rs`):

1. `motosan_sandbox::helper::run_if_invoked()` as the first line of `main`
   (Linux self-reexec hook; no-op on macOS).
2. Build a temp workspace (`tempfile`), canonicalize it. Plant:
   - `input.csv` — a normal readable input.
   - `.env` — a fake secret (`BINANCE_SECRET=do-not-read`).
   - `.venv/` will be created in Phase A.
3. Write `strategy.py` (from `include_str!`) into the workspace.
4. **Phase A — provision** (`WorkspaceWrite::new([ws]).network(Proxied{["pypi.org",
   "files.pythonhosted.org"]})`; env carries `PATH`, `HOME=ws`,
   `PIP_CACHE_DIR=ws/.cache/pip`, `TMPDIR=ws/tmp`): the harness first
   `create_dir_all`s `ws/tmp` and `ws/.cache/pip` (the redirected dirs must
   exist or pip can't write). Then run `python3 -m venv .venv` (deterministic —
   venv needs no network). Then a best-effort
   `.venv/bin/pip install --no-input --quiet packaging` step whose failure
   (offline / no bwrap) is printed, not fatal. Print the venv-create exit code.
   The PyPI allowlist here is deliberately *different* from Phase B's exchange
   allowlist — that contrast (install tools vs run untrusted code) is the lesson.
5. **Phase B — run** (`WorkspaceWrite::new([ws]).network(Proxied{["api.binance.com"]})
   .deny_read("<ws>/.env")`; curated env = `PATH` only; `RunOpts{ timeout: 30s,
   max_output_bytes: 1 MiB }`): run the strategy with `.venv/bin/python strategy.py`
   if the venv exists, else system `python3`. Print exit code + captured stdout.
6. **Propagate the Phase B strategy's exit code** as the harness's own exit code
   (0 = all deterministic controls held; non-zero = a control leaked open). This
   is what makes the CI smoke step a real regression guard. Harness-level skips
   (`python3`/`bwrap` absent) and best-effort failures still exit 0.

The strategy (`strategy.py`, stdlib only) runs each check, prints
`PASS <name>` / `FAIL <name> <detail>`, and `sys.exit(1)` if any **deterministic**
control failed open:

| # | Control | Action | PASS condition |
|---|---|---|---|
| 1 | workspace write | write `result.json` in cwd | write succeeds |
| 2 | write confinement | write `/tmp/motosan_escape` | raises `PermissionError`/`OSError` |
| 3 | read normal file | read `input.csv` | read succeeds |
| 4 | secret deny-read | read `.env` | raises `PermissionError`/`OSError` |
| 5 | network allowlist **deny** | `urllib.request.urlopen("https://example.com", timeout=3)` (uses the injected proxy env) | raises — the proxy refuses the `CONNECT` to a non-allowlisted host, **locally, no internet** |
| 6 | direct-egress **wall** | `socket.create_connection(("example.com",443),2)` | raises — direct egress blocked (kernel on macOS / `ENETUNREACH` in the netns) |
| 7 | network **allow** (best-effort) | `urllib.request.urlopen("https://api.binance.com/api/v3/ping", timeout=3)` | printed only — needs internet, never affects exit |

Checks 1–6 are deterministic and offline; failing any of them open → `sys.exit(1)`
(which the harness propagates so the CI smoke step goes red). Check 7 is
informational/best-effort. Check 5 exercises the host **allowlist** itself
(proxy refuses a non-allowlisted host); check 6 exercises the egress **wall**
(no proxy bypass) — both matter for a financial sandbox.

## Error handling / reliability

- `python3` not on `PATH` → harness prints `skip: python3 not found` and exits 0.
- Phase A `pip install` and strategy check 6 are best-effort: failure prints a
  note, never fails the example.
- Network **block** (check 5) does not need the internet — the allowlist proxy
  refuses the `CONNECT` locally — so it is a hard assertion.
- Linux requires `bwrap` for `Proxied`; if absent, `Sandbox::run` returns
  `Error::Unsupported`. The harness prints a clear message pointing at the README
  Phase 3 provisioning and exits 0 (so a bwrap-less box still "runs" the example
  without a confusing panic). The smoke test tolerates this skip.

## Testing

- **CI compile:** examples are built by the existing `clippy --all-targets` /
  `cargo build` steps — guards against API drift.
- **CI smoke step** (in `ci.yml`, after the test steps, both OSes): run
  `cargo run --example financial_sandbox --features proxy`. The example exits 0
  on success OR on a self-skip (`python3`/`bwrap` absent), and exits **non-zero
  only if a deterministic control leaks open** — so this step is a real
  regression guard (e.g. if `deny_read` silently stopped working, CI goes red).
  Both CI runners already have `python3`; ubuntu already provisions `bwrap`
  (Phase 3 steps), so the strategy actually runs there.

## Out of scope / follow-ups

- A real-exchange variant (swap the allowlist host + drop best-effort) — one-line
  change documented in the README.
- npm/Node strategy variant.
- Wiring the example as an `motosan-agent-loop` Tool (separate integration).
