# sshhole — defensive auditor for CVE-2026-123158

A read-only-by-default auditor for the OpenSSH/musl password authentication bypass on Alpine Linux. It can inspect a host's local OpenSSH configuration and Alpine package state, check remote SSH availability without authenticating, or perform **explicitly opted-in** active validation against systems you administer.

The tool never runs a command, opens a shell, or takes a session on a target, in any mode.

## Requirements

- Python 3.9 or later; standard library only for `--local` and passive checks.
- Optional for active checks only: `python -m pip install paramiko`.
- On a local Alpine installation, run with sufficient privileges to read `/etc/shadow` and inspect the running daemon's `/proc/PID/exe` information.
- For `--active`, the target's SSH host key **must already be trusted** in your known-hosts file. Validate the host-key fingerprint through an independent trusted channel before adding it. Hashed entries (`HashKnownHosts`) are supported. If the file contains markers Paramiko cannot parse (`@cert-authority`, `@revoked`), every target is reported `inconclusive` rather than being tested against a partially trusted store.

## Examples

```sh
# Inspect only this machine (no network activity)
python sshhole.py --local
python sshhole.py --local --json

# Passively check if an SSH service responds; the banner alone is inconclusive
python sshhole.py --target 192.0.2.10

# Authorized, limited active confirmation against an already trusted SSH host
python sshhole.py --target 192.0.2.10 --active \
  --known-hosts ~/.ssh/known_hosts --users your-test-account

# Audit a bounded list of known, in-scope assets (one host[:port] per line)
python sshhole.py --list owned-hosts.txt --active \
  --known-hosts ~/.ssh/known_hosts --workers 2 --json -o results.jsonl

# Run offline regression tests
python -m unittest -v test_sshole.py
```

Active checks send failed authentication attempts and may result in a successful authentication on a vulnerable target. They can trigger account alerts, log entries, rate limiting, SSH connection penalties, and monitoring rules. No shell, session command, or post-auth command is executed. The test requires two attempts on the same SSH connection and then performs a second independent connection with distinct short control passwords. The tool limits active runs to 32 hosts, 8 usernames, and 4 workers.

## Verdicts

| Verdict | Meaning |
|---|---|
| `vulnerable` | Remote boundary behavior observed and a distinct short-password control rejected twice. A password-authenticated connection was established and immediately closed. |
| `potentially-vulnerable` | Local prerequisite indicators present; **not** proof that a remote login is possible. |
| `not-detected` | Test did not observe the issue **within the checked accounts, source context, and local visibility**. It does not guarantee universal safety. |
| `inconclusive` | Incomplete or ambiguous evidence; the test did not establish safety or exposure. Passive banner checks always give this verdict. |

The local audit identifies the running daemon's own package via its resolved executable path, so a fixed `openssh-server` does not excuse an unfixed `openssh-server-pam` (Alpine ships both, with independent revisions).

Exit codes are `0` for `vulnerable` or `potentially-vulnerable`, `1` for `not-detected`, `2` for `inconclusive`, `3` for input/dependency/output errors, and `130` for Ctrl+C.

## Important limitations

- The local package table is based on Alpine's November 5, 2026 security advisory. Unknown custom builds, distributions, or newer package formats remain unknown rather than being declared safe.
- A patched Alpine package on disk is not enough: the main daemon may still be running the old executable. The local audit compares `/proc/PID/exe` with the on-disk daemon and only applies Alpine package assurances to the daemon binary that package actually ships (`openssh-server` → `/usr/sbin/sshd`, `openssh-server-pam` → `/usr/sbin/sshd.pam`).
- If no `sshd` process is visible, socket activation or a different PID namespace may still expose SSH; this is reported as inconclusive.
- `sshd -T -C` is evaluated using the supplied `--source-address` (default `127.0.0.1`); source-dependent `Match` rules, external identities, directory services, and multi-factor policies can change real access. The local audit reports a **configuration risk**, not an exploit confirmation.
- A remote test covers only the explicitly specified usernames; all other accounts remain untested.
- Authentication retries are performed on live SSH and can behave differently across implementations and versions. Both modes were exercised end-to-end against a live musl/OpenSSH-10.3 lab container: the vulnerable daemon reports `vulnerable`, the same binary under `UsePAM yes` reports `not-detected`, and `--local` correctly distinguishes fixed, unfixed, and stale-running-binary states.
- Verified against one Alpine release (3.24.1) and one Paramiko version (5.1.0). Other combinations are untested.
- Active mode is serial per target: each username is tested with its own connections, so `--workers` parallelizes hosts, not accounts within a host.

## Exit codes in automation

`0` covers both `vulnerable` and `potentially-vulnerable`, so a CI gate cannot currently distinguish a confirmed remote bypass from a local configuration risk. Treat exit `0` as "act on this" and read the JSON verdict when the distinction matters. A configurable failure threshold is not implemented.

## Operational limits

- Passive scans are uncapped but buffer results: `-f` with very large lists queues every target before the first line is printed. Keep passive lists in the hundreds, not the hundreds of thousands.
- Active scans are capped at 32 hosts, 8 usernames, and 4 workers per run by design. Split larger fleets into batches to stay within the per-target login-penalty budget.

## Reference

[Alpine Linux security advisory, November 5, 2026](https://alpinelinux.org/posts/2026-11-05-openssh-password-authentication-bypass/)

The vendor recommends updating OpenSSH and restarting `sshd`, or disabling password authentication and restarting `sshd` when upgrading is not immediately possible.
