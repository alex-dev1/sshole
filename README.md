# sshole — defensive auditor for CVE-2026-123158

A read-only-by-default auditor for the OpenSSH/musl password authentication bypass on Alpine Linux. It can inspect a host's local OpenSSH configuration and Alpine package state, check remote SSH availability without authenticating, or perform **explicitly opted-in** active validation against systems you administer.

Remote checks never open an SSH session channel, run a remote command, or open a shell. Active checks may authenticate successfully, then immediately close the connection. The local audit runs inspection commands (`sshd -V`, `sshd -T -C`, and `apk info -v`) on this machine without invoking a shell or changing configuration.

## Requirements

- Python 3.9 or later; standard library only for `--local` and passive checks.
- Paramiko is required for active checks and for the full regression test suite: `python -m pip install paramiko`. It is not needed to run local or passive checks.
- On a local Alpine installation, run with sufficient privileges to read `/etc/shadow` and inspect the running daemon's `/proc/PID/exe` information.
- For `--active`, the target's SSH host key **must already be trusted** in your known-hosts file. Validate the host-key fingerprint through an independent trusted channel before adding it. Hashed entries (`HashKnownHosts`) are supported. If the file contains markers Paramiko cannot parse (`@cert-authority`, `@revoked`), every target is reported `inconclusive` rather than being tested against a partially trusted store.

## Getting started

```sh
git clone https://github.com/alex-dev1/sshole.git
cd sshole
python sshole.py --help
```

Use a Python 3.9+ interpreter (`python3` instead of `python` if needed). For active checks or the full test suite, install Paramiko in your Python environment first, preferably in a virtual environment.

## Examples

```sh
# Inspect only this machine (no network activity; see local privilege requirements)
python sshole.py --local
python sshole.py --local --json

# Passively check if an SSH service responds; the banner alone is inconclusive
python sshole.py --target 192.0.2.10

# Authorized, limited active confirmation against an already trusted SSH host
python sshole.py --target 192.0.2.10 --active \
  --known-hosts ~/.ssh/known_hosts --users your-test-account

# Audit a bounded list of known, in-scope assets (one host[:port] per line)
python sshole.py --list owned-hosts.txt --active \
  --known-hosts ~/.ssh/known_hosts --users your-test-account \
  --workers 2 --json -o results.jsonl

# Run offline regression tests (requires Paramiko; no live targets are contacted)
python -m unittest -v test_sshole.py
```

Active checks send password authentication attempts and may authenticate successfully. They can trigger account alerts, log entries, lockouts, rate limiting, SSH connection penalties, and monitoring rules. No shell, session channel, or remote command is opened. For each username, the test sends a boundary password and, only if it is rejected, a second boundary password on the same connection. Only a rejection followed by acceptance triggers a second independent connection with distinct short control passwords. A confirmed verdict requires both control attempts to be rejected. The tool stops checking further usernames on a host after confirmation.

### Inputs and output

- Remote mode is passive unless `--active` is supplied. `--local` cannot be combined with remote targets or `--active`.
- Active mode defaults to the usernames `root,alpine`. Set `--users` to a comma-separated list of the authorized accounts you intend to check. Local mode inspects all local literal-`*` shadow accounts; `--users` does not restrict that audit.
- Targets may be hostnames, IPv4 addresses, bare IPv6 addresses, `host:port`, or `[IPv6]:port`. `--port` defaults to `22` and applies to entries without an explicit port. Target lists accept blank lines and `#` comments; duplicate targets are removed. `--target` and `--list` may be combined.
- `--workers` defaults to `2`. `--timeout` defaults to `8` seconds (allowed range: `0.1`–`120`); it is a connection/authentication timeout, not a deadline for an entire host or run.
- `--known-hosts` defaults to `~/.ssh/known_hosts`. Trust entries must match the supplied hostname or address; non-default ports use `[host]:port` entries.
- `--json` writes one JSON object per result to stdout (JSON Lines, not a JSON array). `-o`/`--output` **appends** full JSONL results to a file regardless of stdout format; existing results are not overwritten. Remote results are buffered until all targets finish, rather than streamed as each check completes.

## Verdicts

| Verdict | Meaning |
|---|---|
| `vulnerable` | Remote boundary behavior observed and a distinct short-password control rejected twice. A password-authenticated connection was established and immediately closed. |
| `potentially-vulnerable` | Local prerequisite indicators present; **not** proof that a remote login is possible. |
| `not-detected` | Test did not observe the issue **within the checked accounts, source context, and local visibility**. It does not guarantee universal safety. |
| `inconclusive` | Incomplete or ambiguous evidence; the test did not establish safety or exposure. Passive banner checks always give this verdict. |

The local audit selects an installed daemon binary and maps its resolved path to `openssh-server` or `openssh-server-pam`. It compares visible `sshd`/`sshd.pam` process executables with that binary before trusting a fixed-package result. It does not independently audit every installed or running daemon: if both builds are installed, `/usr/sbin/sshd` is preferred, and a running PAM daemon may produce an inconclusive binary mismatch.

For a completed run, exit code `0` means at least one result is `vulnerable` or `potentially-vulnerable`; otherwise `2` means at least one result is `inconclusive`, and `1` means all results are `not-detected`. Exit code `3` indicates a CLI-handled input/dependency/output error, and `130` indicates Ctrl+C. Per-target failures such as host-key verification errors are reported as `inconclusive`, not exit `3`.

## Important limitations

- The local package table is based on Alpine's November 5, 2026 security advisory. Unknown custom builds, distributions, or newer package versions/formats do not receive a fixed-package assurance; configuration checks can still report a risk or a scope-limited `not-detected` result.
- A patched Alpine package on disk is not enough: the main daemon may still be running the old executable. The local audit compares `/proc/PID/exe` with the on-disk daemon and only applies Alpine package assurances to the daemon binary that package actually ships (`openssh-server` → `/usr/sbin/sshd`, `openssh-server-pam` → `/usr/sbin/sshd.pam`).
- If no `sshd` process is visible, socket activation or a different PID namespace may still expose SSH; this is reported as inconclusive.
- `sshd -T -C` is evaluated using the supplied `--source-address` (default `127.0.0.1`); source-dependent `Match` rules, external identities, directory services, and multi-factor policies can change real access. The local audit reports a **configuration risk**, not an exploit confirmation.
- A remote test covers only the supplied usernames (or the defaults `root,alpine` if `--users` is omitted), and stops after a confirmed result. Consult `tested_users` in JSON output for the accounts actually attempted; all other accounts remain untested.
- Authentication retries occur over live SSH and can behave differently across implementations and versions. The existing lab validation is reported for Alpine 3.24.1, OpenSSH 10.3, and Paramiko 5.1.0 only; it is not a compatibility guarantee for other combinations.
- The included regression suite uses mocked local state and SSH transports. It checks verdict logic and safety guards offline, but does not reproduce the reported live-lab validation.
- Active mode is serial per target: each username is tested with its own connections, so `--workers` parallelizes hosts, not accounts within a host.

## Exit codes in automation

`0` covers both `vulnerable` and `potentially-vulnerable`, so a CI gate cannot currently distinguish a confirmed remote bypass from a local configuration risk. Treat exit `0` as "act on this" and read the JSON verdict when the distinction matters. A configurable failure threshold is not implemented.

## Operational limits

- Passive scans have no host-count cap and allow 1–16 workers, but buffer all targets and results before reporting. Very large lists can consume substantial memory; keep passive lists manageable.
- Active scans are capped at 32 hosts, 8 usernames, and 4 workers per run by design. These are per-run limits, not a per-target login-penalty budget: the tool does not track attempts across runs or enforce a cooldown. For larger fleets, use non-overlapping batches and account for server lockout and rate-limit policies before repeating checks.

## Reference

[Alpine Linux security advisory, November 5, 2026](https://alpinelinux.org/posts/2026-11-05-openssh-password-authentication-bypass/)

The vendor recommends updating OpenSSH and restarting `sshd`, or disabling password authentication and restarting `sshd` when upgrading is not immediately possible.
