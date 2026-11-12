#!/usr/bin/env python3
"""SSHole / CVE-2026-123158 defensive auditor.

Modes:
  --local         Read-only local configuration, package and process audit.
  --target/--list Passive remote SSH banner check (no authentication).
  --active        Opt-in remote password-pair test for authorized systems only.

The active test can result in an authenticated SSH session if the target is
vulnerable. Sessions are always closed; no command or shell is run. It requires
an already-trusted SSH host key. Never treat an untested account, an unreadable
configuration, or an interrupted probe as evidence of safety.

Exit codes: 0 evidence of vulnerability/risk; 1 not detected in tested scope;
            2 inconclusive; 3 CLI or output error.

Requires Python 3.9+. Paramiko is needed ONLY for --active mode.
"""
from __future__ import annotations

import argparse
import glob
import ipaddress
import json
import math
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

PROG = "sshole"
CVE = "CVE-2026-123158"
BOUNDARY = ("A" * 256, "A" * 257)
CONTROLS = ("ctl-a7f3", "ctl-b9e1")
DEFAULT_USERS = ("root", "alpine")

RISK = "potentially-vulnerable"  # local prerequisites present, not a login test
VULNERABLE = "vulnerable"         # active, with separate control passed
NOT_DETECTED = "not-detected"     # limited to tested users / local inspection
INCONCLUSIVE = "inconclusive"
EXIT = {RISK: 0, VULNERABLE: 0, NOT_DETECTED: 1, INCONCLUSIVE: 2}

# Alpine's 2026-11-05 advisory: openssh package revisions containing the fix.
FIXED_ALPINE_REVISIONS = {
    "10.6_p2": 0, "10.3_p1": 2, "10.2_p1": 1, "10.0_p1": 11,
    "9.9_p2": 1, "9.7_p1": 6, "9.6_p1": 3, "9.3_p2": 4,
    "9.1_p1": 7, "9.0_p1": 6,
}

# Alpine installs distinct daemon binaries per package. Package assurances
# apply only to the binary that package ships, so the running executable's
# resolved name selects which revision table entry is relevant.
DAEMON_BINARY_PACKAGE = {
    "sshd": "openssh-server",
    "sshd.pam": "openssh-server-pam",
}
ALPINE_SBIN = "/usr/sbin"


def daemon_package(path: Optional[str]) -> Optional[str]:
    """Return the Alpine package that ships `path`, or None if it is not packaged.

    Only Alpine's /usr/sbin daemon binaries carry package assurances. A custom
    build elsewhere (e.g. /usr/local/sbin/sshd) is never covered by apk state.
    Drive prefixes are stripped so the check is stable on non-POSIX hosts.
    """
    if not path:
        return None
    resolved = os.path.realpath(path).replace("\\", "/")
    resolved = re.sub(r"^[A-Za-z]:", "", resolved)
    normalized = os.path.normpath(resolved)
    if os.path.normpath(os.path.dirname(normalized)) != os.path.normpath(ALPINE_SBIN):
        return None
    return DAEMON_BINARY_PACKAGE.get(os.path.basename(normalized))


class CLIError(ValueError):
    """Invalid user input or unavailable required dependency."""


class SSHIdentityError(Exception):
    """Remote SSH host identity was not trusted."""


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(3, f"{self.prog}: error: {message}\n")


@dataclass(frozen=True)
class Target:
    host: str
    port: int = 22

    def display(self):
        return f"[{self.host}]:{self.port}" if ":" in self.host else f"{self.host}:{self.port}"


@dataclass
class Result:
    target: str
    mode: str
    verdict: str = INCONCLUSIVE
    detail: str = ""
    user: str = ""
    banner: str = ""
    tested_users: list[str] = field(default_factory=list)
    checks: dict[str, str] = field(default_factory=dict)
    elapsed_ms: int = 0

    def as_dict(self):
        return asdict(self)


def valid_port(value):
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise CLIError(f"invalid port {value!r}") from exc
    if not 1 <= port <= 65535:
        raise CLIError(f"port must be 1..65535, got {port}")
    return port


def parse_target(value: str, default_port: int) -> Target:
    """Accept hostname, host:port, IPv4, bare IPv6, or [IPv6]:port."""
    line = value.strip()
    if not line or any(ch.isspace() for ch in line):
        raise CLIError(f"invalid target {value!r}")
    if line.startswith("["):
        match = re.fullmatch(r"\[([^\]]+)\](?::([0-9]+))?", line)
        if not match:
            raise CLIError(f"invalid bracketed address {value!r}")
        host = match.group(1)
        port = valid_port(match.group(2)) if match.group(2) else default_port
    elif line.count(":") == 1:
        host, sep, port_s = line.partition(":")
        if not host or not port_s:
            raise CLIError(f"invalid host:port {value!r}")
        port = valid_port(port_s)
    else:
        host, port = line, default_port
    if not host or any(c in host for c in "/\\\x00"):
        raise CLIError(f"invalid hostname {host!r}")
    return Target(host, port)


def load_targets(one: Optional[str], filename: Optional[str], default_port: int):
    values = []
    if one:
        values.append(one)
    if filename:
        try:
            with open(filename, encoding="utf-8") as handle:
                for lineno, raw in enumerate(handle, 1):
                    line = raw.split("#", 1)[0].strip()
                    if line:
                        try:
                            values.append(parse_target(line, default_port))
                        except CLIError as exc:
                            raise CLIError(f"{filename}:{lineno}: {exc}") from exc
        except OSError as exc:
            raise CLIError(f"could not open target list: {exc}") from exc
    parsed = [v if isinstance(v, Target) else parse_target(v, default_port) for v in values]
    return list(dict.fromkeys(parsed))  # de-duplicate: avoid extra failed logins


def run_command(argv, timeout=6):
    """Never invoke a shell, and preserve stderr and return code."""
    try:
        proc = subprocess.run(argv, text=True, capture_output=True,
                              timeout=timeout, check=False)
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        return None, "", str(exc)


def find_sshd():
    # Alpine ships the PAM server build only as /usr/sbin/sshd.pam, so a
    # PAM-only host has no /usr/sbin/sshd at all.
    for path in ("/usr/sbin/sshd", "/usr/sbin/sshd.pam",
                 "/usr/local/sbin/sshd", "/sbin/sshd"):
        if os.path.isfile(path):
            return path
    return shutil.which("sshd")


def parse_package(line: str):
    """Return (name, base, revision) only for an exact Alpine server package."""
    match = re.fullmatch(
        r"(openssh-server(?:-pam)?)-(\d+\.\d+_p\d+)-r(\d+)", line.strip()
    )
    if match is None:
        return None
    return match.group(1), match.group(2), int(match.group(3))


def package_fix_state(pkg_line: str):
    parsed = parse_package(pkg_line)
    if not parsed:
        return "unknown"
    _name, base, revision = parsed
    minimum = FIXED_ALPINE_REVISIONS.get(base)
    if minimum is None:
        return "unknown"  # don't interpret unknown/newer branch as unfixed
    return "fixed" if revision >= minimum else "unfixed"


def read_shadow():
    """Return (star users, donor users, error). Never return shadow hashes."""
    stars, donors = [], []
    try:
        with open("/etc/shadow", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                fields = line.rstrip("\n").split(":", 2)
                if len(fields) < 2:
                    continue
                user, pw = fields[0], fields[1]
                if pw == "*":
                    stars.append(user)
                if pw.startswith(("$5$", "$6$")):
                    donors.append(user)
    except OSError as exc:
        return [], [], str(exc)
    return stars, donors, ""


def running_sshd_state(sshd: Optional[str]):
    """Return (state, detail) for the running daemon vs installed executable.

    A process whose /proc/PID/exe inode differs from the on-disk sshd is
    NOT proven patched, even when the package manager reports a fixed package.
    """
    if not Path("/proc").is_dir():
        return "unknown", "/proc unavailable"
    try:
        pids = [pid for pid in os.listdir("/proc") if pid.isdigit()]
    except OSError as exc:
        return "unknown", str(exc)
    found, unreadable = [], False
    for pid in pids:
        try:
            name = Path(f"/proc/{pid}/comm").read_text(errors="replace").strip()
            # Alpine ships the PAM build as sshd.pam, which sets comm=sshd.pam.
            if name not in DAEMON_BINARY_PACKAGE:
                continue
            exe = f"/proc/{pid}/exe"
            try:
                realpath = os.readlink(exe)
                inode = os.stat(exe)
                found.append((pid, realpath, inode))
            except OSError:
                unreadable = True
        except (OSError, UnicodeError):
            continue
    if not found:
        return ("unknown", "sshd process present but binary unreadable") if unreadable else (
            "not-running", "no sshd process visible in this PID namespace")
    if not sshd:
        return "unknown", "sshd runs, but no installed binary path was found"
    try:
        on_disk = os.stat(sshd)
    except OSError as exc:
        return "unknown", f"cannot stat installed sshd: {exc}"
    matches = []
    for pid, realpath, inode in found:
        if (inode.st_dev, inode.st_ino) != (on_disk.st_dev, on_disk.st_ino):
            return "different", f"PID {pid} runs {realpath!r}, not current {sshd} inode"
        matches.append(pid)
    if unreadable:
        return "unknown", "some sshd processes were not readable"
    return "matches", f"running sshd PID(s) {','.join(map(str, matches))} match installed binary"


def effective_settings(sshd: str, user: str, source_address: str):
    """sshd -T resolves Match for a supplied user/source context."""
    candidate = f"user={user},host=localhost,addr={source_address}"
    rc, out, err = run_command([sshd, "-T", "-C", candidate])
    if rc != 0 or not out:
        return {}, err or "sshd -T failed or returned no settings"
    settings = {}
    for line in out.splitlines():
        key, _, value = line.partition(" ")
        if value:
            settings[key.lower()] = value.strip()
    return settings, ""


def audit_local(users: list[str], source_address: str) -> Result:
    start = time.monotonic()
    res = Result(target="localhost", mode="local")
    ck = res.checks
    ck["source_context"] = source_address
    musl = bool(glob.glob("/lib/ld-musl-*.so.1"))
    ck["musl_loader_present"] = str(musl).lower()
    sshd = find_sshd()
    ck["sshd_path"] = sshd or "not found"
    process, explanation = running_sshd_state(sshd)
    ck["running_daemon"] = process
    ck["running_detail"] = explanation
    if process == "not-running":
        # Socket-activated sshd or daemons in other PID namespaces may not be
        # visible until a connection arrives. Absence of a process is not proof.
        res.verdict = INCONCLUSIVE
        res.detail = ("No currently running sshd process was visible; "
                      "socket activation and other PID namespaces were not ruled out.")
        res.elapsed_ms = int((time.monotonic() - start) * 1000)
        return res
    if not sshd:
        res.verdict = INCONCLUSIVE
        res.detail = "Could not locate installed sshd (running daemon state unverified)."
        res.elapsed_ms = int((time.monotonic() - start) * 1000)
        return res

    rc, _out, version_err = run_command([sshd, "-V"])
    ck["sshd_version"] = (version_err or _out).splitlines()[0] if (version_err or _out) else "unknown"
    rc, pkg_out, pkg_err = run_command(["apk", "info", "-v"])
    packages = [line for line in pkg_out.splitlines() if parse_package(line)] if rc == 0 else []
    ck["alpine_server_packages"] = ", ".join(packages) if packages else "unknown"
    # Alpine can have both openssh-server and openssh-server-pam installed. The
    # fixed revision differs per package, so assurances must come from the
    # package that actually ships the running executable.
    shipped_by = daemon_package(sshd)
    ck["daemon_package"] = shipped_by or "unpackaged"
    if shipped_by:
        pkg = next((p for p in packages if p.rsplit("-", 2)[0] == shipped_by), None)
    else:
        # Unknown provenance: fall back to any installed server package only so
        # the report can name it; the fixed-package shortcut stays disabled.
        pkg = next((p for p in packages if p.startswith(("openssh-server-", "openssh-server-pam-"))), None)
    patch = package_fix_state(pkg or "")
    ck["package_fix"] = patch
    # Both package AND running binary inode must match to trust package fix.
    # Alpine package metadata only attests the distro-packaged daemon path.
    # A custom /usr/local/sbin/sshd is not fixed merely because apk is current.
    running_packaged_path = shipped_by is not None
    ck["running_packaged_path"] = str(running_packaged_path).lower()
    if patch == "fixed" and process == "matches" and running_packaged_path:
        res.verdict = NOT_DETECTED
        res.detail = f"Installed {pkg} is fixed and running sshd matches its on-disk binary."
        res.elapsed_ms = int((time.monotonic() - start) * 1000)
        return res

    stars, donors, shadow_error = read_shadow()
    ck["star_accounts"] = ", ".join(stars) if stars else ("unreadable" if shadow_error else "none")
    ck["sha5_sha6_donor_count"] = str(len(donors)) if not shadow_error else "unknown"
    # Restrict checking to relevant local * accounts: root may be password blocked.
    user_checks, candidates, unknown = [], [], []
    for user in stars:
        settings, err = effective_settings(sshd, user, source_address)
        if err:
            unknown.append(f"{user}: {err}")
            user_checks.append(f"{user}: config unknown")
            continue
        pam = settings.get("usepam")
        if pam is None and shipped_by == "openssh-server":
            pam = "no"  # Alpine non-PAM server build doesn't list UsePAM.
        pa = settings.get("passwordauthentication")
        root_rule = settings.get("permitrootlogin") if user == "root" else "n/a"
        user_checks.append(f"{user}: PAM={pam or '?'} password={pa or '?'} root={root_rule or '?'}")
        if pa == "no" or pam == "yes" or (user == "root" and root_rule not in ("yes", None)):
            continue
        if pa != "yes" or pam != "no" or (user == "root" and root_rule is None):
            unknown.append(f"{user}: auth prerequisites unresolved")
            continue
        if settings.get("authenticationmethods", "any") not in ("any", "password"):
            unknown.append(f"{user}: additional authentication method may be required")
            continue
        candidates.append(user)
    ck["account_checks"] = "; ".join(user_checks) if user_checks else "no local * accounts"
    ck["matching_star_accounts"] = ", ".join(candidates) or "none"
    # User hints are not evidence that no other accounts are relevant.
    ck["requested_users"] = ", ".join(users)

    if shadow_error:
        res.verdict, res.detail = INCONCLUSIVE, f"Cannot read /etc/shadow: {shadow_error}"
    elif not donors:
        res.verdict, res.detail = NOT_DETECTED, "No local $5$/$6$ shadow hash donor was found."
    elif process in ("unknown", "different") or (patch == "fixed" and not running_packaged_path):
        res.verdict, res.detail = INCONCLUSIVE, (
            "Running sshd binary is not verified against installed package; a package update may need a restart."
        )
    elif not musl:
        # A loader path alone is not a reliable test of the running binary's libc.
        res.verdict, res.detail = INCONCLUSIVE, "No musl loader found; cannot establish running sshd's libc."
    elif candidates:
        res.verdict, res.detail = RISK, (
            f"Unfixed or unverified package ({pkg or 'unknown'}), musl loader present, "
            f"password authentication potentially available to: {', '.join(candidates)}. "
            "This is a configuration-risk assessment, not an authenticated exploit confirmation."
        )
    elif unknown:
        res.verdict, res.detail = INCONCLUSIVE, "; ".join(unknown[:3])
    elif not stars:
        res.verdict, res.detail = NOT_DETECTED, (
            "No local literal-* shadow accounts; directory-service accounts were not enumerated."
        )
    else:
        res.verdict, res.detail = NOT_DETECTED, (
            "Password authentication was disabled or blocked for the inspected literal-* accounts "
            f"under source address {source_address}; other source contexts may differ."
        )
    res.elapsed_ms = int((time.monotonic() - start) * 1000)
    return res


def passive_banner(target: Target, timeout: float) -> Result:
    """Read only the SSH identification line; do not attempt authentication."""
    start = time.monotonic()
    res = Result(target=target.display(), mode="passive")
    try:
        with socket.create_connection((target.host, target.port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            with sock.makefile("rb") as stream:
                for _ in range(8):  # SSH permits pre-banner notice lines
                    line = stream.readline(256)
                    if not line:
                        break
                    decoded = line.decode("ascii", "replace").strip()
                    if decoded.startswith("SSH-"):
                        res.banner = decoded[:255]
                        break
        if res.banner:
            res.detail = "SSH identified; banner alone cannot establish CVE exposure."
        else:
            res.detail = "No SSH identification line received."
    except (OSError, EOFError) as exc:
        res.detail = f"Connection/identification failed: {type(exc).__name__}: {exc}"
    res.elapsed_ms = int((time.monotonic() - start) * 1000)
    return res


def _paramiko():
    try:
        import paramiko
    except ImportError as exc:
        raise CLIError("--active requires Paramiko: python -m pip install paramiko") from exc
    return paramiko


def exception_types(pm, *names):
    """Resolve Paramiko exception classes across top-level and submodule exports.

    Paramiko does not re-export every exception at package level: for example
    `PartialAuthentication` lives only in `paramiko.ssh_exception`. Resolving
    them dynamically keeps `except` clauses valid for any Paramiko version
    instead of raising AttributeError from inside an exception handler.
    """
    submodule = getattr(pm, "ssh_exception", None)
    resolved = []
    for name in names:
        cls = getattr(pm, name, None)
        if cls is None and submodule is not None:
            cls = getattr(submodule, name, None)
        if isinstance(cls, type):
            resolved.append(cls)
    return tuple(resolved)


def load_trust_store(pm, known_hosts: str):
    """Load known_hosts, reporting unparsable lines instead of aborting the run.

    Paramiko raises InvalidHostKey (a plain Exception, NOT an SSHException) for
    lines it cannot parse. OpenSSH accepts marker lines such as
    `@cert-authority` and `@revoked`, so a normal user's known_hosts frequently
    contains entries Paramiko rejects. Trust is never weakened: rejected lines
    are reported, and the entries that did parse are still enforced.
    """
    invalid = getattr(pm, "InvalidHostKey", None)
    if invalid is None:
        submodule = getattr(pm, "hostkeys", None)
        invalid = getattr(submodule, "InvalidHostKey", None)
    skip = (invalid,) if isinstance(invalid, type) else ()
    keys = pm.HostKeys()
    try:
        keys.load(known_hosts)
    except (*skip, UnicodeDecodeError, ValueError, OSError) as exc:
        return keys, f"could not parse {known_hosts}: {type(exc).__name__}: {exc}"
    return keys, ""


def open_verified_transport(pm, target: Target, timeout: float, known_hosts: str):
    """Authenticate no one until the SSH server key matches an existing trust entry."""
    sock = socket.create_connection((target.host, target.port), timeout=timeout)
    transport = None
    try:
        transport = pm.Transport(sock)
        transport.banner_timeout = timeout
        transport.auth_timeout = timeout
        transport.start_client(timeout=timeout)
        keys, store_error = load_trust_store(pm, known_hosts)
        if store_error:
            # Refuse rather than proceed with a partially trusted store.
            raise SSHIdentityError(store_error)
        name = target.host if target.port == 22 else f"[{target.host}]:{target.port}"
        if not keys.lookup(name):
            raise SSHIdentityError(f"no trusted host key for {name} in {known_hosts}")
        if not keys.check(name, transport.get_remote_server_key()):
            raise SSHIdentityError(f"server host key mismatch for {name}")
        return transport
    except BaseException:
        if transport is not None:
            transport.close()
        else:
            sock.close()
        raise


def password_attempt(pm, transport, user: str, password: str):
    """Return state, detail; explicitly recognize partial/multifactor auth."""
    bad_type, partial, auth_failed, ssh_error = exception_types(
        pm, "BadAuthenticationType", "PartialAuthentication",
        "AuthenticationException", "SSHException")
    try:
        remaining = transport.auth_password(user, password, fallback=False)
    except bad_type or () as exc:
        return "no-password-method", str(exc)
    except partial or () as exc:
        return "partial", str(exc)
    except auth_failed or () as exc:
        return "rejected", str(exc)
    except (ssh_error or (), EOFError, OSError) as exc:
        return "error", f"{type(exc).__name__}: {exc}"
    if transport.is_authenticated():
        return "accepted", ""
    if remaining:
        return "partial", ",".join(remaining)
    return "error", "authentication returned without clear result"


@dataclass
class PairOutcome:
    first: str
    second: str
    detail: str = ""
    banner: str = ""


def test_password_pair(pm, target: Target, user: str, passwords: tuple[str, str],
                       timeout: float, known_hosts: str) -> PairOutcome:
    """On one connection, send EXACTLY the two caller-provided strings."""
    transport = None
    try:
        transport = open_verified_transport(pm, target, timeout, known_hosts)
        banner = getattr(transport, "remote_version", "") or ""
        first, msg = password_attempt(pm, transport, user, passwords[0])
        if first != "rejected":
            return PairOutcome(first, "not-attempted", msg, banner)
        second, msg = password_attempt(pm, transport, user, passwords[1])
        return PairOutcome(first, second, msg, banner)
    except (SSHIdentityError, OSError, EOFError) + exception_types(pm, "SSHException") as exc:
        return PairOutcome("error", "not-attempted", f"{type(exc).__name__}: {exc}")
    finally:
        if transport is not None:
            transport.close()  # never open a channel, command, or shell


def guarded(work, target: Target, mode: str) -> Result:
    """Never let one target's unexpected exception abort the whole run.

    ThreadPoolExecutor.map re-raises worker exceptions from the iterator, which
    would discard every remaining target. An unanticipated failure is reported
    as that target's inconclusive result instead.
    """
    try:
        return work(target)
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException as exc:
        failure = Result(target=target.display(), mode=mode, verdict=INCONCLUSIVE)
        failure.detail = f"internal error while testing this target: {type(exc).__name__}: {exc}"
        return failure


def active_target(pm, target: Target, users: list[str], timeout: float, known_hosts: str) -> Result:
    start = time.monotonic()
    res = Result(target=target.display(), mode="active")
    inconclusive = []
    for user in users:
        res.tested_users.append(user)
        pair = test_password_pair(pm, target, user, BOUNDARY, timeout, known_hosts)
        res.banner = res.banner or pair.banner
        if pair.first == "rejected" and pair.second == "accepted":
            control = test_password_pair(pm, target, user, CONTROLS, timeout, known_hosts)
            if control.first == "rejected" and control.second == "rejected":
                res.verdict, res.user = VULNERABLE, user
                res.detail = ("Boundary password rejected then accepted on one connection; "
                              "distinct short-password control rejected twice; no command executed.")
                break
            inconclusive.append(f"{user}: boundary accepted but short-password control "
                                f"was {control.first}/{control.second} ({control.detail})")
            continue
        if pair.first == "rejected" and pair.second == "rejected":
            continue
        if pair.first == "no-password-method":
            continue
        inconclusive.append(f"{user}: {pair.first}/{pair.second} ({pair.detail})")
    else:
        if inconclusive:
            res.verdict = INCONCLUSIVE
            res.detail = "; ".join(inconclusive[:3])
        else:
            res.verdict = NOT_DETECTED
            res.detail = ("Exploit behavior not observed for the listed usernames only; "
                          "other accounts and authentication configurations were not tested.")
    res.elapsed_ms = int((time.monotonic() - start) * 1000)
    return res


def text_report(res: Result):
    # SSH banners and exception text can contain terminal-control characters.
    def escaped(text):
        return json.dumps(str(text), ensure_ascii=True)[1:-1]

    who = f" user={escaped(res.user)}" if res.user else ""
    banner = f" [{escaped(res.banner)}]" if res.banner else ""
    return f"[{res.verdict}] {escaped(res.target)}{who}{banner}: {escaped(res.detail)}"


def positive_result(res: Result):
    return res.verdict in (VULNERABLE, RISK)


def make_parser():
    p = Parser(prog=PROG, description="Auditor for OpenSSH/musl password bypass (CVE-2026-123158)")
    group = p.add_mutually_exclusive_group()
    group.add_argument("--local", action="store_true", help="read-only audit of this host")
    group.add_argument("-t", "--target", help="one SSH target")
    p.add_argument("-f", "--list", help="target list (hostname, host:port, or [IPv6]:port)")
    p.add_argument("-p", "--port", type=int, default=22)
    p.add_argument("-u", "--users", default=",".join(DEFAULT_USERS),
                   help="comma-separated user list for --active")
    p.add_argument("--source-address", default="127.0.0.1",
                   help="source address for local sshd Match checks")
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--workers", type=int, default=2)
    p.add_argument("--active", action="store_true",
                   help="send password attempts; authorized systems only; trusted host key required")
    p.add_argument("--known-hosts", default=os.path.expanduser("~/.ssh/known_hosts"),
                   help="SSH host-key trust store for --active")
    p.add_argument("--json", action="store_true", help="write JSON lines to stdout")
    p.add_argument("-o", "--output", help="append full JSONL results to this file")
    return p


def main(argv=None):
    parser = make_parser()
    args = parser.parse_args(argv)
    try:
        valid_port(args.port)
        try:
            ipaddress.ip_address(args.source_address)
        except ValueError as exc:
            raise CLIError("--source-address must be an IP address") from exc
        if not math.isfinite(args.timeout) or not (0.1 <= args.timeout <= 120.0):
            raise CLIError("--timeout must be between 0.1 and 120 seconds")
        if not 1 <= args.workers <= 16:
            raise CLIError("--workers must be 1..16")
        users = list(dict.fromkeys(u.strip() for u in args.users.split(",") if u.strip()))
        if not users:
            raise CLIError("--users must include at least one username")
        if len(users) > 32:
            raise CLIError("--users supports a maximum of 32 accounts")
        if args.local:
            if args.active or args.list:
                raise CLIError("--local cannot be combined with --active or --list")
            results = [audit_local(users, args.source_address)]
        else:
            targets = load_targets(args.target, args.list, args.port)
            if not targets:
                raise CLIError("provide --local, --target or --list")
            if args.active:
                if len(targets) > 32 or len(users) > 8:
                    raise CLIError("--active is limited to 32 hosts and 8 usernames per run")
                if args.workers > 4:
                    raise CLIError("--active supports at most 4 parallel workers")
                if not os.path.isfile(args.known_hosts):
                    raise CLIError("--active requires a readable --known-hosts file")
                pm = _paramiko()
                work = lambda target: guarded(
                    lambda t: active_target(pm, t, users, args.timeout, args.known_hosts),
                    target, "active")
            else:
                work = lambda target: guarded(
                    lambda t: passive_banner(t, args.timeout), target, "passive")
            with ThreadPoolExecutor(max_workers=args.workers) as pool:
                results = list(pool.map(work, targets))
        # Reporting and output occur on one thread: no lock re-entry or deadlock.
        for res in results:
            print(json.dumps(res.as_dict(), sort_keys=True) if args.json else text_report(res))
            if args.local and not args.json:
                for key, value in res.checks.items():
                    print(f"  {key:<25} {value}")
        if args.output:
            try:
                with open(args.output, "a", encoding="utf-8") as handle:
                    for res in results:
                        handle.write(json.dumps(res.as_dict(), sort_keys=True) + "\n")
            except OSError as exc:
                raise CLIError(f"cannot write {args.output!r}: {exc}") from exc
        if any(positive_result(r) for r in results):
            return 0
        return 2 if any(r.verdict == INCONCLUSIVE for r in results) else 1
    except CLIError as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
