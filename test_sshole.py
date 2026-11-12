"""Offline regression tests for sshole.py (no network, no credentials)."""
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import sshole as s


class FakePM:
    class SSHException(Exception):
        pass
    class AuthenticationException(Exception):
        pass
    class BadAuthenticationType(AuthenticationException):
        pass
    class PartialAuthentication(AuthenticationException):
        pass


class RejectedTransport:
    remote_version = "SSH-2.0-fixture"

    def __init__(self):
        self.attempts = []
        self.closed = False

    def auth_password(self, user, password, fallback=False):
        self.attempts.append((user, password, fallback))
        raise FakePM.AuthenticationException("rejected")

    def close(self):
        self.closed = True


class ParsingTests(unittest.TestCase):
    def test_target_formats(self):
        self.assertEqual(s.parse_target("server.example:2222", 22), s.Target("server.example", 2222))
        self.assertEqual(s.parse_target("[2001:db8::1]:2222", 22), s.Target("2001:db8::1", 2222))
        self.assertEqual(s.parse_target("2001:db8::1", 22), s.Target("2001:db8::1", 22))

    def test_malformed_target_has_actionable_error(self):
        with tempfile.TemporaryDirectory() as temp:
            targets = Path(temp) / "hosts.txt"
            targets.write_text("server:abc\n", encoding="utf8")
            with self.assertRaisesRegex(s.CLIError, r"hosts.txt:1: invalid port"):
                s.load_targets(None, str(targets), 22)

    def test_deduplicate_targets(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "hosts.txt"
            path.write_text("host\nhost\nhost:22\n", encoding="utf8")
            self.assertEqual(s.load_targets("host", str(path), 22), [s.Target("host", 22)])

    def test_package_revision(self):
        self.assertEqual(s.package_fix_state("openssh-server-10.3_p1-r2"), "fixed")
        self.assertEqual(s.package_fix_state("openssh-server-pam-10.3_p1-r1"), "unfixed")
        self.assertEqual(s.package_fix_state("openssh-server-10.3_p1-r200"), "fixed")
        self.assertEqual(s.package_fix_state("openssh-server-11.1_p1-r0"), "unknown")
        self.assertEqual(s.package_fix_state("openssh-client-10.3_p1-r2"), "unknown")


class ActivePairTests(unittest.TestCase):
    def test_control_uses_distinct_literal_passwords(self):
        transport = RejectedTransport()
        with patch.object(s, "open_verified_transport", return_value=transport):
            result = s.test_password_pair(FakePM, s.Target("lab"), "auditor", s.CONTROLS, 2, "trusted_hosts")
        self.assertEqual((result.first, result.second), ("rejected", "rejected"))
        self.assertEqual([row[1] for row in transport.attempts], ["ctl-a7f3", "ctl-b9e1"])
        self.assertTrue(transport.closed)

    def test_first_accept_does_not_trigger_second_auth(self):
        class Accepted(RejectedTransport):
            def auth_password(self, user, password, fallback=False):
                self.attempts.append((user, password, fallback))
                return []

            def is_authenticated(self):
                return True

        transport = Accepted()
        with patch.object(s, "open_verified_transport", return_value=transport):
            result = s.test_password_pair(FakePM, s.Target("lab"), "test", s.BOUNDARY, 2, "hosts")
        self.assertEqual(result.first, "accepted")
        self.assertEqual(result.second, "not-attempted")
        self.assertEqual(len(transport.attempts), 1)
        self.assertTrue(transport.closed)

    def test_verified_positive(self):
        tests = [s.PairOutcome("rejected", "accepted"), s.PairOutcome("rejected", "rejected")]
        with patch.object(s, "test_password_pair", side_effect=tests) as run:
            result = s.active_target(FakePM, s.Target("lab"), ["test"], 1, "hosts")
        self.assertEqual(result.verdict, s.VULNERABLE)
        self.assertEqual(run.call_args_list[0].args[3], s.BOUNDARY)
        self.assertEqual(run.call_args_list[1].args[3], s.CONTROLS)

    def test_short_password_acceptance_is_not_verified_vulnerable(self):
        tests = [s.PairOutcome("rejected", "accepted"), s.PairOutcome("rejected", "accepted")]
        with patch.object(s, "test_password_pair", side_effect=tests):
            result = s.active_target(FakePM, s.Target("lab"), ["test"], 1, "hosts")
        self.assertEqual(result.verdict, s.INCONCLUSIVE)

    def test_early_acceptance_is_inconclusive(self):
        with patch.object(s, "test_password_pair", return_value=s.PairOutcome("accepted", "not-attempted")):
            result = s.active_target(FakePM, s.Target("lab"), ["test"], 1, "hosts")
        self.assertEqual(result.verdict, s.INCONCLUSIVE)

    def test_negative_limited_to_accounts(self):
        with patch.object(s, "test_password_pair", return_value=s.PairOutcome("rejected", "rejected")):
            result = s.active_target(FakePM, s.Target("lab"), ["root", "alpine"], 1, "hosts")
        self.assertEqual(result.verdict, s.NOT_DETECTED)
        self.assertIn("listed usernames only", result.detail)
        self.assertEqual(result.tested_users, ["root", "alpine"])


class LocalAuditTests(unittest.TestCase):
    def audit(self, proc_state="matches", package="openssh-server-10.3_p1-r1", settings=None):
        if settings is None:
            settings = {"usepam": "no", "passwordauthentication": "yes", "permitrootlogin": "yes"}
        def run(argv, timeout=6):
            if argv[-1] == "-V":
                return (0, "", "OpenSSH_10.3p1")
            if argv[:2] == ["apk", "info"]:
                return (0, package, "")
            return (1, "", "not simulated")
        with patch.object(s, "find_sshd", return_value="/usr/sbin/sshd"), \
             patch.object(s, "running_sshd_state", return_value=(proc_state, "fixture")), \
             patch.object(s, "run_command", side_effect=run), \
             patch.object(s, "read_shadow", return_value=(["root"], ["account"], "")), \
             patch.object(s, "effective_settings", return_value=(settings, "")), \
             patch.object(s.glob, "glob", return_value=["/lib/ld-musl-x86_64.so.1"]):
            return s.audit_local(["root"], "127.0.0.1")

    def test_no_process_does_not_exclude_socket_activation(self):
        result = self.audit(proc_state="not-running")
        self.assertEqual(result.verdict, s.INCONCLUSIVE)
        self.assertIn("socket activation", result.detail)

    def test_unfixed_with_prerequisites_is_risk_not_confirmed_exploit(self):
        result = self.audit()
        self.assertEqual(result.verdict, s.RISK)

    def test_fixed_running_binary_is_not_detected(self):
        result = self.audit(package="openssh-server-10.3_p1-r2")
        self.assertEqual(result.verdict, s.NOT_DETECTED)

    def test_fixed_on_disk_but_stale_running_binary_is_inconclusive(self):
        result = self.audit(proc_state="different", package="openssh-server-10.3_p1-r2")
        self.assertEqual(result.verdict, s.INCONCLUSIVE)
        self.assertIn("restart", result.detail)

    def test_unknown_auth_setting_is_inconclusive(self):
        result = self.audit(settings={"usepam": "no", "permitrootlogin": "yes"})
        self.assertEqual(result.verdict, s.INCONCLUSIVE)

    def test_root_login_blocked_is_not_detected(self):
        result = self.audit(settings={"usepam": "no", "passwordauthentication": "yes",
                                      "permitrootlogin": "prohibit-password"})
        self.assertEqual(result.verdict, s.NOT_DETECTED)


class CLITests(unittest.TestCase):
    def test_cli_only_local_without_paramiko(self):
        with patch.object(s, "audit_local", return_value=s.Result("localhost", "local", s.NOT_DETECTED)):
            with patch("sys.stdout", new_callable=io.StringIO):
                self.assertEqual(s.main(["--local", "--json"]), 1)

    def test_bad_output_returns_exit_3_not_deadlock(self):
        with patch.object(s, "passive_banner", return_value=s.Result("lab:22", "passive")), \
             patch("sys.stdout", new_callable=io.StringIO), \
             patch("sys.stderr", new_callable=io.StringIO):
            with self.assertRaises(SystemExit) as ctx:
                s.main(["--target", "lab", "--output", "/impossible_path_x/file.jsonl"])
        self.assertEqual(ctx.exception.code, 3)

    def test_active_requires_known_hosts(self):
        with patch("sys.stderr", new_callable=io.StringIO):
            with self.assertRaises(SystemExit) as ctx:
                s.main(["--target", "lab", "--active", "--known-hosts", "/impossible/file"])
        self.assertEqual(ctx.exception.code, 3)


class RunContainmentTests(unittest.TestCase):
    """One host's failure must never discard the rest of the run."""

    def test_unexpected_exception_becomes_inconclusive(self):
        def boom(target):
            raise RuntimeError("unexpected")

        result = s.guarded(boom, s.Target("lab"), "active")
        self.assertEqual(result.verdict, s.INCONCLUSIVE)
        self.assertEqual(result.mode, "active")
        self.assertIn("RuntimeError", result.detail)

    def test_keyboard_interrupt_is_not_swallowed(self):
        def interrupt(target):
            raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            s.guarded(interrupt, s.Target("lab"), "passive")

    def test_unparsable_trust_store_aborts_nothing_and_weakens_nothing(self):
        import paramiko

        class BrokenKeys:
            def load(self, path):
                raise paramiko.hostkeys.InvalidHostKey("bad line", ValueError("padd"))

        class PM:
            HostKeys = BrokenKeys
            hostkeys = paramiko.hostkeys

        keys, error = s.load_trust_store(PM, "known_hosts")
        self.assertIsInstance(keys, BrokenKeys)
        self.assertIn("InvalidHostKey", error)

    def test_trust_store_error_refuses_authentication(self):
        def broken_store(pm, path):
            return object(), "could not parse known_hosts"

        class FakeTransport:
            def __init__(self, sock):
                self.closed = False
            def start_client(self, timeout):
                pass
            def close(self):
                self.closed = True

        class Sock:
            def close(self):
                pass

        class PM:
            Transport = FakeTransport
            HostKeys = object

        with patch.object(s, "load_trust_store", side_effect=broken_store), \
             patch.object(s.socket, "create_connection", return_value=Sock()):
            with self.assertRaisesRegex(s.SSHIdentityError, "could not parse"):
                s.open_verified_transport(PM, s.Target("lab"), 1, "kh")


class ParamikoCompatibilityTests(unittest.TestCase):
    """PartialAuthentication is only exported from paramiko.ssh_exception."""

    def test_exception_types_falls_back_to_submodule(self):
        class SSHException(Exception):
            pass

        class AuthenticationException(SSHException):
            pass

        class PartialAuthentication(AuthenticationException):
            pass

        class FakePM:
            pass

        FakePM.SSHException = SSHException
        FakePM.AuthenticationException = AuthenticationException
        FakePM.ssh_exception = type("m", (), {"PartialAuthentication": PartialAuthentication})

        resolved = s.exception_types(FakePM, "PartialAuthentication", "AuthenticationException")
        self.assertEqual(resolved, (PartialAuthentication, AuthenticationException))

    def test_missing_exception_class_is_not_a_bare_type_error(self):
        class FakePM:
            pass

        FakePM.SSHException = Exception
        FakePM.ssh_exception = type("m", (), {})

        self.assertEqual(s.exception_types(FakePM, "PartialAuthentication"), ())

    def test_password_attempt_reports_rejection_without_attribute_error(self):
        import paramiko

        class Rejecting:
            def auth_password(self, user, password, fallback=False):
                raise paramiko.AuthenticationException("denied")

        state, _detail = s.password_attempt(paramiko, Rejecting(), "alpine", "x" * 257)
        self.assertEqual(state, "rejected")


class DaemonPackageTests(unittest.TestCase):
    """Alpine ships sshd and sshd.pam as separate packages with separate fixes."""

    def test_pam_daemon_maps_to_pam_package(self):
        self.assertEqual(s.daemon_package("/usr/sbin/sshd.pam"), "openssh-server-pam")
        self.assertEqual(s.daemon_package("/usr/sbin/sshd"), "openssh-server")

    def test_unpackaged_path_has_no_package_assurance(self):
        self.assertIsNone(s.daemon_package("/usr/local/sbin/sshd"))
        self.assertIsNone(s.daemon_package(None))

    def test_find_sshd_finds_pam_only_install(self):
        def fake_isfile(path):
            return path == "/usr/sbin/sshd.pam"

        with patch.object(s.os.path, "isfile", side_effect=fake_isfile):
            self.assertEqual(s.find_sshd(), "/usr/sbin/sshd.pam")


class IdentityAndPassiveTests(unittest.TestCase):
    def test_unknown_host_key_prevents_authentication(self):
        class FakeTransport:
            def __init__(self, sock):
                self.sock = sock
                self.closed = False
            def start_client(self, timeout):
                pass
            def get_remote_server_key(self):
                return object()
            def close(self):
                self.closed = True

        class FakeKeys:
            def load(self, path):
                self.path = path
            def lookup(self, name):
                return None
            def check(self, name, key):
                raise AssertionError("should not check a missing trust entry")

        class PM:
            Transport = FakeTransport
            HostKeys = FakeKeys

        class Sock:
            def close(self):
                self.closed = True

        with patch.object(s.socket, "create_connection", return_value=Sock()):
            with self.assertRaisesRegex(s.SSHIdentityError, "no trusted host key"):
                s.open_verified_transport(PM, s.Target("lab"), 1, "known_hosts")

    def test_host_key_mismatch_prevents_authentication(self):
        class FakeTransport:
            def __init__(self, sock):
                self.closed = False
            def start_client(self, timeout):
                pass
            def get_remote_server_key(self):
                return object()
            def close(self):
                self.closed = True

        class FakeKeys:
            def load(self, path):
                pass
            def lookup(self, name):
                return {"ssh-ed25519": object()}
            def check(self, name, key):
                return False

        class PM:
            Transport = FakeTransport
            HostKeys = FakeKeys

        class Sock:
            def close(self):
                pass

        with patch.object(s.socket, "create_connection", return_value=Sock()):
            with self.assertRaisesRegex(s.SSHIdentityError, "host key mismatch"):
                s.open_verified_transport(PM, s.Target("lab"), 1, "known_hosts")

    def test_passive_banner_is_always_inconclusive(self):
        class Stream:
            def __init__(self):
                self.lines = iter([b"notice\r\n", b"SSH-2.0-test-daemon\r\n"])
            def readline(self, n):
                return next(self.lines, b"")
            def __enter__(self):
                return self
            def __exit__(self, *exc):
                return False

        class Sock:
            def settimeout(self, value):
                pass
            def makefile(self, mode):
                return Stream()
            def __enter__(self):
                return self
            def __exit__(self, *exc):
                return False

        with patch.object(s.socket, "create_connection", return_value=Sock()):
            result = s.passive_banner(s.Target("lab"), 1)
        self.assertEqual(result.verdict, s.INCONCLUSIVE)
        self.assertEqual(result.banner, "SSH-2.0-test-daemon")


if __name__ == "__main__":
    unittest.main(verbosity=2)
