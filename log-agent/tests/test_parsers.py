"""
tests/test_parsers.py
Run with: pytest tests/ (from log-agent/, with src/ on PYTHONPATH — see
pytest.ini-style config below or run `PYTHONPATH=src pytest`)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from models import RawLogLine, SourceType  # noqa: E402
from parsers.auth_parser import AuthParser  # noqa: E402
from parsers.syslog_parser import SyslogParser  # noqa: E402
from parsers.web_parser import WebParser  # noqa: E402


def _raw(line: str, source_type: SourceType) -> RawLogLine:
    return RawLogLine(source_type=source_type, source_path="/dev/null", hostname="test-host", raw_line=line)


class TestSyslogParser:
    def setup_method(self):
        self.parser = SyslogParser()

    def test_parses_standard_line_with_pri(self):
        line = "<34>Oct 11 22:14:15 mymachine su[1234]: 'su root' failed for user on /dev/pts/8"
        event = self.parser.parse(_raw(line, SourceType.SYSLOG))
        assert event is not None
        assert event.process == "su"
        assert event.fields["pid"] == 1234
        assert event.facility == "auth"
        assert event.severity == "crit"
        assert "failed for user" in event.message

    def test_parses_line_without_pri(self):
        line = "Oct 11 22:14:15 mymachine cron[999]: (root) CMD (run-parts /etc/cron.hourly)"
        event = self.parser.parse(_raw(line, SourceType.SYSLOG))
        assert event is not None
        assert event.facility is None
        assert event.process == "cron"

    def test_malformed_line_still_forwarded(self):
        line = "this is not a valid syslog line at all"
        event = self.parser.parse(_raw(line, SourceType.SYSLOG))
        assert event is not None
        assert event.fields.get("malformed") is True

    def test_blank_line_returns_none(self):
        assert self.parser.parse(_raw("", SourceType.SYSLOG)) is None


class TestAuthParser:
    def setup_method(self):
        self.parser = AuthParser()

    def test_ssh_failed_password(self):
        line = "Sep 13 10:00:01 host sshd[4021]: Failed password for root from 203.0.113.42 port 51514 ssh2"
        event = self.parser.parse(_raw(line, SourceType.AUTH))
        assert event.fields["event_subtype"] == "ssh_failed_login"
        assert event.fields["username"] == "root"
        assert event.fields["source_ip"] == "203.0.113.42"
        assert event.fields["source_port"] == 51514
        assert event.fields["outcome"] == "failure"

    def test_ssh_accepted_publickey(self):
        line = "Sep 13 10:00:05 host sshd[4022]: Accepted publickey for deploy from 198.51.100.5 port 60000"
        event = self.parser.parse(_raw(line, SourceType.AUTH))
        assert event.fields["event_subtype"] == "ssh_successful_login"
        assert event.fields["auth_method"] == "publickey"
        assert event.fields["outcome"] == "success"

    def test_ssh_invalid_user(self):
        line = "Sep 13 10:01:00 host sshd[4030]: Invalid user admin from 198.51.100.9 port 44000"
        event = self.parser.parse(_raw(line, SourceType.AUTH))
        assert event.fields["event_subtype"] == "ssh_invalid_user"
        assert event.fields["username"] == "admin"

    def test_sudo_command(self):
        line = "Sep 13 10:02:00 host sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx"
        event = self.parser.parse(_raw(line, SourceType.AUTH))
        assert event.fields["event_subtype"] == "sudo_command"
        assert event.fields["target_user"] == "root"
        assert "systemctl restart nginx" in event.fields["command"]

    def test_su_failure(self):
        line = "Sep 13 10:03:00 host su[5001]: FAILED su for root by alice"
        event = self.parser.parse(_raw(line, SourceType.AUTH))
        assert event.fields["event_subtype"] == "su_failure"
        assert event.fields["target_user"] == "root"
        assert event.fields["by"] == "alice"


class TestWebParser:
    def setup_method(self):
        self.parser = WebParser()

    def test_parses_combined_log_format(self):
        line = ('127.0.0.1 - frank [10/Oct/2023:13:55:36 -0700] "GET /index.html HTTP/1.1" '
                '200 2326 "http://example.com/" "Mozilla/5.0"')
        event = self.parser.parse(_raw(line, SourceType.WEB))
        assert event.fields["client_ip"] == "127.0.0.1"
        assert event.fields["status_code"] == 200
        assert event.fields["http_method"] == "GET"
        assert event.fields["path"] == "/index.html"
        assert event.fields["user_agent"] == "Mozilla/5.0"

    def test_flags_sql_injection_attempt(self):
        line = ('10.0.0.5 - - [10/Oct/2023:13:56:00 -0700] '
                '"GET /products?id=1%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1" '
                '500 512 "-" "curl/7.88"')
        event = self.parser.parse(_raw(line, SourceType.WEB))
        assert "sql_injection" in event.fields["attack_signatures"]
        assert event.severity == "err"

    def test_flags_path_traversal(self):
        line = ('10.0.0.6 - - [10/Oct/2023:13:57:00 -0700] '
                '"GET /../../etc/passwd HTTP/1.1" 404 0 "-" "sqlmap/1.0"')
        event = self.parser.parse(_raw(line, SourceType.WEB))
        assert "path_traversal" in event.fields["attack_signatures"]

    def test_plain_request_no_signatures(self):
        line = ('10.0.0.7 - - [10/Oct/2023:13:58:00 -0700] '
                '"GET /favicon.ico HTTP/1.1" 200 150 "-" "Mozilla/5.0"')
        event = self.parser.parse(_raw(line, SourceType.WEB))
        assert event.fields["attack_signatures"] == []
