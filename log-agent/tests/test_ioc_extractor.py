import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ioc.extractor import IOCExtractor  # noqa: E402
from models import IOCType  # noqa: E402


class TestIOCExtractor:
    def setup_method(self):
        self.extractor = IOCExtractor(exclude_private_ips=False)

    def test_extracts_ipv4(self):
        matches = self.extractor.extract("connection from 203.0.113.42 refused")
        ips = [m.value for m in matches if m.ioc_type == IOCType.IPV4]
        assert ips == ["203.0.113.42"]

    def test_rejects_invalid_ipv4_octets(self):
        matches = self.extractor.extract("garbage value 999.999.999.999 here")
        ips = [m.value for m in matches if m.ioc_type == IOCType.IPV4]
        assert ips == []

    def test_extracts_md5(self):
        h = "5d41402abc4b2a76b9719d911017c592"[:32]
        matches = self.extractor.extract(f"file hash={h} detected")
        found = [m for m in matches if m.ioc_type == IOCType.MD5]
        assert len(found) == 1
        assert found[0].value == h

    def test_extracts_sha256(self):
        h = "a" * 64
        matches = self.extractor.extract(f"sha256:{h}")
        found = [m for m in matches if m.ioc_type == IOCType.SHA256]
        assert len(found) == 1

    def test_extracts_domain(self):
        matches = self.extractor.extract("beaconing to evil-c2.malicious-domain.net over https")
        domains = [m.value for m in matches if m.ioc_type == IOCType.DOMAIN]
        assert "evil-c2.malicious-domain.net" in domains

    def test_ignores_file_extension_lookalikes(self):
        matches = self.extractor.extract("wrote output to report.log and archive.tar.gz")
        domains = [m.value for m in matches if m.ioc_type == IOCType.DOMAIN]
        assert domains == []

    def test_private_ip_exclusion_flag(self):
        extractor = IOCExtractor(exclude_private_ips=True)
        matches = extractor.extract("internal hop via 10.0.0.5 then 203.0.113.42")
        ips = [m.value for m in matches if m.ioc_type == IOCType.IPV4]
        assert ips == ["203.0.113.42"]

    def test_deduplicates_repeated_ioc_in_same_line(self):
        matches = self.extractor.extract("203.0.113.42 talked to 203.0.113.42 twice")
        ips = [m.value for m in matches if m.ioc_type == IOCType.IPV4]
        assert ips == ["203.0.113.42"]
