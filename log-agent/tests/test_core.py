import unittest
import json
import hmac
import hashlib
from src.parsers.auth_parser import AuthLogParser
from src.parsers.web_parser import WebLogParser
from src.shipper import LogShipper, CryptoEngine

class TestLogParsers(unittest.TestCase):

    def setUp(self):
        self.auth_parser = AuthLogParser()
        self.web_parser = WebLogParser()

    def test_auth_parser_failed_password(self):
        log_line = "Failed password for invalid user admin from 192.168.1.100 port 4422 ssh2"
        parsed = self.auth_parser.parse(log_line)
        
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed['event_type'], 'ssh_failed_login')
        self.assertEqual(parsed['ip'], '192.168.1.100')
        self.assertIn('192.168.1.100', [ioc['value'] for ioc in parsed['iocs']])

    def test_web_parser_sql_injection(self):
        log_line = '10.0.0.5 - - [12/May/2026:10:00:00 +0000] "GET /login?user=admin\' OR \'1\'=\'1 HTTP/1.1" 200 512'
        parsed = self.web_parser.parse(log_line)
        
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed['client_ip'], '10.0.0.5')
        self.assertIn('sql_injection_attempt', parsed['tags'])


class TestCryptoAndShipper(unittest.TestCase):

    def setUp(self):
        self.key = b'0123456789abcdef0123456789abcdef' # 32 bytes key
        self.hmac_secret = "super-secret-hmac-key"
        self.crypto = CryptoEngine(secret_key=self.key)

    def test_aes_encryption_decryption(self):
        plaintext = "Sensitive security log payload"
        ciphertext_b64, nonce_b64, tag_b64 = self.crypto.encrypt(plaintext)
        
        self.assertIsNotNone(ciphertext_b64)
        self.assertIsNotNone(nonce_b64)
        
        # Verify decryption produces original text
        decrypted = self.crypto.decrypt(ciphertext_b64, nonce_b64, tag_b64)
        self.assertEqual(decrypted, plaintext)

    def test_hmac_signature_verification(self):
        payload_data = {"test": "data"}
        payload_bytes = json.dumps(payload_data, sort_keys=True).encode('utf-8')
        
        expected_sig = hmac.new(
            self.hmac_secret.encode('utf-8'),
            payload_bytes,
            hashlib.sha256
        ).hexdigest()

        self.assertEqual(len(expected_sig), 64)

if __name__ == '__main__':
    unittest.main()
