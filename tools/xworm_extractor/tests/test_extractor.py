"""
Run with:  python -m unittest discover -s tests -v

The end-to-end tests compile a small harmless C# program whose Settings class is
encrypted the same way XWorm does it, so no malware has to live in the repo.
"""
import base64
import contextlib
import hashlib
import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import xworm_extractor as xe  # noqa: E402

CSC = next((p for p in (
    r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
    r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe",
    shutil.which("csc"),
    shutil.which("mcs"),
) if p and os.path.exists(p)), None)


def encrypt(plain: str, mutex: str) -> str:
    padder = padding.PKCS7(128).padder()
    data = padder.update(plain.encode("utf-8")) + padder.finalize()
    enc = Cipher(algorithms.AES(xe.derive_key(mutex)), modes.ECB()).encryptor()
    return base64.b64encode(enc.update(data) + enc.finalize()).decode()


def compile_cs(source: str, directory: str, name: str) -> str:
    src = os.path.join(directory, name + ".cs")
    exe = os.path.join(directory, name + ".exe")
    with open(src, "w", encoding="utf-8") as f:
        f.write(source)
    subprocess.run([CSC, "/nologo", "/target:exe", f"/out:{exe}", src], check=True, capture_output=True)
    return exe


class TestCrypto(unittest.TestCase):
    def test_key_layout(self):
        digest = hashlib.md5(b"aGO284VKfQVe8Vup").digest()
        key = xe.derive_key("aGO284VKfQVe8Vup")
        self.assertEqual(len(key), 32)
        self.assertEqual(key[0:15], digest[0:15])
        self.assertEqual(key[15], digest[0])
        self.assertEqual(key[16:31], digest[1:16])
        self.assertEqual(key[31], 0)

    def test_roundtrip(self):
        raw = xe.decode_ciphertext(encrypt("192.0.2.10", "m"))
        self.assertEqual(xe.decrypt(raw, xe.derive_key("m")), "192.0.2.10")

    def test_wrong_key(self):
        raw = xe.decode_ciphertext(encrypt("192.0.2.10", "right"))
        self.assertIsNone(xe.decrypt(raw, xe.derive_key("wrong")))

    def test_not_ciphertext(self):
        self.assertIsNone(xe.decode_ciphertext("cmd.exe"))
        self.assertIsNone(xe.decode_ciphertext("SGVsbG8gV29ybGQhIEhlbGxvIQ=="))  # 20 bytes
        self.assertIsNone(xe.decode_ciphertext("aGO284VKfQVe8Vup"))              # a mutex

    def test_real_v30_strings(self):
        # #US strings from XWorm V3.0, c784971dffa317fcb27e9e47d68939b22871c0061e293921ca9c2591e3070ae8
        strings = ["q2Gqf3L4FZk3EvZn/gUL/KxWKtPhwnlRptnlIVqY/IU=", "6sN212b80DM2fiwqWkwL7w==",
                   "AGbLgXgjW5e0JznOinWrHQ==", "wRoEfiNb8akS/vyD3Bnbhw==", "F/hczr4WIpbn9rUDL1NV/g==",
                   "tE9JJV5nTLQSTP4J", "INFO", "Microsoft", "XWorm V3.0", "PING!"]
        mutex, key, plain = xe.find_key(strings)
        self.assertEqual(mutex, "tE9JJV5nTLQSTP4J")
        self.assertEqual(key.hex(), "7b31ad0d2eec5b7b5a1275af27dc517b31ad0d2eec5b7b5a1275af27dc51ba00")
        self.assertEqual([plain[i] for i in sorted(plain)],
                         ["watfcokhms.localto.net", "8845", "<123456789>", "<Xwormmm>", "USB.exe"])


class TestUserStringHeap(unittest.TestCase):
    @staticmethod
    def entry(s: str) -> bytes:
        data = s.encode("utf-16-le") + b"\x00"
        n = len(data)
        return (bytes([n]) if n < 0x80 else bytes([0x80 | (n >> 8), n & 0xFF])) + data

    def test_short_and_long_entries(self):
        long_s = "A" * 200  # needs the two-byte length form
        heap = b"\x00" + self.entry("hello") + self.entry(long_s) + b"\x00\x00"
        self.assertEqual(xe.parse_us_heap(heap), ["hello", long_s])


class TestLabels(unittest.TestCase):
    def test_field_order(self):
        cfg, rest = xe.label_config(["192.0.2.10,example.org", "7000", "<123456789>", "<Xwormmm>",
                                     "XWorm V5.6", "USB.exe", "%AppData%", "svchost.exe"])
        self.assertEqual(cfg["hosts"], ["192.0.2.10", "example.org"])
        self.assertEqual(cfg["port"], 7000)
        self.assertEqual(cfg["aes_key"], "<123456789>")
        self.assertEqual(cfg["splitter"], "<Xwormmm>")
        self.assertEqual(cfg["group"], "XWorm V5.6")
        self.assertEqual(cfg["usb_name"], "USB.exe")
        self.assertEqual(cfg["install_dir"], "%AppData%")
        self.assertEqual(cfg["install_name"], "svchost.exe")
        self.assertEqual(rest, [])

    def test_renamed_group(self):
        cfg, rest = xe.label_config(["45.141.27.251", "7777", "<123456789>", "<Xwormmm>",
                                     "SLUMZICK v8.5", "USB.exe", "%AppData%", "XClient.exe"])
        self.assertEqual(cfg["group"], "SLUMZICK v8.5")
        self.assertEqual(cfg["install_name"], "XClient.exe")
        self.assertEqual(rest, [])

    def test_telegram(self):
        cfg, _ = xe.label_config(["192.0.2.1", "443",
                                  "1234567890:AAHabcdefghijklmnopqrstuvwxyz012345", "-1001234567890"])
        self.assertIn("telegram_token", cfg)
        self.assertEqual(cfg["telegram_chat_id"], "-1001234567890")

    def test_clipper_wallets(self):
        # decrypted from XWorm V7.4, d00a97e1..., newlines included as found
        cfg, rest = xe.label_config([
            "13.140.42.128", "7004", "<V74PV74PV74PV74PV74P>", "<Xwormmm>", "XWorm V7.4",
            "USB.exe", "%AppData%", "XWormClient.exe",
            "\nbc1qggndak7m7snkceetns5jj7a9j9gug9g3psftuq",
            "\n0xf595a366e864599c95150c6d332a9af4ba0e457b\n",
            "TQ6xazYvnMUjBKL2QLAiPmRdXXyeFcatfU"])
        self.assertEqual(cfg["clipper_wallets"], {
            "btc": ["bc1qggndak7m7snkceetns5jj7a9j9gug9g3psftuq"],
            "eth": ["0xf595a366e864599c95150c6d332a9af4ba0e457b"],
            "trx": ["TQ6xazYvnMUjBKL2QLAiPmRdXXyeFcatfU"]})
        self.assertEqual(rest, [])

    def test_version(self):
        self.assertEqual(xe.detect_version(["foo", "XWorm V7.1"]), "7.1")
        self.assertIsNone(xe.detect_version(["nothing here"]))


@unittest.skipUnless(CSC, "no C# compiler available")
class TestEndToEnd(unittest.TestCase):
    MUTEX = "TestMutex_9f3aQ2"
    SETTINGS = {
        "Hosts": "192.0.2.10",
        "Port": "7000",
        "KEY": "<TESTKEY123>",
        "SPL": "<SPLITTER>",
        "Groub": "TestGroup",
        "USBNM": "USB.exe",
        "InstallDir": "%AppData%",
        "InstallStr": "updater.exe",
    }

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="xw_test_")
        fields = "\n".join(f'        public static string {k} = "{encrypt(v, cls.MUTEX)}";'
                           for k, v in cls.SETTINGS.items())
        cls.stub = compile_cs(f"""
using System;
namespace Stub {{
    public static class Settings {{
{fields}
        public static int Sleep = 3;
        public static string Mutex = "{cls.MUTEX}";
    }}
    public static class Program {{
        public static void Main() {{
            string other = "SGVsbG8gV29ybGQhIEhlbGxvIQ==";
            Console.WriteLine(other.Length + Settings.Hosts.Length);
        }}
    }}
}}
""", cls.tmp, "stub")
        cls.no_strings = compile_cs(
            "public static class P { public static int Main() { int a = 1; return a + 1; } }",
            cls.tmp, "nostr")
        cls.junk = os.path.join(cls.tmp, "junk.bin")
        with open(cls.junk, "wb") as f:
            f.write(b"MZ" + b"\x00" * 200)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_extract(self):
        res = xe.extract(self.stub)
        self.assertEqual(res["status"], "ok", res.get("error"))
        cfg = res["config"]
        self.assertEqual(cfg["mutex"], self.MUTEX)
        self.assertEqual(cfg["hosts"], ["192.0.2.10"])
        self.assertEqual(cfg["port"], 7000)
        self.assertEqual(cfg["aes_key"], "<TESTKEY123>")
        self.assertEqual(cfg["splitter"], "<SPLITTER>")
        self.assertEqual(cfg["group"], "TestGroup")
        self.assertEqual(cfg["usb_name"], "USB.exe")
        self.assertEqual(cfg["install_dir"], "%AppData%")
        self.assertEqual(cfg["install_name"], "updater.exe")
        self.assertEqual(res["c2"], ["192.0.2.10:7000"])
        self.assertEqual(res["unlabeled_values"], [])

    def test_not_pe(self):
        self.assertEqual(xe.extract(self.junk)["status"], "not_pe")
        self.assertEqual(xe.extract(os.path.join(self.tmp, "stub.cs"))["status"], "not_pe")

    def test_no_strings(self):
        self.assertEqual(xe.extract(self.no_strings)["status"], "dotnet_no_strings")

    def test_dump_strings(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(xe.main([self.stub, "--dump-strings"]), 0)
        self.assertIn(self.MUTEX, buf.getvalue())

    def test_exit_codes(self):
        self.assertEqual(xe.main([self.stub, "-o", os.path.join(self.tmp, "a.jsonl")]), 0)
        self.assertEqual(xe.main([self.junk, "-o", os.path.join(self.tmp, "b.jsonl")]), 1)


if __name__ == "__main__":
    unittest.main()
